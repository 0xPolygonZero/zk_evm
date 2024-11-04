#![cfg(feature = "eth_mainnet")]

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

use either::Either;
use ethereum_types::{Address, BigEndianHash, H160, H256, U256};
use evm_arithmetization::generation::mpt::{LegacyReceiptRlp, LogRlp, MptAccountRlp};
use evm_arithmetization::generation::{GenerationInputs, TrieInputs};
use evm_arithmetization::proof::{BlockHashes, BlockMetadata, TrieRoots};
use evm_arithmetization::prover::testing::prove_all_segments;
use evm_arithmetization::testing_utils::{
    beacon_roots_account_nibbles, beacon_roots_contract_from_storage, create_account_storage,
    init_logger, preinitialized_state_and_storage_tries, sd2u, sh2u,
    update_beacon_roots_account_storage,
};
use evm_arithmetization::verifier::testing::verify_all_proofs;
use evm_arithmetization::world::tries::{StateMpt, StorageTrie};
use evm_arithmetization::world::world::{StateWorld, Type1World};
use evm_arithmetization::{AllStark, Node, StarkConfig, EMPTY_CONSOLIDATED_BLOCKHASH};
use hex_literal::hex;
use keccak_hash::keccak;
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::plonk::config::KeccakGoldilocksConfig;
use plonky2::util::timing::TimingTree;

type F = GoldilocksField;
const D: usize = 2;
type C = KeccakGoldilocksConfig;

/// Test a simple ERC721 token transfer.
/// Used the following Solidity code:
/// ```solidity
/// pragma solidity ^0.8.20;
///
/// import "@openzeppelin/contracts@5.0.1/token/ERC721/ERC721.sol";
/// import "@openzeppelin/contracts@5.0.1/access/Ownable.sol";
///
/// contract TestToken is ERC721, Ownable {
///     constructor(address initialOwner)
///         ERC721("TestToken", "TEST")
///         Ownable(initialOwner)
///     {}
///
///     function safeMint(address to, uint256 tokenId) public onlyOwner {
///         _safeMint(to, tokenId);
///     }
/// }
/// ```
///
/// The transaction calls the `safeTransferFrom` function to transfer token
/// `1337` from address `0x5B38Da6a701c568545dCfcB03FcB875f56beddC4` to address
/// `0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2`.
#[test]
fn test_erc721() -> anyhow::Result<()> {
    init_logger();

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();

    let beneficiary = hex!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    let owner = hex!("5B38Da6a701c568545dCfcB03FcB875f56beddC4");
    let contract = hex!("f2B1114C644cBb3fF63Bf1dD284c8Cd716e95BE9");

    let owner_state_key = keccak(owner);
    let contract_state_key = keccak(contract);

    let owner_nibbles = Nibbles::from_bytes_be(owner_state_key.as_bytes()).unwrap();
    let contract_nibbles = Nibbles::from_bytes_be(contract_state_key.as_bytes()).unwrap();

    let (mut state_trie_before, mut storage_tries) = preinitialized_state_and_storage_tries()?;
    let mut beacon_roots_account_storage = storage_tries[0].1.clone();
    state_trie_before.insert(owner_nibbles, rlp::encode(&owner_account()).to_vec())?;
    state_trie_before.insert(contract_nibbles, rlp::encode(&contract_account()?).to_vec())?;

    storage_tries.push((contract_state_key, contract_storage()?));

    let state_trie_before = get_state_world(state_trie_before, storage_tries);
    let tries_before = TrieInputs {
        state_trie: state_trie_before,
        transactions_trie: HashedPartialTrie::from(Node::Empty),
        receipts_trie: HashedPartialTrie::from(Node::Empty),
        // storage_tries,
    };

    let txn = signed_tx();

    let gas_used = 58_418.into();

    let contract_code = [contract_bytecode(), vec![]]
        .map(|v| (Either::Left(keccak(v.clone())), v))
        .into();

    let logs = vec![LogRlp {
        address: H160::from_str("0xf2B1114C644cBb3fF63Bf1dD284c8Cd716e95BE9").unwrap(),
        topics: vec![
            H256::from_str("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")
                .unwrap(),
            H256::from_str("0x0000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc4")
                .unwrap(),
            H256::from_str("0x000000000000000000000000ab8483f64d9c6d1ecf9b849ae677dd3315835cb2")
                .unwrap(),
            H256::from_str("0x0000000000000000000000000000000000000000000000000000000000000539")
                .unwrap(),
        ],
        data: vec![].into(),
    }];

    let mut bloom_bytes = [0u8; 256];
    add_logs_to_bloom(&mut bloom_bytes, &logs);

    let bloom = bloom_bytes
        .chunks_exact(32)
        .map(U256::from_big_endian)
        .collect::<Vec<_>>();

    let block_metadata = BlockMetadata {
        block_beneficiary: Address::from(beneficiary),
        block_timestamp: 0x03e8.into(),
        block_number: 1.into(),
        block_difficulty: 0x020000.into(),
        block_random: H256::from_uint(&0x020000.into()),
        block_gaslimit: 0xff112233u32.into(),
        block_chain_id: 1.into(),
        block_base_fee: 0xa.into(),
        block_gas_used: gas_used,
        block_bloom: bloom.try_into().unwrap(),
        ..Default::default()
    };

    let expected_state_trie_after: HashedPartialTrie = {
        let mut state_trie_after = HashedPartialTrie::from(Node::Empty);

        update_beacon_roots_account_storage(
            &mut beacon_roots_account_storage,
            block_metadata.block_timestamp,
            block_metadata.parent_beacon_block_root,
        )?;
        let beacon_roots_account =
            beacon_roots_contract_from_storage(&beacon_roots_account_storage);

        let owner_account = owner_account();
        let owner_account_after = MptAccountRlp {
            nonce: owner_account.nonce + 1,
            balance: owner_account.balance - gas_used * 0xa,
            ..owner_account
        };
        state_trie_after.insert(owner_nibbles, rlp::encode(&owner_account_after).to_vec())?;
        let contract_account_after = MptAccountRlp {
            storage_root: contract_storage_after()?.hash(),
            ..contract_account()?
        };
        state_trie_after.insert(
            contract_nibbles,
            rlp::encode(&contract_account_after).to_vec(),
        )?;
        state_trie_after.insert(
            beacon_roots_account_nibbles(),
            rlp::encode(&beacon_roots_account).to_vec(),
        )?;

        state_trie_after
    };

    let receipt_0 = LegacyReceiptRlp {
        status: true,
        cum_gas_used: gas_used,
        bloom: bloom_bytes.to_vec().into(),
        logs,
    };
    let mut receipts_trie = HashedPartialTrie::from(Node::Empty);
    receipts_trie.insert(Nibbles::from_str("0x80").unwrap(), receipt_0.encode(0))?;
    let transactions_trie: HashedPartialTrie = Node::Leaf {
        nibbles: Nibbles::from_str("0x80").unwrap(),
        value: txn.to_vec(),
    }
    .into();

    let trie_roots_after = TrieRoots {
        state_root: expected_state_trie_after.hash(),
        transactions_root: transactions_trie.hash(),
        receipts_root: receipts_trie.hash(),
    };

    let inputs = GenerationInputs::<F> {
        signed_txns: vec![txn.to_vec()],
        burn_addr: None,
        withdrawals: vec![],
        ger_data: None,
        tries: tries_before,
        trie_roots_after,
        contract_code,
        checkpoint_state_trie_root: HashedPartialTrie::from(Node::Empty).hash(),
        checkpoint_consolidated_hash: EMPTY_CONSOLIDATED_BLOCKHASH.map(F::from_canonical_u64),
        block_metadata,
        txn_number_before: 0.into(),
        gas_used_before: 0.into(),
        gas_used_after: gas_used,
        block_hashes: BlockHashes {
            prev_hashes: vec![H256::default(); 256],
            cur_hash: H256::default(),
        },
    };

    let max_cpu_len_log = 20;
    let mut timing = TimingTree::new("prove", log::Level::Debug);

    let proofs = prove_all_segments::<F, C, D>(
        &all_stark,
        &config,
        inputs,
        max_cpu_len_log,
        &mut timing,
        None,
    )?;

    timing.filter(Duration::from_millis(100)).print();

    verify_all_proofs(&all_stark, &proofs, &config)
}

fn contract_bytecode() -> Vec<u8> {
    hex!("608060405234801561000f575f80fd5b5060043610610109575f3560e01c8063715018a6116100a0578063a22cb4651161006f578063a22cb465146102a1578063b88d4fde146102bd578063c87b56dd146102d9578063e985e9c514610309578063f2fde38b1461033957610109565b8063715018a61461023f5780638da5cb5b1461024957806395d89b4114610267578063a14481941461028557610109565b806323b872dd116100dc57806323b872dd146101a757806342842e0e146101c35780636352211e146101df57806370a082311461020f57610109565b806301ffc9a71461010d57806306fdde031461013d578063081812fc1461015b578063095ea7b31461018b575b5f80fd5b61012760048036038101906101229190611855565b610355565b604051610134919061189a565b60405180910390f35b610145610436565b604051610152919061193d565b60405180910390f35b61017560048036038101906101709190611990565b6104c5565b60405161018291906119fa565b60405180910390f35b6101a560048036038101906101a09190611a3d565b6104e0565b005b6101c160048036038101906101bc9190611a7b565b6104f6565b005b6101dd60048036038101906101d89190611a7b565b6105f5565b005b6101f960048036038101906101f49190611990565b610614565b60405161020691906119fa565b60405180910390f35b61022960048036038101906102249190611acb565b610625565b6040516102369190611b05565b60405180910390f35b6102476106db565b005b6102516106ee565b60405161025e91906119fa565b60405180910390f35b61026f610716565b60405161027c919061193d565b60405180910390f35b61029f600480360381019061029a9190611a3d565b6107a6565b005b6102bb60048036038101906102b69190611b48565b6107bc565b005b6102d760048036038101906102d29190611cb2565b6107d2565b005b6102f360048036038101906102ee9190611990565b6107ef565b604051610300919061193d565b60405180910390f35b610323600480360381019061031e9190611d32565b610855565b604051610330919061189a565b60405180910390f35b610353600480360381019061034e9190611acb565b6108e3565b005b5f7f80ac58cd000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916827bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916148061041f57507f5b5e139f000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916827bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916145b8061042f575061042e82610967565b5b9050919050565b60605f805461044490611d9d565b80601f016020809104026020016040519081016040528092919081815260200182805461047090611d9d565b80156104bb5780601f10610492576101008083540402835291602001916104bb565b820191905f5260205f20905b81548152906001019060200180831161049e57829003601f168201915b5050505050905090565b5f6104cf826109d0565b506104d982610a56565b9050919050565b6104f282826104ed610a8f565b610a96565b5050565b5f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1603610566575f6040517f64a0ae9200000000000000000000000000000000000000000000000000000000815260040161055d91906119fa565b60405180910390fd5b5f6105798383610574610a8f565b610aa8565b90508373ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16146105ef578382826040517f64283d7b0000000000000000000000000000000000000000000000000000000081526004016105e693929190611dcd565b60405180910390fd5b50505050565b61060f83838360405180602001604052805f8152506107d2565b505050565b5f61061e826109d0565b9050919050565b5f8073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1603610696575f6040517f89c62b6400000000000000000000000000000000000000000000000000000000815260040161068d91906119fa565b60405180910390fd5b60035f8373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f20549050919050565b6106e3610cb3565b6106ec5f610d3a565b565b5f60065f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b60606001805461072590611d9d565b80601f016020809104026020016040519081016040528092919081815260200182805461075190611d9d565b801561079c5780601f106107735761010080835404028352916020019161079c565b820191905f5260205f20905b81548152906001019060200180831161077f57829003601f168201915b5050505050905090565b6107ae610cb3565b6107b88282610dfd565b5050565b6107ce6107c7610a8f565b8383610e1a565b5050565b6107dd8484846104f6565b6107e984848484610f83565b50505050565b60606107fa826109d0565b505f610804611135565b90505f8151116108225760405180602001604052805f81525061084d565b8061082c8461114b565b60405160200161083d929190611e3c565b6040516020818303038152906040525b915050919050565b5f60055f8473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f9054906101000a900460ff16905092915050565b6108eb610cb3565b5f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff160361095b575f6040517f1e4fbdf700000000000000000000000000000000000000000000000000000000815260040161095291906119fa565b60405180910390fd5b61096481610d3a565b50565b5f7f01ffc9a7000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916827bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916149050919050565b5f806109db83611215565b90505f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1603610a4d57826040517f7e273289000000000000000000000000000000000000000000000000000000008152600401610a449190611b05565b60405180910390fd5b80915050919050565b5f60045f8381526020019081526020015f205f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050919050565b5f33905090565b610aa3838383600161124e565b505050565b5f80610ab384611215565b90505f73ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff1614610af457610af381848661140d565b5b5f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614610b7f57610b335f855f8061124e565b600160035f8373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f82825403925050819055505b5f73ffffffffffffffffffffffffffffffffffffffff168573ffffffffffffffffffffffffffffffffffffffff1614610bfe57600160035f8773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f82825401925050819055505b8460025f8681526020019081526020015f205f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550838573ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef60405160405180910390a4809150509392505050565b610cbb610a8f565b73ffffffffffffffffffffffffffffffffffffffff16610cd96106ee565b73ffffffffffffffffffffffffffffffffffffffff1614610d3857610cfc610a8f565b6040517f118cdaa7000000000000000000000000000000000000000000000000000000008152600401610d2f91906119fa565b60405180910390fd5b565b5f60065f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff1690508160065f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508173ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a35050565b610e16828260405180602001604052805f8152506114d0565b5050565b5f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1603610e8a57816040517f5b08ba18000000000000000000000000000000000000000000000000000000008152600401610e8191906119fa565b60405180910390fd5b8060055f8573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f6101000a81548160ff0219169083151502179055508173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167f17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c3183604051610f76919061189a565b60405180910390a3505050565b5f8373ffffffffffffffffffffffffffffffffffffffff163b111561112f578273ffffffffffffffffffffffffffffffffffffffff1663150b7a02610fc6610a8f565b8685856040518563ffffffff1660e01b8152600401610fe89493929190611eb1565b6020604051808303815f875af192505050801561102357506040513d601f19601f820116820180604052508101906110209190611f0f565b60015b6110a4573d805f8114611051576040519150601f19603f3d011682016040523d82523d5f602084013e611056565b606091505b505f81510361109c57836040517f64a0ae9200000000000000000000000000000000000000000000000000000000815260040161109391906119fa565b60405180910390fd5b805181602001fd5b63150b7a0260e01b7bffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916817bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19161461112d57836040517f64a0ae9200000000000000000000000000000000000000000000000000000000815260040161112491906119fa565b60405180910390fd5b505b50505050565b606060405180602001604052805f815250905090565b60605f6001611159846114eb565b0190505f8167ffffffffffffffff81111561117757611176611b8e565b5b6040519080825280601f01601f1916602001820160405280156111a95781602001600182028036833780820191505090505b5090505f82602001820190505b60011561120a578080600190039150507f3031323334353637383961626364656600000000000000000000000000000000600a86061a8153600a85816111ff576111fe611f3a565b5b0494505f85036111b6575b819350505050919050565b5f60025f8381526020019081526020015f205f9054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050919050565b808061128657505f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614155b156113b8575f611295846109d0565b90505f73ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff16141580156112ff57508273ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff1614155b801561131257506113108184610855565b155b1561135457826040517fa9fbf51f00000000000000000000000000000000000000000000000000000000815260040161134b91906119fa565b60405180910390fd5b81156113b657838573ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b92560405160405180910390a45b505b8360045f8581526020019081526020015f205f6101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555050505050565b61141883838361163c565b6114cb575f73ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff160361148c57806040517f7e2732890000000000000000000000000000000000000000000000000000000081526004016114839190611b05565b60405180910390fd5b81816040517f177e802f0000000000000000000000000000000000000000000000000000000081526004016114c2929190611f67565b60405180910390fd5b505050565b6114da83836116fc565b6114e65f848484610f83565b505050565b5f805f90507a184f03e93ff9f4daa797ed6e38ed64bf6a1f0100000000000000008310611547577a184f03e93ff9f4daa797ed6e38ed64bf6a1f010000000000000000838161153d5761153c611f3a565b5b0492506040810190505b6d04ee2d6d415b85acef81000000008310611584576d04ee2d6d415b85acef8100000000838161157a57611579611f3a565b5b0492506020810190505b662386f26fc1000083106115b357662386f26fc1000083816115a9576115a8611f3a565b5b0492506010810190505b6305f5e10083106115dc576305f5e10083816115d2576115d1611f3a565b5b0492506008810190505b61271083106116015761271083816115f7576115f6611f3a565b5b0492506004810190505b60648310611624576064838161161a57611619611f3a565b5b0492506002810190505b600a8310611633576001810190505b80915050919050565b5f8073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff16141580156116f357508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff1614806116b457506116b38484610855565b5b806116f257508273ffffffffffffffffffffffffffffffffffffffff166116da83610a56565b73ffffffffffffffffffffffffffffffffffffffff16145b5b90509392505050565b5f73ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff160361176c575f6040517f64a0ae9200000000000000000000000000000000000000000000000000000000815260040161176391906119fa565b60405180910390fd5b5f61177883835f610aa8565b90505f73ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16146117ea575f6040517f73c6ac6e0000000000000000000000000000000000000000000000000000000081526004016117e191906119fa565b60405180910390fd5b505050565b5f604051905090565b5f80fd5b5f80fd5b5f7fffffffff0000000000000000000000000000000000000000000000000000000082169050919050565b61183481611800565b811461183e575f80fd5b50565b5f8135905061184f8161182b565b92915050565b5f6020828403121561186a576118696117f8565b5b5f61187784828501611841565b91505092915050565b5f8115159050919050565b61189481611880565b82525050565b5f6020820190506118ad5f83018461188b565b92915050565b5f81519050919050565b5f82825260208201905092915050565b5f5b838110156118ea5780820151818401526020810190506118cf565b5f8484015250505050565b5f601f19601f8301169050919050565b5f61190f826118b3565b61191981856118bd565b93506119298185602086016118cd565b611932816118f5565b840191505092915050565b5f6020820190508181035f8301526119558184611905565b905092915050565b5f819050919050565b61196f8161195d565b8114611979575f80fd5b50565b5f8135905061198a81611966565b92915050565b5f602082840312156119a5576119a46117f8565b5b5f6119b28482850161197c565b91505092915050565b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f6119e4826119bb565b9050919050565b6119f4816119da565b82525050565b5f602082019050611a0d5f8301846119eb565b92915050565b611a1c816119da565b8114611a26575f80fd5b50565b5f81359050611a3781611a13565b92915050565b5f8060408385031215611a5357611a526117f8565b5b5f611a6085828601611a29565b9250506020611a718582860161197c565b9150509250929050565b5f805f60608486031215611a9257611a916117f8565b5b5f611a9f86828701611a29565b9350506020611ab086828701611a29565b9250506040611ac18682870161197c565b9150509250925092565b5f60208284031215611ae057611adf6117f8565b5b5f611aed84828501611a29565b91505092915050565b611aff8161195d565b82525050565b5f602082019050611b185f830184611af6565b92915050565b611b2781611880565b8114611b31575f80fd5b50565b5f81359050611b4281611b1e565b92915050565b5f8060408385031215611b5e57611b5d6117f8565b5b5f611b6b85828601611a29565b9250506020611b7c85828601611b34565b9150509250929050565b5f80fd5b5f80fd5b7f4e487b71000000000000000000000000000000000000000000000000000000005f52604160045260245ffd5b611bc4826118f5565b810181811067ffffffffffffffff82111715611be357611be2611b8e565b5b80604052505050565b5f611bf56117ef565b9050611c018282611bbb565b919050565b5f67ffffffffffffffff821115611c2057611c1f611b8e565b5b611c29826118f5565b9050602081019050919050565b828183375f83830152505050565b5f611c56611c5184611c06565b611bec565b905082815260208101848484011115611c7257611c71611b8a565b5b611c7d848285611c36565b509392505050565b5f82601f830112611c9957611c98611b86565b5b8135611ca9848260208601611c44565b91505092915050565b5f805f8060808587031215611cca57611cc96117f8565b5b5f611cd787828801611a29565b9450506020611ce887828801611a29565b9350506040611cf98782880161197c565b925050606085013567ffffffffffffffff811115611d1a57611d196117fc565b5b611d2687828801611c85565b91505092959194509250565b5f8060408385031215611d4857611d476117f8565b5b5f611d5585828601611a29565b9250506020611d6685828601611a29565b9150509250929050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52602260045260245ffd5b5f6002820490506001821680611db457607f821691505b602082108103611dc757611dc6611d70565b5b50919050565b5f606082019050611de05f8301866119eb565b611ded6020830185611af6565b611dfa60408301846119eb565b949350505050565b5f81905092915050565b5f611e16826118b3565b611e208185611e02565b9350611e308185602086016118cd565b80840191505092915050565b5f611e478285611e0c565b9150611e538284611e0c565b91508190509392505050565b5f81519050919050565b5f82825260208201905092915050565b5f611e8382611e5f565b611e8d8185611e69565b9350611e9d8185602086016118cd565b611ea6816118f5565b840191505092915050565b5f608082019050611ec45f8301876119eb565b611ed160208301866119eb565b611ede6040830185611af6565b8181036060830152611ef08184611e79565b905095945050505050565b5f81519050611f098161182b565b92915050565b5f60208284031215611f2457611f236117f8565b5b5f611f3184828501611efb565b91505092915050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601260045260245ffd5b5f604082019050611f7a5f8301856119eb565b611f876020830184611af6565b939250505056fea2646970667358221220432b30673e00c0eb009e1718c271f4cfdfbeded17345829703b06d322360990164736f6c63430008160033").into()
}

fn contract_storage() -> anyhow::Result<HashedPartialTrie> {
    create_account_storage(&[
        (
            U256::zero(),
            sh2u("0x54657374546f6b656e0000000000000000000000000000000000000000000012"),
        ),
        (
            U256::one(),
            sh2u("0x5445535400000000000000000000000000000000000000000000000000000008"),
        ),
        (
            sd2u("6"),
            sh2u("0x5b38da6a701c568545dcfcb03fcb875f56beddc4"),
        ),
        (
            sh2u("0x343ff8127bd64f680be4e996254dc3528603c6ecd54364b4cf956ebdd28f0028"),
            sh2u("0x5b38da6a701c568545dcfcb03fcb875f56beddc4"),
        ),
        (
            sh2u("0x118c1ea466562cb796e30ef705e4db752f5c39d773d22c5efd8d46f67194e78a"),
            sd2u("1"),
        ),
    ])
}

fn contract_storage_after() -> anyhow::Result<HashedPartialTrie> {
    create_account_storage(&[
        (
            U256::zero(),
            sh2u("0x54657374546f6b656e0000000000000000000000000000000000000000000012"),
        ),
        (
            U256::one(),
            sh2u("0x5445535400000000000000000000000000000000000000000000000000000008"),
        ),
        (
            sd2u("6"),
            sh2u("0x5b38da6a701c568545dcfcb03fcb875f56beddc4"),
        ),
        (
            sh2u("0x343ff8127bd64f680be4e996254dc3528603c6ecd54364b4cf956ebdd28f0028"),
            sh2u("0xab8483f64d9c6d1ecf9b849ae677dd3315835cb2"),
        ),
        (
            sh2u("0xf3aa6a8a9f7e3707e36cc99c499a27514922afe861ec3d80a1a314409cba92f9"),
            sd2u("1"),
        ),
    ])
}

fn owner_account() -> MptAccountRlp {
    MptAccountRlp {
        nonce: 2.into(),
        balance: 0x1000000.into(),
        storage_root: HashedPartialTrie::from(Node::Empty).hash(),
        code_hash: keccak([]),
    }
}

fn contract_account() -> anyhow::Result<MptAccountRlp> {
    Ok(MptAccountRlp {
        nonce: 0.into(),
        balance: 0.into(),
        storage_root: contract_storage()?.hash(),
        code_hash: keccak(contract_bytecode()),
    })
}

fn signed_tx() -> Vec<u8> {
    hex!("f8c5020a8307a12094f2b1114c644cbb3ff63bf1dd284c8cd716e95be980b86442842e0e0000000000000000000000005b38da6a701c568545dcfcb03fcb875f56beddc4000000000000000000000000ab8483f64d9c6d1ecf9b849ae677dd3315835cb2000000000000000000000000000000000000000000000000000000000000053925a0414867f13ac63d663e84099d52c8215615666ea37c969c69aa58a0fad26a3f6ea01a7160c6274969083b2316eb8ca6011b4bf6b00972159a78bf64d06fa40c1402").into()
}

fn add_logs_to_bloom(bloom: &mut [u8; 256], logs: &Vec<LogRlp>) {
    for log in logs {
        add_to_bloom(bloom, log.address.as_bytes());
        for topic in &log.topics {
            add_to_bloom(bloom, topic.as_bytes());
        }
    }
}

fn add_to_bloom(bloom: &mut [u8; 256], bloom_entry: &[u8]) {
    let bloom_hash = keccak(bloom_entry).to_fixed_bytes();

    for idx in 0..3 {
        let bit_pair = u16::from_be_bytes(bloom_hash[2 * idx..2 * (idx + 1)].try_into().unwrap());
        let bit_to_set = 0x07FF - (bit_pair & 0x07FF);
        let byte_index = bit_to_set / 8;
        let bit_value = 1 << (7 - bit_to_set % 8);
        bloom[byte_index as usize] |= bit_value;
    }
}

fn get_state_world(
    state: HashedPartialTrie,
    storage_tries: Vec<(H256, HashedPartialTrie)>,
) -> StateWorld {
    let mut type1world =
        Type1World::new(StateMpt::new_with_inner(state), BTreeMap::default()).unwrap();
    let mut init_storage = BTreeMap::default();
    for (storage, v) in storage_tries {
        init_storage.insert(storage, StorageTrie::new_with_trie(v));
    }
    type1world.set_storage(init_storage);
    StateWorld {
        state: Either::Left(type1world),
    }
}
