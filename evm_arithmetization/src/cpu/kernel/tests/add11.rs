use std::collections::HashMap;
use std::str::FromStr;

use ethereum_types::{Address, BigEndianHash, H256};
use hex_literal::hex;
use keccak_hash::keccak;
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::{HashedPartialTrie, Node, PartialTrie};
use plonky2::field::goldilocks_field::GoldilocksField as F;

use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::interpreter::Interpreter;
use crate::generation::mpt::{AccountRlp, LegacyReceiptRlp};
use crate::generation::TrieInputs;
use crate::proof::{BlockHashes, BlockMetadata, TrieRoots};
use crate::testing_utils::{
    beacon_roots_account_nibbles, beacon_roots_contract_from_storage, ger_account_nibbles,
    preinitialized_state_and_storage_tries, update_beacon_roots_account_storage,
    GLOBAL_EXIT_ROOT_ACCOUNT,
};
use crate::GenerationInputs;

#[test]
fn test_add11_yml() {
    let beneficiary = hex!("2adc25665018aa1fe0e6bc666dac8fc2697ff9ba");
    let sender = hex!("a94f5374fce5edbc8e2a8697c15331677e6ebf0b");
    let to = hex!("095e7baea6a6c7c4c2dfeb977efac326af552d87");

    let beneficiary_state_key = keccak(beneficiary);
    let sender_state_key = keccak(sender);
    let to_hashed = keccak(to);

    let beneficiary_nibbles = Nibbles::from_bytes_be(beneficiary_state_key.as_bytes()).unwrap();
    let sender_nibbles = Nibbles::from_bytes_be(sender_state_key.as_bytes()).unwrap();
    let to_nibbles = Nibbles::from_bytes_be(to_hashed.as_bytes()).unwrap();

    let code = [0x60, 0x01, 0x60, 0x01, 0x01, 0x60, 0x00, 0x55, 0x00];
    let code_hash = keccak(code);

    let mut contract_code = HashMap::new();
    contract_code.insert(keccak(vec![]), vec![]);
    contract_code.insert(code_hash, code.to_vec());

    let beneficiary_account_before = AccountRlp {
        nonce: 1.into(),
        ..AccountRlp::default()
    };
    let sender_account_before = AccountRlp {
        balance: 0x0de0b6b3a7640000u64.into(),
        ..AccountRlp::default()
    };
    let to_account_before = AccountRlp {
        balance: 0x0de0b6b3a7640000u64.into(),
        code_hash,
        ..AccountRlp::default()
    };

    let (mut state_trie_before, mut storage_tries) =
        preinitialized_state_and_storage_tries().unwrap();
    let mut beacon_roots_account_storage = storage_tries[0].1.clone();
    state_trie_before
        .insert(
            beneficiary_nibbles,
            rlp::encode(&beneficiary_account_before).to_vec(),
        )
        .unwrap();
    state_trie_before
        .insert(sender_nibbles, rlp::encode(&sender_account_before).to_vec())
        .unwrap();
    state_trie_before
        .insert(to_nibbles, rlp::encode(&to_account_before).to_vec())
        .unwrap();

    storage_tries.push((to_hashed, Node::Empty.into()));

    let tries_before = TrieInputs {
        state_trie: state_trie_before,
        transactions_trie: Node::Empty.into(),
        receipts_trie: Node::Empty.into(),
        storage_tries,
    };

    let txn = hex!("f863800a83061a8094095e7baea6a6c7c4c2dfeb977efac326af552d87830186a0801ba0ffb600e63115a7362e7811894a91d8ba4330e526f22121c994c4692035dfdfd5a06198379fcac8de3dbfac48b165df4bf88e2088f294b61efb9a65fe2281c76e16");

    let gas_used = 0xa868u64.into();

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
        ..Default::default()
    };

    let expected_state_trie_after = {
        let beneficiary_account_after = AccountRlp {
            nonce: 1.into(),
            ..AccountRlp::default()
        };
        let sender_account_after = AccountRlp {
            balance: 0xde0b6b3a75be550u64.into(),
            nonce: 1.into(),
            ..AccountRlp::default()
        };
        let to_account_after = AccountRlp {
            balance: 0xde0b6b3a76586a0u64.into(),
            code_hash,
            // Storage map: { 0 => 2 }
            storage_root: HashedPartialTrie::from(Node::Leaf {
                nibbles: Nibbles::from_h256_be(keccak([0u8; 32])),
                value: vec![2],
            })
            .hash(),
            ..AccountRlp::default()
        };
        update_beacon_roots_account_storage(
            &mut beacon_roots_account_storage,
            block_metadata.block_timestamp,
            block_metadata.parent_beacon_block_root,
        )
        .unwrap();
        let beacon_roots_account =
            beacon_roots_contract_from_storage(&beacon_roots_account_storage);

        let mut expected_state_trie_after = HashedPartialTrie::from(Node::Empty);
        expected_state_trie_after
            .insert(
                beneficiary_nibbles,
                rlp::encode(&beneficiary_account_after).to_vec(),
            )
            .unwrap();
        expected_state_trie_after
            .insert(sender_nibbles, rlp::encode(&sender_account_after).to_vec())
            .unwrap();
        expected_state_trie_after
            .insert(to_nibbles, rlp::encode(&to_account_after).to_vec())
            .unwrap();
        expected_state_trie_after
            .insert(
                beacon_roots_account_nibbles(),
                rlp::encode(&beacon_roots_account).to_vec(),
            )
            .unwrap();
        expected_state_trie_after
            .insert(
                ger_account_nibbles(),
                rlp::encode(&GLOBAL_EXIT_ROOT_ACCOUNT).to_vec(),
            )
            .unwrap();
        expected_state_trie_after
    };
    let receipt_0 = LegacyReceiptRlp {
        status: true,
        cum_gas_used: gas_used,
        bloom: vec![0; 256].into(),
        logs: vec![],
    };
    let mut receipts_trie = HashedPartialTrie::from(Node::Empty);
    receipts_trie
        .insert(
            Nibbles::from_str("0x80").unwrap(),
            rlp::encode(&receipt_0).to_vec(),
        )
        .unwrap();
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

    let inputs = GenerationInputs {
        signed_txns: vec![txn.to_vec()],
        withdrawals: vec![],
        global_exit_roots: vec![],
        tries: tries_before,
        trie_roots_after,
        contract_code: contract_code.clone(),
        block_metadata,
        checkpoint_state_trie_root: HashedPartialTrie::from(Node::Empty).hash(),
        txn_number_before: 0.into(),
        gas_used_before: 0.into(),
        gas_used_after: gas_used,
        block_hashes: BlockHashes {
            prev_hashes: vec![H256::default(); 256],
            cur_hash: H256::default(),
        },
    };

    let initial_stack = vec![];
    let initial_offset = KERNEL.global_labels["init"];
    let mut interpreter: Interpreter<F> =
        Interpreter::new_with_generation_inputs(initial_offset, initial_stack, &inputs, None);

    interpreter.set_is_kernel(true);
    interpreter.run().expect("Proving add11 failed.");
}

#[test]
fn test_add11_yml_with_exception() {
    // In this test, we make sure that the user code throws a stack underflow
    // exception.
    let beneficiary = hex!("2adc25665018aa1fe0e6bc666dac8fc2697ff9ba");
    let sender = hex!("a94f5374fce5edbc8e2a8697c15331677e6ebf0b");
    let to = hex!("095e7baea6a6c7c4c2dfeb977efac326af552d87");

    let beneficiary_state_key = keccak(beneficiary);
    let sender_state_key = keccak(sender);
    let to_hashed = keccak(to);

    let beneficiary_nibbles = Nibbles::from_bytes_be(beneficiary_state_key.as_bytes()).unwrap();
    let sender_nibbles = Nibbles::from_bytes_be(sender_state_key.as_bytes()).unwrap();
    let to_nibbles = Nibbles::from_bytes_be(to_hashed.as_bytes()).unwrap();

    let code = [0x60, 0x01, 0x60, 0x01, 0x01, 0x8e, 0x00];
    let code_hash = keccak(code);

    let mut contract_code = HashMap::new();
    contract_code.insert(keccak(vec![]), vec![]);
    contract_code.insert(code_hash, code.to_vec());

    let beneficiary_account_before = AccountRlp {
        nonce: 1.into(),
        ..AccountRlp::default()
    };
    let sender_account_before = AccountRlp {
        balance: 0x0de0b6b3a7640000u64.into(),
        ..AccountRlp::default()
    };
    let to_account_before = AccountRlp {
        balance: 0x0de0b6b3a7640000u64.into(),
        code_hash,
        ..AccountRlp::default()
    };

    let (mut state_trie_before, mut storage_tries) =
        preinitialized_state_and_storage_tries().unwrap();
    let mut beacon_roots_account_storage = storage_tries[0].1.clone();
    state_trie_before
        .insert(
            beneficiary_nibbles,
            rlp::encode(&beneficiary_account_before).to_vec(),
        )
        .unwrap();
    state_trie_before
        .insert(sender_nibbles, rlp::encode(&sender_account_before).to_vec())
        .unwrap();
    state_trie_before
        .insert(to_nibbles, rlp::encode(&to_account_before).to_vec())
        .unwrap();

    storage_tries.push((to_hashed, Node::Empty.into()));

    let tries_before = TrieInputs {
        state_trie: state_trie_before,
        transactions_trie: Node::Empty.into(),
        receipts_trie: Node::Empty.into(),
        storage_tries,
    };

    let txn = hex!("f863800a83061a8094095e7baea6a6c7c4c2dfeb977efac326af552d87830186a0801ba0ffb600e63115a7362e7811894a91d8ba4330e526f22121c994c4692035dfdfd5a06198379fcac8de3dbfac48b165df4bf88e2088f294b61efb9a65fe2281c76e16");
    let txn_gas_limit = 400_000;
    let gas_price = 10;

    let block_metadata = BlockMetadata {
        block_beneficiary: Address::from(beneficiary),
        block_timestamp: 0x03e8.into(),
        block_number: 1.into(),
        block_difficulty: 0x020000.into(),
        block_random: H256::from_uint(&0x020000.into()),
        block_gaslimit: 0xff112233u32.into(),
        block_chain_id: 1.into(),
        block_base_fee: 0xa.into(),
        block_gas_used: txn_gas_limit.into(),
        ..Default::default()
    };

    // Here, since the transaction fails, it consumes its gas limit, and does
    // nothing else. The beacon roots contract is still updated prior transaction
    // execution.
    let expected_state_trie_after = {
        let beneficiary_account_after = beneficiary_account_before;
        // This is the only account that changes: the nonce and the balance are updated.
        let sender_account_after = AccountRlp {
            balance: sender_account_before.balance - txn_gas_limit * gas_price,
            nonce: 1.into(),
            ..AccountRlp::default()
        };
        let to_account_after = to_account_before;

        update_beacon_roots_account_storage(
            &mut beacon_roots_account_storage,
            block_metadata.block_timestamp,
            block_metadata.parent_beacon_block_root,
        )
        .unwrap();
        let beacon_roots_account =
            beacon_roots_contract_from_storage(&beacon_roots_account_storage);

        let mut expected_state_trie_after = HashedPartialTrie::from(Node::Empty);
        expected_state_trie_after
            .insert(
                beneficiary_nibbles,
                rlp::encode(&beneficiary_account_after).to_vec(),
            )
            .unwrap();
        expected_state_trie_after
            .insert(sender_nibbles, rlp::encode(&sender_account_after).to_vec())
            .unwrap();
        expected_state_trie_after
            .insert(to_nibbles, rlp::encode(&to_account_after).to_vec())
            .unwrap();
        expected_state_trie_after
            .insert(
                beacon_roots_account_nibbles(),
                rlp::encode(&beacon_roots_account).to_vec(),
            )
            .unwrap();
        expected_state_trie_after
            .insert(
                ger_account_nibbles(),
                rlp::encode(&GLOBAL_EXIT_ROOT_ACCOUNT).to_vec(),
            )
            .unwrap();
        expected_state_trie_after
    };

    let receipt_0 = LegacyReceiptRlp {
        status: false,
        cum_gas_used: txn_gas_limit.into(),
        bloom: vec![0; 256].into(),
        logs: vec![],
    };
    let mut receipts_trie = HashedPartialTrie::from(Node::Empty);
    receipts_trie
        .insert(
            Nibbles::from_str("0x80").unwrap(),
            rlp::encode(&receipt_0).to_vec(),
        )
        .unwrap();
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

    let inputs = GenerationInputs {
        signed_txns: vec![txn.to_vec()],
        withdrawals: vec![],
        global_exit_roots: vec![],
        tries: tries_before,
        trie_roots_after,
        contract_code: contract_code.clone(),
        block_metadata,
        checkpoint_state_trie_root: HashedPartialTrie::from(Node::Empty).hash(),
        txn_number_before: 0.into(),
        gas_used_before: 0.into(),
        gas_used_after: txn_gas_limit.into(),
        block_hashes: BlockHashes {
            prev_hashes: vec![H256::default(); 256],
            cur_hash: H256::default(),
        },
    };

    let initial_stack = vec![];
    let initial_offset = KERNEL.global_labels["init"];
    let mut interpreter: Interpreter<F> =
        Interpreter::new_with_generation_inputs(initial_offset, initial_stack, &inputs, None);

    interpreter.set_is_kernel(true);
    interpreter
        .run()
        .expect("Proving add11 with exception failed.");
}
