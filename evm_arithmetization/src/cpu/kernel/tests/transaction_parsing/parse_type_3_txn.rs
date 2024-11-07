use anyhow::Result;
use either::Either;
use ethereum_types::{Address, U256};
use hex_literal::hex;
use keccak_hash::H256;
use plonky2::field::goldilocks_field::GoldilocksField as F;
use NormalizedTxnField::*;

use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::txn_fields::NormalizedTxnField;
use crate::cpu::kernel::interpreter::Interpreter;
use crate::cpu::kernel::tests::account_code::prepare_interpreter;
use crate::cpu::kernel::tests::transaction_parsing::prepare_interpreter_for_txn_parsing;
use crate::generation::mpt::{EitherAccount, MptAccount};
use crate::testing_utils::EMPTY_NODE_HASH;

#[test]
fn process_type_3_txn() -> Result<()> {
    let sender_address = Address::from_slice(&hex!("a94f5374fce5edbc8e2a8697c15331677e6ebf0b"));
    let sender_account = EitherAccount(Either::Left(MptAccount {
        nonce: 1.into(),
        balance: 0x1000000.into(),
        storage_root: EMPTY_NODE_HASH,
        code_hash: H256::default(),
    }));

    let mut interpreter: Interpreter<F> = Interpreter::new(0, vec![], None);
    // Prepare the interpreter by inserting the sender account in the state trie.
    prepare_interpreter(&mut interpreter, sender_address, &sender_account)?;

    // Generated with py-evm:
    // from eth_keys import keys
    // from eth_utils import decode_hex
    // from eth_typing import Address, Hash32
    // from eth import constants
    // from eth.chains.base import MiningChain
    // from eth.vm.forks.cancun import CancunVM
    // from eth.db.atomic import AtomicDB
    // from rlp import encode
    // GENESIS_PARAMS = {
    //     'difficulty': 0,
    //     'gas_limit': 3141592,
    //     'timestamp': 1514764800,
    // }
    // SENDER_PRIVATE_KEY = keys.PrivateKey(
    //     decode_hex('
    // 0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8') )
    // SENDER = Address(SENDER_PRIVATE_KEY.public_key.to_canonical_address())
    // RECEIVER = Address(b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x02')
    // klass = MiningChain.configure(
    //     __name__='TestChain',
    //     vm_configuration=(
    //         (constants.GENESIS_BLOCK_NUMBER, CancunVM),
    //     ))
    // chain = klass.from_genesis(AtomicDB(), GENESIS_PARAMS)
    // genesis = chain.get_canonical_block_header_by_number(0)
    // vm = chain.get_vm()
    // blob_versioned_hashes = [Hash32(32 * b"\x01"), Hash32(32 * b"\x01")]
    // unsigned_tx =
    // vm.get_transaction_builder().new_unsigned_blob_transaction(chain_id=1337,
    // nonce=1, max_priority_fee_per_gas=1000, max_fee_per_gas=500, gas=21000,
    // to=RECEIVER, value=1, data=b'\x42\x42', access_list=[], max_fee_per_blob_gas
    // = 1000, blob_versioned_hashes=blob_versioned_hashes
    //         )
    // signed_tx = unsigned_tx.as_signed_transaction(SENDER_PRIVATE_KEY)
    // encode(signed_tx).hex()[4::] # We don't need the initial RLP prefix.
    let txn = hex!("03f8b1820539018203e88201f482520894000000000000000000000000000000000000000201824242c08203e8f842a00101010101010101010101010101010101010101010101010101010101010101a0010101010101010101010101010101010101010101010101010101010101010180a076e2a81a28e69fb1e96f5e9470b454b80663197b416c3783be98a6b5bd162b21a01a182d7a386f81bcbdcc714b2b481b78547b26eaa6b4de417ecd3c1cd53ab839").to_vec();

    prepare_interpreter_for_txn_parsing(
        &mut interpreter,
        KERNEL.global_labels["process_type_3_txn"],
        KERNEL.global_labels["process_normalized_txn"],
        txn,
    )?;

    interpreter.run()?;

    assert_eq!(interpreter.get_txn_field(ChainIdPresent), 1.into());
    assert_eq!(interpreter.get_txn_field(ChainId), 1337.into());
    assert_eq!(interpreter.get_txn_field(Nonce), 1.into());
    assert_eq!(interpreter.get_txn_field(MaxPriorityFeePerGas), 1000.into());
    assert_eq!(interpreter.get_txn_field(MaxFeePerGas), 500.into());
    assert_eq!(interpreter.get_txn_field(To), 0x02.into());
    assert_eq!(interpreter.get_txn_field(Value), 1.into());
    assert_eq!(interpreter.get_txn_field(DataLen), 2.into());
    assert_eq!(interpreter.get_txn_data(), &[0x42.into(), 0x42.into()]);
    assert_eq!(interpreter.get_txn_field(YParity), 0.into());
    assert_eq!(
        interpreter.get_txn_field(R),
        U256::from_big_endian(&hex!(
            "76e2a81a28e69fb1e96f5e9470b454b80663197b416c3783be98a6b5bd162b21"
        ))
    );
    assert_eq!(
        interpreter.get_txn_field(S),
        U256::from_big_endian(&hex!(
            "1a182d7a386f81bcbdcc714b2b481b78547b26eaa6b4de417ecd3c1cd53ab839"
        ))
    );
    assert_eq!(
        interpreter.get_txn_field(Origin),
        U256::from_big_endian(&hex!("a94f5374fce5edbc8e2a8697c15331677e6ebf0b"))
    );

    Ok(())
}

#[test]
fn process_type_3_txn_invalid_sig() -> Result<()> {
    let sender_address = Address::from_slice(&hex!("a94f5374fce5edbc8e2a8697c15331677e6ebf0b"));
    let sender_account = EitherAccount(Either::Left(MptAccount {
        nonce: 1.into(),
        balance: 0x1000000.into(),
        storage_root: EMPTY_NODE_HASH,
        code_hash: H256::default(),
    }));

    let mut interpreter: Interpreter<F> = Interpreter::new(0, vec![], None);
    // Prepare the interpreter by inserting the sender account in the state trie.
    prepare_interpreter(&mut interpreter, sender_address, &sender_account)?;

    // Same transaction as `process_type_3_txn()`, with the exception that the `s`
    // component in the signature is flipped (i.e. `s' = N - s`, where `N` is the
    // order of the SECP256k1 prime subgroup).
    // It should fail according to EIP-2 (`s` must be no greater than `N/2`).
    let txn = hex!("03f8b1820539018203e88201f482520894000000000000000000000000000000000000000201824242c08203e8f842a00101010101010101010101010101010101010101010101010101010101010101a0010101010101010101010101010101010101010101010101010101010101010180a076e2a81a28e69fb1e96f5e9470b454b80663197b416c3783be98a6b5bd162b21a0e5e7d285c7907e4342338eb4d4b7e4866633b5fc0893c1fa4105226ffafb8908").to_vec();

    let mut interpreter = Interpreter::<F>::new(0, vec![], None);
    prepare_interpreter_for_txn_parsing(
        &mut interpreter,
        KERNEL.global_labels["process_type_3_txn"],
        KERNEL.global_labels["process_normalized_txn"],
        txn,
    )?;

    let result = interpreter.run();
    assert!(result.is_err());

    Ok(())
}
