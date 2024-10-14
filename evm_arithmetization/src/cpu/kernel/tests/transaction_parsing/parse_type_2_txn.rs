use anyhow::Result;
use ethereum_types::U256;
use hex_literal::hex;
use plonky2::field::goldilocks_field::GoldilocksField as F;
use NormalizedTxnField::*;

use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::txn_fields::NormalizedTxnField;
use crate::cpu::kernel::interpreter::Interpreter;
use crate::cpu::kernel::tests::transaction_parsing::prepare_interpreter_for_txn_parsing;

#[test]
fn process_type_2_txn() -> Result<()> {
    // Generated with py-evm:
    // from eth_keys import keys
    // from eth_utils import decode_hex
    // from eth_typing import Address
    // from eth import constants
    // from eth.chains.base import MiningChain
    // from eth.vm.forks.london import LondonVM
    // from eth.db.atomic import AtomicDB
    // from rlp import encode
    // GENESIS_PARAMS = {
    //     'difficulty': 1,
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
    //         (constants.GENESIS_BLOCK_NUMBER, LondonVM),
    //     ))
    // chain = klass.from_genesis(AtomicDB(), GENESIS_PARAMS)
    // genesis = chain.get_canonical_block_header_by_number(0)
    // vm = chain.get_vm()
    // unsigned_tx =
    // vm.get_transaction_builder().
    // new_unsigned_dynamic_fee_transaction(chain_id=1337, nonce=1,
    // max_priority_fee_per_gas=1000, max_fee_per_gas=500, gas=21000, to=RECEIVER,
    // value=1, data=b'\x42\x42', access_list=[],
    //         )
    // signed_tx = unsigned_tx.as_signed_transaction(SENDER_PRIVATE_KEY)
    // encode(signed_tx).hex()[4::] # We don't need the initial RLP prefix.
    let txn =  hex!("02f86a820539018203e88201f482520894000000000000000000000000000000000000000201824242c080a06312f059f931a9cf9e9ef4648b14fff1d6f88fbc1aed5ebcb1138f50e295a6b3a0252349ddb42d28b1b2b7c749370867047c8c33d4a0ada8ff7f0d5b71bea862ab").to_vec();

    let mut interpreter = Interpreter::<F>::new(0, vec![], None, &None);
    prepare_interpreter_for_txn_parsing(
        &mut interpreter,
        KERNEL.global_labels["process_type_2_txn"],
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
            "6312f059f931a9cf9e9ef4648b14fff1d6f88fbc1aed5ebcb1138f50e295a6b3"
        ))
    );
    assert_eq!(
        interpreter.get_txn_field(S),
        U256::from_big_endian(&hex!(
            "252349ddb42d28b1b2b7c749370867047c8c33d4a0ada8ff7f0d5b71bea862ab"
        ))
    );
    assert_eq!(
        interpreter.get_txn_field(Origin),
        U256::from_big_endian(&hex!("a94f5374fce5edbc8e2a8697c15331677e6ebf0b"))
    );

    Ok(())
}

#[test]
fn process_type_2_txn_invalid_sig() -> Result<()> {
    // Same transaction as `process_type_2_txn()`, with the exception that the `s`
    // component in the signature is flipped (i.e. `s' = N - s`, where `N` is the
    // order of the SECP256k1 prime subgroup).
    // It should fail according to EIP-2 (`s` must be no greater than `N/2`).
    let txn = hex!("f86a820539018203e88201f482520894000000000000000000000000000000000000000201824242c080a06312f059f931a9cf9e9ef4648b14fff1d6f88fbc1aed5ebcb1138f50e295a6b3a0dadcb6224bd2d74e4d4838b6c8f798fa3e22a9120e9af73c40c5031b118dde96").to_vec();

    let mut interpreter = Interpreter::<F>::new(0, vec![], None, &None);
    prepare_interpreter_for_txn_parsing(
        &mut interpreter,
        KERNEL.global_labels["process_type_2_txn"],
        KERNEL.global_labels["process_normalized_txn"],
        txn,
    )?;

    let result = interpreter.run();
    assert!(result.is_err());

    Ok(())
}
