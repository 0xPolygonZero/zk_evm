use anyhow::Result;
use ethereum_types::U256;
use hex_literal::hex;
use plonky2::field::goldilocks_field::GoldilocksField as F;
use NormalizedTxnField::*;

use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::txn_fields::NormalizedTxnField;
use crate::cpu::kernel::interpreter::Interpreter;
use crate::memory::segments::Segment;

#[test]
fn process_type_1_txn() -> Result<()> {
    let process_type_1_txn = KERNEL.global_labels["process_type_1_txn"];
    let process_normalized_txn = KERNEL.global_labels["process_normalized_txn"];

    let retaddr = 0xDEADBEEFu32.into();
    const INITIAL_TXN_RLP_ADDR: usize = Segment::RlpRaw as usize + 1;
    let mut interpreter: Interpreter<F> = Interpreter::new(
        process_type_1_txn,
        vec![retaddr, INITIAL_TXN_RLP_ADDR.into()],
        None,
    );

    // When we reach process_normalized_txn, we're done with parsing and
    // normalizing. Processing normalized transactions is outside the scope of
    // this test.
    interpreter.halt_offsets.push(process_normalized_txn);

    // Generated with py-evm:
    // from eth_keys import keys
    // from eth_utils import decode_hex
    // from eth_typing import Address
    // from eth import constants
    // from eth.chains.base import MiningChain
    // from eth.vm.forks.berlin import BerlinVM
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
    //         (constants.GENESIS_BLOCK_NUMBER, BerlinVM),
    //     ))
    // chain = klass.from_genesis(AtomicDB(), GENESIS_PARAMS)
    // genesis = chain.get_canonical_block_header_by_number(0)
    // vm = chain.get_vm()
    // unsigned_tx =
    // vm.get_transaction_builder().
    // new_unsigned_access_list_transaction(chain_id=1337, nonce=1, gas_price=1000,
    // gas=21000, to=RECEIVER, value=1, data=b'\x42\x42', access_list=[],
    //         )
    // signed_tx = unsigned_tx.as_signed_transaction(SENDER_PRIVATE_KEY)
    // encode(signed_tx).hex()[4::] # We don't need the initial RLP prefix.
    interpreter.extend_memory_segment_bytes(Segment::RlpRaw, hex!("01f867820539018203e882520894000000000000000000000000000000000000000201824242c080a0e0c03d1aae7278dffd6c864231a5bb571d7ee3ececd3718b26d3d8554b4987f5a02dfb1aeea35ba8c5191abb6efdae6f73c052209fc6a598025b7292db470d9450").to_vec());

    interpreter.run()?;

    assert_eq!(interpreter.get_txn_field(ChainIdPresent), 1.into());
    assert_eq!(interpreter.get_txn_field(ChainId), 1337.into());
    assert_eq!(interpreter.get_txn_field(Nonce), 1.into());
    assert_eq!(interpreter.get_txn_field(MaxPriorityFeePerGas), 1000.into());
    assert_eq!(interpreter.get_txn_field(MaxFeePerGas), 1000.into());
    assert_eq!(interpreter.get_txn_field(To), 0x02.into());
    assert_eq!(interpreter.get_txn_field(Value), 1.into());
    assert_eq!(interpreter.get_txn_field(DataLen), 2.into());
    assert_eq!(interpreter.get_txn_data(), &[0x42.into(), 0x42.into()]);
    assert_eq!(interpreter.get_txn_field(YParity), 0.into());
    assert_eq!(
        interpreter.get_txn_field(R),
        U256::from_big_endian(&hex!(
            "e0c03d1aae7278dffd6c864231a5bb571d7ee3ececd3718b26d3d8554b4987f5"
        ))
    );
    assert_eq!(
        interpreter.get_txn_field(S),
        U256::from_big_endian(&hex!(
            "2dfb1aeea35ba8c5191abb6efdae6f73c052209fc6a598025b7292db470d9450"
        ))
    );

    Ok(())
}

#[test]
fn process_type_1_txn_invalid_sig() -> Result<()> {
    let process_type_1_txn = KERNEL.global_labels["process_type_1_txn"];
    let process_normalized_txn = KERNEL.global_labels["process_normalized_txn"];

    let retaddr = 0xDEADBEEFu32.into();
    const INITIAL_TXN_RLP_ADDR: usize = Segment::RlpRaw as usize + 1;
    let mut interpreter: Interpreter<F> = Interpreter::new(
        process_type_1_txn,
        vec![retaddr, INITIAL_TXN_RLP_ADDR.into()],
        None,
    );

    // If we reach process_normalized_txn, the test fails (we should have had a
    // kernel panic beforehand).
    interpreter.halt_offsets.push(process_normalized_txn);

    // Same transaction as `process_type_1_txn()`, with the exception that the `s`
    // component in the signature is flipped (i.e. `s' = N - s`, where `N` is the
    // order of the SECP256k1 prime subgroup).
    interpreter.extend_memory_segment_bytes(Segment::RlpRaw, hex!("01f867820539018203e882520894000000000000000000000000000000000000000201824242c080a0e0c03d1aae7278dffd6c864231a5bb571d7ee3ececd3718b26d3d8554b4987f5a0d204e5115ca4573ae6e544910251908afa5cbc46e8a30839645fcbb18928acf1").to_vec());

    let result = interpreter.run();
    assert!(result.is_err());

    Ok(())
}
