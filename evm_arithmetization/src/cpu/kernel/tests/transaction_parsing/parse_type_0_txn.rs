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
fn process_type_0_txn() -> Result<()> {
    // Generated with py-evm:
    // import eth, eth_keys, eth_utils, rlp
    // genesis_params = { 'difficulty': eth.constants.GENESIS_DIFFICULTY }
    // chain = eth.chains.mainnet.MainnetChain.from_genesis(eth.db.atomic.
    // AtomicDB(), genesis_params, {}) unsigned_txn =
    // chain.create_unsigned_transaction(     nonce=5,
    //     gas_price=10,
    //     gas=22_000,
    //     to=eth.constants.ZERO_ADDRESS,
    //     value=100,
    //     data=b'\x42\x42',
    // )
    // sk = eth_keys.keys.PrivateKey(eth_utils.decode_hex('
    // 4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318'))
    // signed_txn = unsigned_txn.as_signed_transaction(sk)
    // rlp.encode(signed_txn).hex()
    let txn = hex!("f861050a8255f0940000000000000000000000000000000000000000648242421ca07c5c61ed975ebd286f6b027b8c504842e50a47d318e1e801719dd744fe93e6c6a01e7b5119b57dd54e175ff2f055c91f3ab1b53eba0b2c184f347cdff0e745aca2").to_vec();

    let mut interpreter = Interpreter::<F>::new(0, vec![], None, None);
    prepare_interpreter_for_txn_parsing(
        &mut interpreter,
        KERNEL.global_labels["process_type_0_txn"],
        KERNEL.global_labels["process_normalized_txn"],
        txn,
    )?;

    interpreter.run()?;

    assert_eq!(interpreter.get_txn_field(ChainIdPresent), 0.into());
    assert_eq!(interpreter.get_txn_field(ChainId), 0.into());
    assert_eq!(interpreter.get_txn_field(Nonce), 5.into());
    assert_eq!(interpreter.get_txn_field(MaxPriorityFeePerGas), 10.into());
    assert_eq!(interpreter.get_txn_field(MaxFeePerGas), 10.into());
    assert_eq!(interpreter.get_txn_field(To), 0.into());
    assert_eq!(interpreter.get_txn_field(Value), 100.into());
    assert_eq!(interpreter.get_txn_field(DataLen), 2.into());
    assert_eq!(interpreter.get_txn_data(), &[0x42.into(), 0x42.into()]);
    assert_eq!(interpreter.get_txn_field(YParity), 1.into());
    assert_eq!(
        interpreter.get_txn_field(R),
        U256::from_big_endian(&hex!(
            "7c5c61ed975ebd286f6b027b8c504842e50a47d318e1e801719dd744fe93e6c6"
        ))
    );
    assert_eq!(
        interpreter.get_txn_field(S),
        U256::from_big_endian(&hex!(
            "1e7b5119b57dd54e175ff2f055c91f3ab1b53eba0b2c184f347cdff0e745aca2"
        ))
    );
    assert_eq!(
        interpreter.get_txn_field(Origin),
        U256::from_big_endian(&hex!("2c7536e3605d9c16a7a3d7b1898e529396a65c23"))
    );

    Ok(())
}

#[test]
fn process_type_0_txn_invalid_sig() -> Result<()> {
    // Same transaction as `process_type_0_txn()`, with the exception that the `s`
    // component in the signature is flipped (i.e. `s' = N - s`, where `N` is the
    // order of the SECP256k1 prime subgroup).
    // It should fail according to EIP-2 (`s` must be no greater than `N/2`).
    let txn = hex!("f861050a8255f0940000000000000000000000000000000000000000648242421ca07c5c61ed975ebd286f6b027b8c504842e50a47d318e1e801719dd744fe93e6c6a0e184aee64a822ab1e8a00d0faa36e0c408f99e2ca41c87ec8b557e9be8f0949f").to_vec();

    let mut interpreter = Interpreter::<F>::new(0, vec![], None, None);
    prepare_interpreter_for_txn_parsing(
        &mut interpreter,
        KERNEL.global_labels["process_type_1_txn"],
        KERNEL.global_labels["process_normalized_txn"],
        txn,
    )?;

    let result = interpreter.run();
    assert!(result.is_err());

    Ok(())
}
