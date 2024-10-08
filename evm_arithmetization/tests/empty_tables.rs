#![cfg(feature = "eth_mainnet")]

use std::time::Duration;

use evm_arithmetization::prover::prove;
use evm_arithmetization::testing_utils::{init_logger, segment_without_keccak};
use evm_arithmetization::verifier::testing::verify_all_proofs;
use evm_arithmetization::AllStark;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::util::timing::TimingTree;
use starky::config::StarkConfig;

/// This test focuses on testing zkVM proofs with some empty tables.
#[test]
fn empty_tables() -> anyhow::Result<()> {
    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    init_logger();

    let all_stark = AllStark::<F, D>::default();
    let config = StarkConfig::standard_fast_config();
    let mut proofs = vec![];
    let mut timing = TimingTree::new("prove", log::Level::Debug);

    let (payload, mut segment_data) = segment_without_keccak()?;
    let proof = prove::<F, C, D>(
        &all_stark,
        &config,
        payload.trim(),
        &mut segment_data,
        &mut timing,
        None,
    )?;
    proofs.push(proof);

    timing.filter(Duration::from_millis(100)).print();

    verify_all_proofs(&all_stark, &proofs, &config)
}
