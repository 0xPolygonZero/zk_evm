#![cfg(feature = "eth_mainnet")]

use evm_arithmetization::fixed_recursive_verifier::AllRecursiveCircuits;
use evm_arithmetization::prover::prove;
use evm_arithmetization::testing_utils::{init_logger, segment_with_empty_tables};
use evm_arithmetization::verifier::testing::verify_all_proofs;
use evm_arithmetization::AllStark;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::timed;
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
    let timing = &mut TimingTree::new("Empty Table Test", log::Level::Info);

    // Generate segment data
    let (payload, mut segment_data) = segment_with_empty_tables()?;

    // Create all STARK proofs
    let mut proofs = vec![];
    let proof = timed!(
        timing,
        log::Level::Info,
        "Create all STARK proofs",
        prove::<F, C, D>(
            &all_stark,
            &config,
            payload,
            &mut segment_data,
            timing,
            None,
        )?
    );
    proofs.push(proof);

    // Verify the generated STARK proofs
    verify_all_proofs(&all_stark, &proofs, &config)?;

    // Process and generate segment proof
    let all_circuits = timed!(
        timing,
        log::Level::Info,
        "Create all recursive circuits",
        AllRecursiveCircuits::<F, C, D>::new(
            &all_stark,
            &[16..17, 8..9, 7..8, 4..9, 8..9, 4..7, 16..17, 16..17, 16..17],
            &config,
        )
    );
    let segment_proof = timed!(
        timing,
        log::Level::Info,
        "Prove segment",
        all_circuits.prove_segment_with_all_proofs(&proofs[0], &config, None)?
    );

    // Verify the generated segment proof
    timed!(
        timing,
        log::Level::Info,
        "Verify segment proof",
        all_circuits.verify_root(segment_proof.proof_with_pvs.intern.clone())?
    );

    // Print timing details
    timing.print();

    Ok(())
}
