#![cfg(feature = "eth_mainnet")]

use std::time::Duration;

use evm_arithmetization::fixed_recursive_verifier::AllRecursiveCircuits;
use evm_arithmetization::prover::prove;
use evm_arithmetization::testing_utils::{
    init_logger, segment_with_empty_tables, TEST_RECURSION_CONFIG, TEST_STARK_CONFIG,
    TEST_THRESHOLD_DEGREE_BITS,
};
use evm_arithmetization::verifier::testing::verify_all_proofs;
use evm_arithmetization::AllStark;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::timed;
use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
use plonky2::util::timing::TimingTree;

/// This test focuses on testing zkVM proofs with some empty tables.
#[test]
#[ignore]
fn empty_tables() -> anyhow::Result<()> {
    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    init_logger();

    let all_stark = AllStark::<F, D>::default();
    let config = TEST_STARK_CONFIG;
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
            &[16..17, 8..9, 7..8, 4..6, 8..9, 4..5, 16..17, 16..17, 16..17],
            &config,
            Some(&TEST_RECURSION_CONFIG),
            Some(&TEST_RECURSION_CONFIG),
            Some(TEST_THRESHOLD_DEGREE_BITS),
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

    // Test serialization of preprocessed circuits
    {
        let gate_serializer = DefaultGateSerializer;
        let generator_serializer = DefaultGeneratorSerializer::<C, D>::default();

        let timing = TimingTree::new("serialize AllRecursiveCircuits", log::Level::Info);
        let all_circuits_bytes = all_circuits
            .to_bytes(false, &gate_serializer, &generator_serializer)
            .map_err(|_| anyhow::Error::msg("AllRecursiveCircuits serialization failed."))?;
        timing.filter(Duration::from_millis(100)).print();
        log::info!(
            "AllRecursiveCircuits length: {} bytes",
            all_circuits_bytes.len()
        );

        let timing = TimingTree::new("deserialize AllRecursiveCircuits", log::Level::Info);
        let all_circuits_from_bytes = AllRecursiveCircuits::from_bytes(
            &all_circuits_bytes,
            false,
            &gate_serializer,
            &generator_serializer,
        )
        .map_err(|_| anyhow::Error::msg("AllRecursiveCircuits deserialization failed."))?;
        timing.filter(Duration::from_millis(100)).print();

        assert_eq!(all_circuits, all_circuits_from_bytes);
    }

    Ok(())
}
