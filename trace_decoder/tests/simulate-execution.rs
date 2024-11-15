//! Check that the [`evm_arithmetization::GenerationInputs`] produced by
//! [`trace_decoder`] are consistent between each other, and with the block
//! header obtained over RPC.

mod common;

use anyhow::Context as _;
use common::{cases, Case};
use evm_arithmetization::{
    testing_utils::{init_logger, TEST_STARK_CONFIG},
    AllStark, ProofWithPublicInputs, StarkConfig,
};
use libtest_mimic::{Arguments, Trial};
use plonky2::{
    field::goldilocks_field::GoldilocksField, plonk::config::PoseidonGoldilocksConfig,
    util::timing::TimingTree,
};
use trace_decoder::observer::DummyObserver;
use zero::prover::WIRE_DISPOSITION;

fn main() -> anyhow::Result<()> {
    init_logger();
    let mut trials = vec![];
    for batch_size in [50] {
        for Case {
            name,
            header: _,
            trace,
            other,
        } in cases()?
        {
            let gen_inputs = trace_decoder::entrypoint(
                trace,
                other,
                batch_size,
                &mut DummyObserver::new(),
                WIRE_DISPOSITION,
            )
            .context(format!(
                "error in `trace_decoder` for {name} at batch size {batch_size}"
            ))?;
            for (ix, gi) in gen_inputs.into_iter().enumerate() {
                if name == "b20240052_main" && ix == 0 {
                    trials.push(Trial::test(
                        format!("{name}@{batch_size}/{ix}"),
                        move || {
                            let all_stark = AllStark::<GoldilocksField, 2>::default();
                            let config = TEST_STARK_CONFIG;
                            let timing =
                                &mut TimingTree::new(&format!("Blockproof"), log::Level::Info);
                            //     evm_arithmetization::prover::testing::simulate_execution_all_segments::<
                            //     GoldilocksField,
                            // >(gi, 25)
                            // .map_err(|e| format!("{e:?}"))?; // get the full error chain
                            evm_arithmetization::prover::testing::prove_all_segments::<
                                GoldilocksField,
                                PoseidonGoldilocksConfig,
                                2,
                            >(&all_stark, &config, gi, 22, timing, None)
                            .unwrap();
                            Ok(())
                        },
                    ))
                }
            }
        }
    }
    libtest_mimic::run(&Arguments::from_args(), trials).exit()
}
