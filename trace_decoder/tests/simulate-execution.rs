//! Check that the [`evm_arithmetization::GenerationInputs`] produced by
//! [`trace_decoder`] are consistent between each other, and with the block
//! header obtained over RPC.

mod common;

use anyhow::Context as _;
use common::{cases, Case};
use libtest_mimic::{Arguments, Trial};
use plonky2::field::goldilocks_field::GoldilocksField;
use trace_decoder::observer::DummyObserver;
use zero::prover::WIRE_DISPOSITION;

fn main() -> anyhow::Result<()> {
    let mut trials = vec![];
    for batch_size in [1, 3] {
        for Case {
            name,
            header: _,
            trace,
            other,
        } in cases()?
        {
            let (gen_inputs, _) = trace_decoder::entrypoint(
                trace,
                other,
                None,
                batch_size,
                &mut DummyObserver::new(),
                WIRE_DISPOSITION,
            )
            .context(format!(
                "error in `trace_decoder` for {name} at batch size {batch_size}"
            ))?;
            for (ix, gi) in gen_inputs.into_iter().enumerate() {
                trials.push(Trial::test(
                    format!("{name}@{batch_size}/{ix}"),
                    move || {
                        evm_arithmetization::prover::testing::simulate_execution_all_segments::<
                            GoldilocksField,
                        >(gi, 19, &None)
                        .map_err(|e| format!("{e:?}"))?; // get the full error chain
                        Ok(())
                    },
                ))
            }
        }
    }
    libtest_mimic::run(&Arguments::from_args(), trials).exit()
}
