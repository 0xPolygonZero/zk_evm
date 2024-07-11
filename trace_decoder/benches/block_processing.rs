//! Benchmarks the processing by the decoder of a block witness obtained from a
//! node into a sequence of prover inputs ready to be sent to a prover.
//!
//! The block being processed here is the 19240650th Ethereum block
//! (<https://etherscan.io/block/19240650>) containing 201 transactions and 16 withdrawals.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use trace_decoder::{BlockTrace, OtherBlockData};

#[derive(Clone, Debug, serde::Deserialize)]
pub struct ProverInput {
    pub block_trace: BlockTrace,
    pub other_data: OtherBlockData,
}

fn criterion_benchmark(c: &mut Criterion) {
    let prover_input =
        serde_json::from_slice::<ProverInput>(include_bytes!("block_input.json").as_slice())
            .unwrap();

    c.bench_function("Block 19240650 processing", |b| {
        b.iter_batched(
            || prover_input.clone(),
            |ProverInput {
                 block_trace,
                 other_data,
             }| {
                trace_decoder::entrypoint(block_trace, other_data, |_| unimplemented!()).unwrap()
            },
            BatchSize::LargeInput,
        )
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = criterion_benchmark);
criterion_main!(benches);
