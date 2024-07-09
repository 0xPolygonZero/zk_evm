//! Benchmarks the processing by the decoder of a block witness obtained from a
//! node into a sequence of prover inputs ready to be sent to a prover.
//!
//! The block being processed here is the 19240650th Ethereum block
//! (<https://etherscan.io/block/19240650>) containing 201 transactions and 16 withdrawals.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use serde::{Deserialize, Serialize};
use trace_decoder::{
    processed_block_trace::ProcessingMeta,
    trace_protocol::BlockTrace,
    types::{CodeHash, OtherBlockData},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProverInput {
    pub block_trace: BlockTrace,
    pub other_data: OtherBlockData,
}

fn resolve_code_hash_fn(_: &CodeHash) -> Vec<u8> {
    todo!()
}

fn criterion_benchmark(c: &mut Criterion) {
    let bytes = std::fs::read("benches/block_input.json").unwrap();
    let prover_input: ProverInput = serde_json::from_slice(&bytes).unwrap();

    let batch_sizes = vec![1, 2, 4, 8];

    let mut group = c.benchmark_group("Benchmark group");

    for batch_size in batch_sizes {
        let batch_size_string =
            format!("Block 19240650 processing, with batch_size = {batch_size}");
        group.bench_function(batch_size_string, |b| {
            b.iter_batched(
                || prover_input.clone(),
                |pi| {
                    pi.block_trace
                        .into_txn_proof_gen_ir(
                            &ProcessingMeta::new(resolve_code_hash_fn),
                            prover_input.other_data.clone(),
                            batch_size,
                        )
                        .unwrap()
                },
                BatchSize::LargeInput,
            )
        });
    }

    group.finish()
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = criterion_benchmark);
criterion_main!(benches);
