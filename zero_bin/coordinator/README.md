# Coordinator

Coordinator serves as modified Leader for evaluating multiple blocks.  It serves as a persistent instance similar to the service provided by the Leader.  The Coordinator steals functions from a modified Leader crate (needed to make some functions public), and runs persistently.  It receives requests for a starting block, along with various possible termination conditions.

## Benchmarking

We set up various benchmarking opportunities to evaluate the amount of time it takes to run several operations per block.

```rust
pub struct BenchmarkingStats {
    /// The block number of the block proved
    pub block_number: u64,
    /// The number of transactions in the block proved
    pub n_txs: u64,
    /// The cumulative transaction count.  This is the number of transactions
    /// from this block and all blocks beforehand.  None implies data not
    /// available, not 0.
    pub cumulative_n_txs: Option<u64>,
    /// Currently not applicable
    pub avg_tx_proof_duration: Option<f64>,
    /// The duration fo time took to fetch [prover::ProverInput], stored as a
    /// [Duration].
    pub fetch_duration: Duration,
    /// The amount of time elapsed during the process of proving this block,
    /// stored as a [Duration]
    pub proof_duration: Duration,
    /// The start time of the proof.  [BenchmarkingStats::proof_duration] is a
    /// more reliable value to use for the proof duration.  Timestamps measured
    /// in UTC.
    pub start_time: DateTime<Utc>,
    /// The end time of the proof.  [BenchmarkingStats::proof_duration] is a
    /// more reliable value to use for the proof duration.  Timestamps measured
    /// in UTC.
    pub end_time: DateTime<Utc>,
    /// The number of seconds elapsed from the first block in the benchmarking
    /// process and the end of the current block being proven
    pub overall_elapsed_seconds: Option<u64>,
    /// The amount of time elapsed during the process of saving this block's
    /// proof to its output, stored as a [Duration]
    pub proof_out_duration: Option<Duration>,
    /// The gas used by the block we proved
    pub gas_used: u64,
    /// The gas used per transaction in the block in the original chain
    pub gas_used_per_tx: Vec<u64>,
    /// The cumulative gas used by the block we proved.  None implies
    /// not filled in, not 0.
    pub cumulative_gas_used: Option<u64>,
    /// The difficulty of the block we proved
    pub difficulty: u64,
}
```

## Concurrency

We have attempted both a sequential approach and two concurrent approaches.

### Sequential

The sequential approach was simply placing the function to prove the blocks within a for loop.  This proved to not be the most effective solution.  

### Parallel

We then tried to utilize tokio's thread spawning to spawn a new thread for each block we intend on proving, performing up to `num_parallel` in parallel, placing the futures in a queue to dequeue from the front whenever it becomes ready.

We later attempted to avoid needlessly recreating the threads we spawned by setting up an async channel receiver in each thread to pull from a queue of ProverInput.  This enables us to start proving blocks without needing to spawn a new thread.  This reduction in overhead did allow for some more blocks to be proven in the same time period.  It also enabled blocks to be completed out of order rather than the former parallel method which relied off dequeueing the blocks in order.

## Requests

To start the benchmarking process, you need to send a post request to the running endpoint.  It accepts the data formatted as a json.

### Fields

Subject to change, if any issues review the structs in the `input` module.

#### Required fields

- `start_block_number`: the first block to be included
- ``

#### Optional Fields

- `checkpoint_block_number`: The checkpoint block number, otherwise will be 0
- `terminate_on`: The conditions for termination.
- `proof_out`: If not provided, will not output the proofs.  

#### Terminate On

TODO: Describe the Termination settings

#### Proof Output

TODO: Describe the Proof Output settings

#### Benchmark Output

TODO: Describe the Benchmark Output settings.

### Examples

The example below proves blocks [1,10] using the RPC function listed in ZeroBin, outputs the proofs to a local directory where each proof will have a prefix of "test" (i.e. "test_1" for block 1, "test_2" for block 2, ...), and output the benchmark statistics locally to "test.csv".  The directories in which these files appear are established by the local environment.

```json
{
  "run_name": "run",
  "block_interval": "3..=10",
  "block_source": {
    "ZeroBinRpc": {"rpc_url": "http://35.208.84.178:8545/"}
  },
  "proof_output": {
    "LocalDirectory": {"prefix": "test"}
  },
  "benchmark_output": {
    "LocalCsv": {"file_name": "test.csv"}
  }
}
```

```json
{
  "run_name": "run",
  "block_interval": "3..=10",
  "block_source": {
    "ZeroBinRpc": {"rpc_url": "http://35.208.84.178:8545/"}
  },
  "benchmark_output": {
    "LocalCsv": {"file_name": "test.csv"}
  }
}
```

An example not recording the proofs, and posting the results to a google cloud storage bucket.

```json
{
  "run_name": "run",
  "block_interval": "3..=5",
  "block_source": {
    "ZeroBinRpc": {"rpc_url": "http://35.208.84.178:8545/"}
  },
  "benchmark_output": {
    "GoogleCloudStorageCsv": {"file_name": "test.csv", "bucket": "zkevm-csv"}
  }
}
```

In this example, we run the experiment for just one minute.

```json
{
  "block_interval": "3..=5",
  "block_source": {
    "ZeroBinRpc": {"rpc_url": "http://35.208.84.178:8545/"}
  },
  "benchmark_output": {
    "GoogleCloudStorageCsv": {"file_name": "test.csv", "bucket": "zkevm-csv"}
  }
}
```

```json
{
  "block_interval": "3..=5",
  "block_source": {
    "ZeroBinRpc": {"rpc_url": "http://35.208.84.178:8545/"}
  },
  "benchmark_output": {
    "GoogleCloudStorageCsv": {"file_name": "test.csv", "bucket": "zkevm-csv"}
  }
}
```

```json
{
  "block_interval": "3..=5",
  "block_source": {
    "ZeroBinRpc": {"rpc_url": "http://35.208.84.178:8545/"}
  },
  "benchmark_output": {
    "GoogleCloudStorageCsv": {"file_name": "2hr_parallel.csv", "bucket": "zkevm-csv"}
  }
}
```
