# Coordinator

Coordinator serves as modified Leader for evaluating multiple blocks.  It serves as a persistent instance similar to the service provided by the Leader.  The Coordinator steals functions from a modified Leader crate (needed to make some functions public), and runs persistently.  It receives requests for a starting block, along with various possible termination conditions.

## Benchmarking

We set up various benchmarking opportunities to evaluate the amount of time it takes to run several operations per block.

| block_number             | The block number of the proof                                                                                                                                                                                                             |
|--------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|  number_txs              | The number of transactions in the block                                                                                                                                                                                                   |
|  cumulative_number_txs   | The number of transactions in the range of blocks we have proven                                                                                                                                                                          |
|  fetch_duration          | The amount of time (if applicable) it took to load the witness                                                                                                                                                                            |
|  unique_proof_duration   | The amount of time from the start of the proof towards the end.  NOTE: Since ZeroBin operates in Parallel now, this is less of an accurate measurement since the block proof may have to wait for all previous blocks to be proven first. |
|  prep_duration           | Everything that happens prior to actually proving                                                                                                                                                                                         |
|  txproof_duration        | The time took to prove the transactions in the block                                                                                                                                                                                      |
| agg_wait_duration        | The time spent waiting for the previous block to be aggregated                                                                                                                                                                            |
|  agg_duration            | The time spent to aggregate the previous blocks into a singular proof including this one                                                                                                                                                  |
|  start_time              | The time the block proof was started                                                                                                                                                                                                      |
|  end_time                | The time the block proof was ended (including aggregation)                                                                                                                                                                                |
|  cumulative_elapsed_time | The overall elapsed time in the run when the                                                                                                                                                                                              |
|  proof_out_duration      | (if applicable) the time it took to output the proof                                                                                                                                                                                      |
|  gas_used                | The amount of gas used in the block                                                                                                                                                                                                       |
|  cumulative_gas_used     | The amount of gas used in all the blocks in the run up to this block                                                                                                                                                                      |
|  difficulty              | The block difficulty                                                                                                                                                                                                                      |
|  gas_used_per_tx         | The gas used per transaction as a list separated by `;`                                                                                                                                                                                   |

## Concurrency

We have attempted both a sequential approach and two concurrent approaches before ZeroBin itself became parallelized.  Now this section is irrelevant.

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
  "block_source": {
    "Rpc": {
      "rpc_url": "http://35.208.84.178:8545/",
      "block_interval": "3..=5",
      "rpc_type": "Jerigon",
    }
  },
  "benchmark_output": {
    "LocalCsv": {"file_name": "test.csv"}
  }
}
```

```json
{
  "run_name": "run",
  "block_source": {
    "Rpc": {
      "rpc_url": "http://35.208.84.178:8545/",
      "block_interval": "3..=10",
      "rpc_type": "Jerigon",
    }
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
