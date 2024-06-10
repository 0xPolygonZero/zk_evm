# Zero Bin

A composition of [`paladin`](https://github.com/0xPolygonZero/paladin) and [`plonky-block-proof-gen`](https://github.com/0xPolygonZero/plonky-block-proof-gen). Given the [proof generation protocol](/prover/src/lib.rs) as input, generate a proof. The project is instrumented with [`paladin`](https://github.com/0xPolygonZero/paladin), and as such can distribute proof generation across multiple worker machines.

- [Zero Bin](#zero-bin)
  - [Project layout](#project-layout)
    - [Ops](#ops)
    - [Worker](#worker)
    - [Leader](#leader)
    - [RPC](#rpc)
    - [Verifier](#verifier)
  - [Leader Usage](#leader-usage)
    - [stdio](#stdio)
    - [Jerigon](#jerigon)
    - [HTTP](#http)
    - [Paladin Runtime](#paladin-runtime)
      - [Starting an AMQP enabled cluster](#starting-an-amqp-enabled-cluster)
        - [Start worker(s)](#start-workers)
        - [Start leader](#start-leader)
      - [Starting an in-memory (single process) cluster](#starting-an-in-memory-single-process-cluster)
  - [Verifier Usage](#verifier-usage)
  - [RPC Usage](#rpc-usage)
  - [Docker](#docker)
  - [Development Branches](#development-branches)
  - [Testing Blocks](#testing-blocks)
    - [Proving Blocks](#proving-blocks)
    - [Generating Witnesses Only](#generating-witnesses-only)
  - [License](#license)
    - [Contribution](#contribution)

## Project layout

```
ops
├── Cargo.toml
└── src
   └── lib.rs
worker
├── Cargo.toml
└── src
   └── main.rs
leader
├── Cargo.toml
└── src
   └── main.rs
rpc
├── Cargo.toml
└── src
   └── main.rs
verifier
├── Cargo.toml
└── src
   └── main.rs
```

### Ops

Defines the proof operations that can be distributed to workers.

### Worker

The worker process. Receives proof operations from the leader, and returns the result.

### Leader

The leader process. Receives proof generation requests, and distributes them to workers.

### RPC

A binary to generate the block trace format expected by the leader.

### Verifier

A binary to verify the correctness of the generated proof.

## Leader Usage

The leader has various subcommands for different io modes. The leader binary arguments are as follows:

```
cargo r --release --bin leader -- --help

Usage: leader [OPTIONS] <COMMAND>

Commands:
  stdio    Reads input from stdin and writes output to stdout
  jerigon  Reads input from a Jerigon node and writes output to stdout
  http     Reads input from HTTP and writes output to a directory
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help
          Print help (see a summary with '-h')

Paladin options:
  -t, --task-bus-routing-key <TASK_BUS_ROUTING_KEY>
          Specifies the routing key for publishing task messages. In most cases, the default value should suffice

          [default: task]

  -s, --serializer <SERIALIZER>
          Determines the serialization format to be used

          [default: postcard]
          [possible values: postcard, cbor]

  -r, --runtime <RUNTIME>
          Specifies the runtime environment to use

          [default: amqp]
          [possible values: amqp, in-memory]

  -n, --num-workers <NUM_WORKERS>
          Specifies the number of worker threads to spawn (in memory runtime only)

      --amqp-uri <AMQP_URI>
          Provides the URI for the AMQP broker, if the AMQP runtime is selected

          [env: AMQP_URI=amqp://localhost:5672]

Table circuit sizes:
      --persistence <PERSISTENCE>
          [default: disk]

          Possible values:
          - none: Do not persist the processed circuits
          - disk: Persist the processed circuits to disk

      --arithmetic <CIRCUIT_BIT_RANGE>
          The min/max size for the arithmetic table circuit.

          [env: ARITHMETIC_CIRCUIT_SIZE=16..22]

      --byte-packing <CIRCUIT_BIT_RANGE>
          The min/max size for the byte packing table circuit.

          [env: BYTE_PACKING_CIRCUIT_SIZE=10..22]

      --cpu <CIRCUIT_BIT_RANGE>
          The min/max size for the cpu table circuit.

          [env: CPU_CIRCUIT_SIZE=15..22]

      --keccak <CIRCUIT_BIT_RANGE>
          The min/max size for the keccak table circuit.

          [env: KECCAK_CIRCUIT_SIZE=14..22]

      --keccak-sponge <CIRCUIT_BIT_RANGE>
          The min/max size for the keccak sponge table circuit.

          [env: KECCAK_SPONGE_CIRCUIT_SIZE=9..22]

      --logic <CIRCUIT_BIT_RANGE>
          The min/max size for the logic table circuit.

          [env: LOGIC_CIRCUIT_SIZE=12..22]

      --memory <CIRCUIT_BIT_RANGE>
          The min/max size for the memory table circuit.

          [env: MEMORY_CIRCUIT_SIZE=18..22]
```

Note that both paladin and plonky2 table circuit sizes are configurable via command line arguments and environment variables. The command line arguments take precedence over the environment variables.

**TABLE CIRCUIT SIZES ARE _ONLY_ RELEVANT FOR THE LEADER WHEN RUNNING IN `in-memory` MODE**.

If you want to configure the table circuit sizes when running in a distributed environment, you must configure the table circuit sizes on the worker processes (the command line arguments are the same).

### stdio

The stdio command reads proof input from stdin and writes output to stdout.

```
cargo r --release --bin leader stdio --help

Reads input from stdin and writes output to stdout

Usage: leader stdio [OPTIONS]

Options:
  -f, --previous-proof <PREVIOUS_PROOF>  The previous proof output
  -h, --help                             Print help
```

Pull prover input from the rpc binary.

```bash
cargo r --release --bin rpc fetch --rpc-url <RPC_URL> -b 6 > ./input/block_6.json
```

Pipe the block input to the leader binary.

```bash
cat ./input/block_6.json | cargo r --release --bin leader -- -r in-memory stdio > ./output/proof_6.json
```

### Jerigon

The Jerigon command reads proof input from a Jerigon node and writes output to stdout.

```
cargo r --release --bin leader jerigon --help

Reads input from a Jerigon node and writes output to stdout

Usage: leader jerigon [OPTIONS] --rpc-url <RPC_URL> --block-number <BLOCK_NUMBER>

Options:
  -u, --rpc-url <RPC_URL>

  -b, --block-number <BLOCK_NUMBER>
          The block number for which to generate a proof
  -c, --checkpoint-block-number <CHECKPOINT_BLOCK_NUMBER>
          The checkpoint block number [default: 0]
  -f, --previous-proof <PREVIOUS_PROOF>
          The previous proof output
  -o, --proof-output-path <PROOF_OUTPUT_PATH>
          If provided, write the generated proof to this file instead of stdout
  -h, --help
          Print help
  -s, --save-inputs-on-error
          If provided, save the public inputs to disk on error
```

Prove a block.

```bash
cargo r --release --bin leader -- -r in-memory jerigon -u <RPC_URL> -b 16 > ./output/proof_16.json
```

### HTTP

The HTTP command reads proof input from HTTP and writes output to a directory.

```
cargo r --release --bin leader http --help

Reads input from HTTP and writes output to a directory

Usage: leader http [OPTIONS] --output-dir <OUTPUT_DIR>

Options:
  -p, --port <PORT>              The port on which to listen [default: 8080]
  -o, --output-dir <OUTPUT_DIR>  The directory to which output should be written
  -h, --help                     Print help
```

Pull prover input from the rpc binary.

```bash
cargo r --release --bin rpc fetch -u <RPC_URL> -b 6 > ./input/block_6.json
```

Start the server.

```bash
RUST_LOG=debug cargo r --release --bin leader http --output-dir ./output
```

Note that HTTP mode requires a [slightly modified input format](./leader/src/http.rs#L56) from the rest of the commands. In particular, [the previous proof is expected to be part of the payload](./leader/src/http.rs#L58). This is due to the fact that the HTTP mode may handle multiple requests concurrently, and thus the previous proof cannot reasonably be given by a command line argument like the other modes.

Using `jq` we can merge the previous proof and the block input into a single JSON object.

```bash
jq -s '{prover_input: .[0], previous: .[1]}' ./input/block_6.json ./output/proof_5.json | curl -X POST -H "Content-Type: application/json" -d @- http://localhost:8080/prove
```

### Paladin Runtime

Paladin supports both an AMQP and in-memory runtime. The in-memory runtime will emulate a cluster in memory within a single process, and is useful for testing. The AMQP runtime is geared for a production environment. The AMQP runtime requires a running AMQP broker and spinning up worker processes. The AMQP uri can be specified with the `--amqp-uri` flag or be set with the `AMQP_URI` environment variable.

#### Starting an AMQP enabled cluster

Start rabbitmq

```bash
docker run --name rabbitmq -p 5672:5672 -p 15672:15672 rabbitmq:3-management
```

##### Start worker(s)

Start worker process(es). The default paladin runtime is AMQP, so no additional flags are required to enable it.

```bash
RUST_LOG=debug cargo r --release --bin worker
```

##### Start leader

Start the leader process with the desired [command](#leader-usage). The default paladin runtime is AMQP, so no additional flags are required to enable it.

```bash
RUST_LOG=debug cargo r --release --bin leader jerigon -u <RPC_URL> -b 16 > ./output/proof_16.json
```

#### Starting an in-memory (single process) cluster

Paladin can emulate a cluster in memory within a single process. Useful for testing purposes.

```bash
cat ./input/block_6.json | cargo r --release --bin leader -- -r in-memory stdio > ./output/proof_6.json
```

## Verifier Usage

A verifier binary is provided to verify the correctness of the generated proof. The verifier expects output in the format generated by the leader. The verifier binary arguments are as follows:

```
cargo r --bin verifier -- --help

Usage: verifier --file-path <FILE_PATH>

Options:
  -f, --file-path <FILE_PATH>  The file containing the proof to verify
  -h, --help                   Print help
```

Example:

```bash
cargo r --release --bin verifier -- -f ./output/proof_16.json
```

## RPC Usage

An rpc binary is provided to generate the block trace format expected by the leader.

```
cargo r --bin rpc -- --help

Usage: rpc <COMMAND>

Commands:
  fetch  Fetch and generate prover input from the RPC endpoint
  help   Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

Example:

```bash
cargo r --release --bin rpc fetch --rpc-url <RPC_URL> --block-number 16 > ./output/block-16.json
```

## Docker

Docker images are provided for both the [leader](leader.Dockerfile) and [worker](worker.Dockerfile) binaries.

## Development Branches

There are three branches that are used for development:

- `main` --> Always points to the latest production release
- `develop` --> All PRs should be merged into this branch
- `testing` --> For testing against the latest changes. Should always point to the `develop` branch for the `zk_evm` deps

## Testing Blocks

For testing proof generation for blocks, the `testing` branch should be used.

### Proving Blocks

If you want to generate a full block proof, you can use `tools/prove_blocks.sh`:

```sh
./prove_blocks.sh <BLOCK_START> <BLOCK_END> <FULL_NODE_ENDPOINT> <IGNORE_PREVIOUS_PROOFS>
```

Which may look like this:

```sh
./prove_blocks.sh 17 18 http://127.0.0.1:8545 false
```

Which will attempt to generate proofs for blocks `17` & `18` consecutively and incorporate the previous block proof during generation.

A few other notes:

- Proving blocks is very resource intensive in terms of both CPU and memory. You can also only generate the witness for a block instead (see [Generating Witnesses Only](#generating-witnesses-only)) to significantly reduce the CPU and memory requirements.
- Because incorporating the previous block proof requires a chain of proofs back to the last checkpoint height, you can also disable this requirement by passing `true` for `<IGNORE_PREVIOUS_PROOFS>` (which internally just sets the current checkpoint height to the previous block height).

### Generating Witnesses Only

If you want to test a block without the high CPU & memory requirements that come with creating a full proof, you can instead generate only the witness using `tools/prove_blocks.sh` in the `test_only` mode:

```sh
./prove_blocks.sh <START_BLOCK> <END_BLOCK> <FULL_NODE_ENDPOINT> <IGNORE_PREVIOUS_PROOFS> test_only
```

Filled in:

```sh
./prove_blocks.sh 18299898 18299899 http://34.89.57.138:8545 true test_only
```

Finally, note that both of these testing scripts force proof generation to be sequential by allowing only one worker. Because of this, this is not a realistic representation of performance but makes the debugging logs much easier to follow.

## License

Licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
