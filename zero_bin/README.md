# Zero Bin

A composition of [`paladin`](https://github.com/0xPolygonZero/paladin) and [`plonky-block-proof-gen`](https://github.com/0xPolygonZero/plonky-block-proof-gen). Given the [proof generation protocol](/leader/src/prover_input.rs) as input, generate a proof. The project is instrumented with [`paladin`](https://github.com/0xPolygonZero/paladin), and as such can distribute proof generation across multiple worker machines.

- [Zero Bin](#zero-bin)
  - [Project layout](#project-layout)
    - [Ops](#ops)
    - [Worker](#worker)
    - [Leader](#leader)
  - [Usage](#usage)
    - [Paladin Runtime](#paladin-runtime)
      - [Starting an AMQP enabled cluster](#starting-an-amqp-enabled-cluster)
        - [Start worker(s)](#start-workers)
        - [Start leader](#start-leader)
      - [Starting an in-memory (single process) cluster](#starting-an-in-memory-single-process-cluster)
    - [Input mode](#input-mode)
      - [stdin](#stdin)
      - [HTTP](#http)
      - [Jerigon](#jerigon)
  - [Docker](#docker)


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
```
### Ops
Defines the proof operations that can be distributed to workers.

### Worker
The worker process. Receives proof operations from the leader, and returns the result.

### Leader
The leader process. Receives proof generation requests, and distributes them to workers.

## Usage

Leader binary arguments and options are comprised of paladin configuration and input mode:
```
cargo run --bin leader -- --help

Usage: leader [OPTIONS]

Options:
  -m, --mode <MODE>                  The input mode. If `std-io`, the input is read from stdin. If `http`, the input is read from HTTP requests. If `jerigon`, the input is read from the `debug_traceBlockByNumber` and `eth_getBlockByNumber` RPC methods from Jerigon [default: std-io] [possible values: std-io, http, jerigon]
  -p, --port <PORT>                  The port to listen on when using the `http` mode [default: 8080]
  -o, --output-dir <OUTPUT_DIR>      The directory to which output should be written (`http` mode only)
      --rpc-url <RPC_URL>            The RPC URL to use when using the `jerigon` mode
  -b, --block-number <BLOCK_NUMBER>  The block number to use when using the `jerigon` mode
  -r, --runtime <RUNTIME>            Specifies the paladin runtime to use [default: amqp] [possible values: amqp, in-memory]
  -h, --help                         Print help
```

### Paladin Runtime

Paladin supports both an AMQP and in-memory runtime. The in-memory runtime will emulate a cluster in memory within a single process, and is useful for testing. The AMQP runtime is geared for a production environment. The AMQP runtime requires a running AMQP broker and spinning up worker processes. The AMQP uri can be specified with the `--amqp-uri` flag or be set with the `AMQP_URI` environment variable.

#### Starting an AMQP enabled cluster

##### Start worker(s)

Start worker process(es). The default paladin runtime is AMQP, so no additional flags are required to enable it.

```bash
RUST_LOG=debug cargo r --release --bin worker
```

##### Start leader

Start the leader process with the desired [input mode](#input-mode). The default paladin runtime is AMQP, so no additional flags are required to enable it.

```bash
RUST_LOG=debug cargo r --release --bin leader -- --mode http --output-dir ./output
```

#### Starting an in-memory (single process) cluster

Paladin can emulate a cluster in memory within a single process. Useful for testing purposes.

```bash
RUST_LOG=debug cargo r --release --bin leader -- --mode http --runtime in-memory --output-dir ./output
```

### Input mode
Pass JSON encoded prover input to stdin or over HTTP, or point the leader to a Jerigon RPC endpoint to retrieve the prover input from the `debug_traceBlockByNumber` and `eth_getBlockByNumber` RPC methods.

See [`prover_input.rs`](/leader/src/prover_input.rs) for the input format. 

The `std-io` and `http` examples below assume some prover input is stored in `./block_121.json`.

#### stdin

```bash
cat ./block_121.json | RUST_LOG=debug cargo r --release --bin leader > ./output/block_121.json
```

#### HTTP

Start the server
```bash
RUST_LOG=debug cargo r --release --bin leader -- --mode http --output-dir ./output
```

Once initialized, send a request:
```bash
curl -X POST -H "Content-Type: application/json" -d @./block_121.json http://localhost:8080/prove
```

#### Jerigon

```bash
RUST_LOG=debug cargo r --release --bin leader -- --mode jerigon --runtime in-memory --rpc-url <RPC_URL> --block-number 16 > ./output/block_16.json
```
## Docker

Docker images are provided for both the [leader](leader.Dockerfile) and [worker](worker.Dockerfile) binaries.