# Zero Bin

A quick and dirty way to prove a block with plonky2. No orchestration. No distributed computation. Just a single instance of plonky2 running on a single machine.

## Usage

Pass JSON formatted prover input to stdin or over HTTP. See [data/block_121.json](data/block_121.json) for an example of the expected format.

### stdin

```bash
cat ./data/block_121.json | RUST_LOG=debug cargo r --release
```

### HTTP

Start the server
```bash
RUST_LOG=debug cargo r --release -- --mode http
```
Wait for initialization.

Once initialized, send a request:
```bash
curl -X POST -H "Content-Type: application/json" -d @./data/block_121.json http://localhost:8080/prove
```