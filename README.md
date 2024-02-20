# zk_evm

A collection of libraries to prove Ethereum blocks with Polygon Zero Type 1 zkEVM,
powered by starky and plonky2 proving systems.


## Directory structure

This repository contains several Rust crates:

* [mpt_trie](./mpt_trie/README.md): A collection of types and functions to work with Ethereum Merkle Patricie Tries.

* [trace_decoder](./trace_decoder/README.md): Flexible protocol designed to process Ethereum clients trace payloads into an IR format that can be
understood by the zkEVM prover.

* [evm_arithmetization](./evm_arithmetization/README.md): Defines all the STARK constraints and recursive circuits to generate succinct proofs of EVM execution.
It uses starky and plonky2 as proving backend: https://github.com/0xPolygonZero/plonky2.

* [proof_gen](./proof_gen/README.md): A convenience library for generating proofs from inputs in Intermediate Representation (IR) format.


## Documentation

Although documentation is still at its early stage and being currently worked on, useful material can
be found in the [docs](./docs/) section, including:

* [sequence diagrams](./docs/usage_seq_diagrams.md) for the proof generation flow
* [zkEVM specifications](./docs/arithmetization/zkevm.pdf), detailing the underlying EVM proving statement


## Building

The zkEVM stack currently requires the `nightly` toolchain, although we may transition to `stable` in the future.
Note that the prover uses the [Jemalloc](http://jemalloc.net/) memory allocator due to its superior performance.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you,
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
