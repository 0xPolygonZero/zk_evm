# Plonky Edge block trace parser

Library for generating proofs from proof IR.

For the time being, the only library that produces proof IR is currently [plonky-edge-block-trace-parser](https://github.com/mir-protocol/plonky-edge-block-trace-parser). Down the road, the IR will be produced by decoding the proof gen protocol.

# General Usage (Extremely rough, will change)

In [proof_gen.rs](https://github.com/mir-protocol/plonky-block-proof-gen/blob/main/src/proof_gen.rs), there are three core functions:

- `generate_txn_proof`
- `generate_agg_proof`
- `generate_block_proof`

Both libraries are currently targeting the latest [plonky2](https://github.com/mir-protocol/plonky2). One noteworthy piece of data that all proofs need is this:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHashes {
    pub prev_hashes: Vec<H256>,
    pub cur_hash: H256,
}
```
Note that `prev_hashes` is going to be `256` elements long (!) most of the time. 

`generate_txn_proof` takes in the output from the parser lib (`TxnProofGenIR`) along with some constant block data.

`generate_agg_proof` takes in the two child proofs (wrapped in `AggregatableProof`` to support txn or agg proofs) & constant block data.

`generate_block_proof` is a bit less obvious. You give it an agg proof that contains all txns in the entire block, but also pass in an optional previous block proof. The previous block proof is able to be `None` on checkpoint heights.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.


### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
