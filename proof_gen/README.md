# Proof generator

Library for generating proofs from proof IR.


# General Usage (Extremely rough, will change)

In [proof_gen.rs](https://github.com/0xPolygonZero/zk_evm/proof-gen/blob/main/src/proof_gen.rs), there are three core functions:

- `generate_txn_proof`
- `generate_agg_proof`
- `generate_block_proof`

Both libraries are currently targeting the latest [plonky2](https://github.com/0xPolygonZero/plonky2). One noteworthy piece of data that all proofs need is this:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHashes {
    pub prev_hashes: Vec<H256>,
    pub cur_hash: H256,
}
```
Note that `prev_hashes` is going to be `256` elements long (!) most of the time. 

`generate_txn_proof` takes in the output from the parser lib (`GenerationInputs`).

`generate_agg_proof` takes in the two child proofs (wrapped in `AggregatableProof`` to support txn or agg proofs).

`generate_block_proof` is a bit less obvious. You give it an agg proof that contains all txns in the entire block, but also pass in an optional previous block proof. The previous block proof is able to be `None` on checkpoint heights.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.


### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
