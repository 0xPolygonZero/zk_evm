[![Crate](https://img.shields.io/crates/v/mpt_trie)](https://crates.io/crates/mpt_trie)
[![Docs](https://img.shields.io/docsrs/mpt_trie)](https://docs.rs/mpt_trie/latest/mpt_trie/)
# Ethereum Trie Utils

Currently a WIP and not the most performant.

Types and functions to work with Ethereum partial tries, which are identical to the tries described in the Ethereum yellow paper with the exception that nodes that we do not care about are replaced with `Hash` nodes. A `Hash` node just contains the merkle hash of the node it replaces.

As a concrete example, we may only care about the storage touched by a given txn. If we wanted to generate a `PartialTrie` for this, we would include the minimum number of nodes needed such that all of the storage addresses involved (leaves) are included in the partial trie. Since we may need to include `Branch` nodes, branch children that are not relevant for any of the storage of the txn are replaced with `Hash` nodes.

## License
Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
