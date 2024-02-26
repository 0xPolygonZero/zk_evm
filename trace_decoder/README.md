# Trace decoder

A flexible protocol that clients (eg. full nodes) can use to easily generate block proofs for different chains.

## Specification

Temporary [high-level overview](docs/usage_seq_diagrams.md). The specification itself is in the repo [here](trace_decoder/src/trace_protocol.rs).

Because processing the incoming proof protocol payload is not a resource bottleneck, the design is not worrying too much about performance. Instead, the core focus is flexibility in clients creating their own implementation, where the protocol supports multiple ways to provide different pieces of data. For example, there are multiple different formats available to provide the trie pre-images in, and the implementor can choose whichever is closest to its own internal data structures. 

TODO

## Adding more to the specification

We want this to be as easy to write an implementation for as possible! If you are finding that you need to do heavy work on your end to adhere to this spec, it may also be the case that other clients have internal data structures similar to your own and are potentially doing the same work. Since it's probably best to only do the work once, please feel free to create a PR or open an issue to add support to the spec/decoder!

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.


### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
