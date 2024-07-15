# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

## [0.5.0] - 2024-07-15

### Changed
- fix: docker images (#108)
- feat: add transaction hash to zero trace (#103)
- perf: add benchmarks for different components (#273)
- fix: add check on decoded versioned hashes (#278)
- fix: discard intermediate proofs (#106)
- feat: stdio parallel proving (#109)
- Fixes related to nightly and alloy (#101)
- Introduce native tracer support (#81)
- chore: bump alloy to v0.1.1 (#111)
- Migrate `zero-bin` into `zk-evm`
- fix: Bring back Cargo.lock (#280)
- ci: add labeler flag for new `zero-bin` crate + update `CODEOWNERS` (#281)
- fix: only executables should choose a global allocator (#301)
- doc: fix typos (#298)
- misc: fix logging filename (#305)
- refactor zero_bin leader cli (#317)
- Removed non-existing dep public `__compat_primitive_types` (#321)
- perf: Check for zero amount early in 'add_eth' (#322)
- fix: interval (#324)
- fix: optimize previous hashes retrieval (#316)
- feat: add jerigon test workflow (#303)
- fix: do not add selfdestruct journal entry for empty accounts (#328)
- ci: add PR check job (#332)
- Constrain FP254 operations and SUBMOD to be kernel-only (#333)
- fix: add recipient to touched_addresses even when skipping empty transfer (#336)
- Fixed leader crashing when `.env` not present (#335)
- perf: reduce overhead in final iteration of memset (#339)
- Make leader work no matter what the CWD is (#307)
- Cleanup/clippy and update pass (#341)
- Add `Columns` and `DerefColumns` derive macros (#315)
- migrate compat to micro crate (#308)
- fix: docker build for worker and leader (#329)
- parse embedded short nodes (#345)
- Add `LogicColumnsView` struct for `LogicStark` (#347)
- fix: properly log final result when due (#352)
- fix: Check valid range for s and add test (#363)
- feat: add caching for `get_block` (#346)
- refactor!: docker builds (#357)
- fix: tweak fetching of previous block hashes (#370)
- fix(evm_arithmetization): Adjust layout of `CpuGeneralColumnsView` (#355)
- feat: skip range-checking `PUSH` operations in `KERNEL` mode (#373)
- Fix iterator length when fetching block hashes (#374)
- fix: scale withdrawals amount to gwei (#371)
- refactor: frontend of `trace_decoder` (#309)


## [0.4.0] - 2024-06-12

### Changed
- Some cleanup ([#190](https://github.com/0xPolygonZero/zk_evm/pull/190))
- Silence jumpdest analysis logs ([#193](https://github.com/0xPolygonZero/zk_evm/pull/193))
- Charge call value gas prior to call ([#199](https://github.com/0xPolygonZero/zk_evm/pull/199))
- refactor: fix todos ([#162](https://github.com/0xPolygonZero/zk_evm/pull/162))
- Remove print call in trace_decoder ([#208](https://github.com/0xPolygonZero/zk_evm/pull/208))
- Update CODEOWNERS ([#224](https://github.com/0xPolygonZero/zk_evm/pull/224))
- Fix access lists pointers check ([#217](https://github.com/0xPolygonZero/zk_evm/pull/217))
- Add a few QoL useability functions to the interface ([#169](https://github.com/0xPolygonZero/zk_evm/pull/169))
- Amortize `sha2` compression loop ([#231](https://github.com/0xPolygonZero/zk_evm/pull/231))
- ci: add cargo audit job ([#236](https://github.com/0xPolygonZero/zk_evm/pull/236))
- fix: Revert interpreter stack display ([#238](https://github.com/0xPolygonZero/zk_evm/pull/238))
- Fix clippy `doc_lazy_continuation` ([#247](https://github.com/0xPolygonZero/zk_evm/pull/247))
- perf: Improve `blake2` precompile ([#239](https://github.com/0xPolygonZero/zk_evm/pull/239))
- fix: rustdoc and tests ([#255](https://github.com/0xPolygonZero/zk_evm/pull/255))
- Native trace processing support ([#246](https://github.com/0xPolygonZero/zk_evm/pull/246))
- Added `Clone` to a few error types in `mpt_trie` ([#259](https://github.com/0xPolygonZero/zk_evm/pull/259))
- cleanup: remove outdated segment ([#262](https://github.com/0xPolygonZero/zk_evm/pull/262))
- fix: add G2 subgroup check for `ECPAIRING` ([#268](https://github.com/0xPolygonZero/zk_evm/pull/268))
- add partial trie builder ([#258](https://github.com/0xPolygonZero/zk_evm/pull/258))

## [0.3.1] - 2024-04-22

### Changed
- Fix withdrawals accesses in state trie ([#176](https://github.com/0xPolygonZero/zk_evm/pull/176))

## [0.3.0] - 2024-04-19

### Changed
- Update plonky2 dependencies ([#119](https://github.com/0xPolygonZero/zk_evm/pull/119))
- Swap out the internal U512 inside nibbles to [u64;5] ([#132](https://github.com/0xPolygonZero/zk_evm/pull/132))
- Charge gas before SLOAD and refactor `insert_accessed_storage_keys` ([#117](https://github.com/0xPolygonZero/zk_evm/pull/117))
- Increased the public interface for `trie_tools` ([#123](https://github.com/0xPolygonZero/zk_evm/pull/123))
- Mpt trie panic refactor  ([#118](https://github.com/0xPolygonZero/zk_evm/pull/118))
- refactor: remove some reallocations from decoder ([#126](https://github.com/0xPolygonZero/zk_evm/pull/126))
- Charge cold access cost in *CALL* before accessing state ([#124](https://github.com/0xPolygonZero/zk_evm/pull/124))
- chore: add debug function for better logging in development ([#134](https://github.com/0xPolygonZero/zk_evm/pull/134))
- Make test_receipt_encoding more meaningful. ([#131](https://github.com/0xPolygonZero/zk_evm/pull/131))
- Add a getter for the KERNEL codehash ([#136](https://github.com/0xPolygonZero/zk_evm/pull/136))
- Remove interpreter-specific preinialization logic from State trait ([#139](https://github.com/0xPolygonZero/zk_evm/pull/139))
- Make some more functions constant ([#154](https://github.com/0xPolygonZero/zk_evm/pull/154))
- fix(keccak-sponge): properly constrain padding bytes ([#158](https://github.com/0xPolygonZero/zk_evm/pull/158))
- Reduce verbosity in logs ([#160](https://github.com/0xPolygonZero/zk_evm/pull/160))
- Bump with latest starky ([#161](https://github.com/0xPolygonZero/zk_evm/pull/161))
- Decouple trace_decoder and proof_gen ([#163](https://github.com/0xPolygonZero/zk_evm/pull/163))
- Extend trace decoder err info ([#148](https://github.com/0xPolygonZero/zk_evm/pull/148))
- Add debug function for better public values logging in development ([#134](https://github.com/0xPolygonZero/zk_evm/pull/134))
- Simplify withdrawals logic ([#168](https://github.com/0xPolygonZero/zk_evm/pull/168))

## [0.2.0] - 2024-03-19

### Changed
- Clean up logging output upon Kernel failure ([#74](https://github.com/0xPolygonZero/zk_evm/pull/74))
- Fix CPU Cycle display in logs during simulations ([#77](https://github.com/0xPolygonZero/zk_evm/pull/77))
- Fix blake2 precompile ([#78](https://github.com/0xPolygonZero/zk_evm/pull/78))
- Create subtries without ever hashing leaves ([#76](https://github.com/0xPolygonZero/zk_evm/pull/76))
- Fix generation inputs logging pre-transaction execution ([#89](https://github.com/0xPolygonZero/zk_evm/pull/89))
- Reduce state trie size for dummy payloads ([#88](https://github.com/0xPolygonZero/zk_evm/pull/88))
- Fix post-txn trie debugging output for multi-logs receipts ([#86](https://github.com/0xPolygonZero/zk_evm/pull/86))
- Fixed *most* failing blocks caused by the merged in aggressive pruning changes ([#97](https://github.com/0xPolygonZero/zk_evm/pull/97))
- Fixed trie hash collision issue when constructing storage tries ([#75](https://github.com/0xPolygonZero/zk_evm/pull/75))
- Fix interpreter rollback by adding the clock to generation state checkpoints ([#109](https://github.com/0xPolygonZero/zk_evm/pull/109))

## [0.1.1] - 2024-03-01

### Changed
- Add verification for invalid jumps ([#36](https://github.com/0xPolygonZero/zk_evm/pull/36))
- Refactor accessed lists as sorted linked lists ([#30](https://github.com/0xPolygonZero/zk_evm/pull/30))
- Change visibility of `compact` mod ([#57](https://github.com/0xPolygonZero/zk_evm/pull/57))
- Fix running doctests in release mode ([#60](https://github.com/0xPolygonZero/zk_evm/pull/60))
- Fix block padding without withdrawals ([#63](https://github.com/0xPolygonZero/zk_evm/pull/63))
- Change position of empty node encoding in RLP segment ([#62](https://github.com/0xPolygonZero/zk_evm/pull/62))
- Unify interpreter and prover witness generation ([#56](https://github.com/0xPolygonZero/zk_evm/pull/56))
- Add utility method for testing CPU execution ([#71](https://github.com/0xPolygonZero/zk_evm/pull/71))
- Expose common types and dummy proof method for testing ([#73](https://github.com/0xPolygonZero/zk_evm/pull/73))

## [0.1.0] - 2024-02-21
* Initial release.
