# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

## [0.7.0] - 2024-11-25

### Changed

- Implement first iteration of continuations by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/69
- Fix trace lengths by @hratoanina in https://github.com/0xPolygonZero/zk_evm/pull/110
- Merge clock fix by @hratoanina in https://github.com/0xPolygonZero/zk_evm/pull/114
- Add context pruning by @hratoanina in https://github.com/0xPolygonZero/zk_evm/pull/112
- continuations: initial cleanup pass by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/181
- Generate all segments before proving. by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/135
- Put kernel code in first MemBefore by @hratoanina in https://github.com/0xPolygonZero/zk_evm/pull/178
- continuations: Remove `GenerationInputs` cloning for segment generation by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/186
- Adapt the circuitry to zero-bin by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/184
- Add dummy segment to the left by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/185
- Add segment indexing by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/191
- Introduce verify_all_proofs and update integration tests by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/192
- New context pruning logic by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/170
- Merge with develop by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/195
- Add log for end of jumpdest analysis simulation. by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/201
- continuations: Remove redundant simulation by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/203
- feat(continuations): trim public values at block proof level by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/235
- Merge `develop` into `feat/continuations` by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/250
- Bring back support for multi-txn batches by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/227
- feat(continuations): reduce some memory overhead by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/260
- perf(continuations): Only copy non-stale contexts by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/264
- continuations: Remove the need for dummy segments by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/245
- Merge develop into `feat/continuations` by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/359
- Improve get_descriptor() by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/380
- feat: expand trace decoder tests by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/394
- refactor: use typed tries in trace_decoder by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/393
- Cleanup `KeccakSpongeStark` index accesses by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/418
- Serialize flaky inputs as 'json' files by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/420
- feat: Implement `Columns` view for `MemoryStark` by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/417
- Now warns if file descriptor limit is too small for native mode by @BGluth in https://github.com/0xPolygonZero/zk_evm/pull/411
- chore(deps): bump openssl from 0.10.64 to 0.10.66 by @dependabot in https://github.com/0xPolygonZero/zk_evm/pull/431
- Make `prove_stdio.sh` work on apple chips by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/430
- feat: add conditional feature support in the kernel assembly by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/416
- Reinitialize TO transaction field in `main` by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/440
- Add overflow check in `codecopy`  by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/444
- Check for overflow in `context_id` increment by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/443
- fix: `StorageTrie`, `ReceiptTrie` and `TransactionTrie` shouldn't use `TypedMpt` by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/446
- fix: cleanup alloy dependencies by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/449
- Ensure proper `offset + size` bounds in `wcopy` by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/445
- fix: set min stack length for transient opcodes by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/450
- feat: test native tracer by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/423
- Increase `MAXCODESIZE` for Polygon PoS by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/419
- Fix jump_to by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/453
- Fix Arithmetic trace length by @hratoanina in https://github.com/0xPolygonZero/zk_evm/pull/454
- Linked lists for the state trie by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/402
- Added derives to `pub` types where possible for `mpt_trie` by @BGluth in https://github.com/0xPolygonZero/zk_evm/pull/456
- perf(continuations): Improve initializations and reduce redundant computations by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/429
- feat(continuations): write storage values directly in linked lists by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/433
- Remove self destructs from the native tracer by @4l0n50 in https://github.com/0xPolygonZero/zk_evm/pull/461
- implement version command for all zero bin binaries by @temaniarpit27 in https://github.com/0xPolygonZero/zk_evm/pull/451
- Preinitialize segments in all contexts by @hratoanina in https://github.com/0xPolygonZero/zk_evm/pull/466
- Fix 2-to-1 test for Cancun by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/464
- Process state trie at the end by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/476
- bug(zero-bin): verifier binary not picking up pre-processed circuits by @temaniarpit27 in https://github.com/0xPolygonZero/zk_evm/pull/474
- feat: Implement `Columns` view for `BytePackingStark` by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/422
- chore: flush logs upon success by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/481
- Fix account creation reversion in decoder processing by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/480
- Feat/237 mpt trie ext to branch collapse error by @BGluth in https://github.com/0xPolygonZero/zk_evm/pull/455
- Fix `SELFDESTRUCT` by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/487
- Circuit cache dir now uses os cache dir by @BGluth in https://github.com/0xPolygonZero/zk_evm/pull/405
- refactor: trace_decoder::decoding by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/469
- fix: do not force precompile address access in case of txn reversion by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/488
- chore: reorganize cli params and rename some types by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/485
- Fix txn indexing in error message by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/490
- Revert "Fix `SELFDESTRUCT`" by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/491
- Allow features with macros within macros by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/492
- Check the global variable `GLOBAL_METADATA_TRIE_DATA_SIZE` by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/483
- Update CODEOWNERS to add more folks by @muursh in https://github.com/0xPolygonZero/zk_evm/pull/497
- Do not propagate zero values by @hratoanina in https://github.com/0xPolygonZero/zk_evm/pull/484
- handle case when contract creation was reverted by @temaniarpit27 in https://github.com/0xPolygonZero/zk_evm/pull/482
- refactor: use typed_mpt in the backend by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/494
- chore: add common crate for project wide definitions by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/500
- feat: Remove duplicate `new_txn_trie_node_byte` by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/477
- Fix selfdestruct for EIP-6780 with non-empty balances by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/493
- Fix: `zero-bin` is now able again to accesses `evm_arithmetization` for circuit versions by @BGluth in https://github.com/0xPolygonZero/zk_evm/pull/310
- Add collapse strategy to `PartialTrie` variants by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/501
- refactor: remove dead `client_code_hash_resolve_f` by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/514
- continuations: have segment iterator return a `Result` by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/509
- feat: retrieve prover input per block by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/499
- refactor: Hash2Code by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/522
- Made sub-trie errors better by @BGluth in https://github.com/0xPolygonZero/zk_evm/pull/520
- Feat/continuations by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/171
- add check for checkpoint block number by @temaniarpit27 in https://github.com/0xPolygonZero/zk_evm/pull/517
- feat: add `leader` command to flush cache by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/527
- fix: output block proof to array format by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/536
- Ignore `too_long_first_doc_paragraph` lint by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/545
- Add txn parsing tests by @hratoanina in https://github.com/0xPolygonZero/zk_evm/pull/540
- Check the keys in the state trie correspond to accounts and storage linked lists by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/502
- Reuse txn rlp by @hratoanina in https://github.com/0xPolygonZero/zk_evm/pull/547
- refactor: StateTrie operations are keyed by Address where possible by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/537
- feat: use eth_call with sc to retrieve block hashes by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/519
- feat: extract decoded transaction from the block by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/504
- fix: limit number of connections by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/546
- fix: eth_call for previous block hashes by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/556
- refactor: trait StateTrie by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/542
- Move documentation to Github Pages by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/557
- Remove unnecessary global metadata by @hratoanina in https://github.com/0xPolygonZero/zk_evm/pull/549
- fix: dockerhub access by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/486
- chore: move provider to the common crate by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/567
- refactor: `trace_decoder` input structures by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/558
- Reuse the same RLP blob by @hratoanina in https://github.com/0xPolygonZero/zk_evm/pull/552
- Prune non-necessary values from `PublicValues` prior 2-to-1 aggregation by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/526
- Introduce a burn address for `cdk_erigon` by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/463
- chore: update alloy by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/573
- `trace_decoder`: Tweak batch size for small blocks by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/576
- chore: fix some variable names and comments by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/578
- Reduce overhead in storage reads and fix stack descriptions by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/572
- Fix pairing tests for null accumulated values by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/579
- Expand conditional blocks logic in Kernel parsing by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/574
- feat: follow from block interval by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/582
- Fix `clean` leader's command by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/586
- fix: disable dockerhub login in ci tests by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/588
- chore: Add additional people as code owners for CI related changes by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/589
- fix: Do not write proofs to disk in test only mode by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/592
- chore: cleanup rpc tool parameters by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/595
- refactor: trace decoder tests by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/596
- Mark constant functions with `const` by @julianbraha in https://github.com/0xPolygonZero/zk_evm/pull/571
- chore: remove unused code by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/602
- Bring in Poseidon implementation under `cdk_erigon` feature flag by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/577
- feat: add pre-state execution for `polygon-cdk` by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/594
- feat: Add feature-gating in prover code based on target network by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/598
- optimize: limit number of blocks proving in parallel by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/600
- doc(book): Fill up empty sections and add table diagram by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/608
- Fix github pages deployment by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/616
- Enable withdrawals only for Eth mainnet by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/610
- Clarify `eth_to_gwei` helper name and move to `common` crate by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/619
- chore: move utility functions to common crate by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/615
- refactor: trace decoder backend by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/583
- feat: add consolidated block hashes across checkpoints by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/551
- Skip missing Cancun bits for non Eth mainnet chains by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/605
- Search in linked lists using a BTree by @4l0n50 in https://github.com/0xPolygonZero/zk_evm/pull/603
- Small fixes to `rpc` and `common` modules by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/629
- refactor: one zero package by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/625
- feat(type2): Skip jumpdest analysis by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/631
- refactor: --version in the CLI by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/632
- Refactor linked lists initial hashing by @4l0n50 in https://github.com/0xPolygonZero/zk_evm/pull/581
- Fix address masking in `trace_decoder` processing by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/639
- make pool size configurable by @temaniarpit27 in https://github.com/0xPolygonZero/zk_evm/pull/644
- Check block_timestamp always increases. by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/638
- Remove unnecessary overhead in linked list preprocessing by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/642
- misc: Do not perform sanity check on `test_only` runs by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/635
- Refactor recursive circuit initialization and per table proving and verification with macros by @sai-deng in https://github.com/0xPolygonZero/zk_evm/pull/647
- feat: add network-specific pre-state execution in decoder by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/633
- Hide associated types and remove `types` module in `proof_gen` by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/649
- Remove `proof_gen` crate by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/650
- feat: trie diff tool by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/630
- build: pin toolchain by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/665
- Fix misplaced overflow check in `wcopy` by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/661
- Refactor access list search by @4l0n50 in https://github.com/0xPolygonZero/zk_evm/pull/637
- perf: Remove some binary ops & make KERNEL `init` section free of logic operations by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/658
- refactor: sort, merge, cleanup dependencies by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/677
- fix(ci): use install-action instead of cargo-binstall by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/679
- Refactor proof types and method outputs by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/672
- fix: add timeouts to ci tests by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/687
- misc: print script logs upon failure by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/686
- Fix flaky test when `DEBUG` logging is enabled by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/685
- Add Tests for Segment Proving Without Keccak Tables by @sai-deng in https://github.com/0xPolygonZero/zk_evm/pull/648
- dev: syntax highlighting for EVM Assembly by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/674
- Expand error messages by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/689
- Fix decoder parsing with new storage tries by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/692
- Fix invalid `blob_gas_fee` burn by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/691
- Fix address marking for state reads by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/695
- fix: missing code read in state write by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/699
- feat: trie multi diff comparison by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/655
- Gate Code for Testing Purposes Under testing Modules by @sai-deng in https://github.com/0xPolygonZero/zk_evm/pull/688
- perf: Improve PUSH checking in JDA by @hratoanina in https://github.com/0xPolygonZero/zk_evm/pull/696
- Update the root circuit to conditionally verify Keccak proofs by @sai-deng in https://github.com/0xPolygonZero/zk_evm/pull/652
- Enables optional verification of Keccak tables by @sai-deng in https://github.com/0xPolygonZero/zk_evm/pull/657
- Fix zero_bin test by @sai-deng in https://github.com/0xPolygonZero/zk_evm/pull/708
- Fix contract call reversion  by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/709
- fix: Add jump DDOS protection by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/710
- fix: check for gas limit overflow by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/711
- perf: Inline some hot spots in witness generation by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/715
- perf: reduce `MemBefore` initial size by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/684
- Optimize code by using De Morgan laws by @einar-polygon in https://github.com/0xPolygonZero/zk_evm/pull/670
- fix: reset global metadata fields in memory post txn processing by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/717
- Fix check against 0xEF byte in contract creation. by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/719
- Optimize zkVM Proving by Skipping Unused Keccak Tables by @sai-deng in https://github.com/0xPolygonZero/zk_evm/pull/690
- Assign specific jobs to dedicated workers by @temaniarpit27 in https://github.com/0xPolygonZero/zk_evm/pull/564
- feat: SMT support in `trace_decoder` ignores storage by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/693
- Bump plonky2 (serialization fix) by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/729
- Fix max_cpu_len_log by @sai-deng in https://github.com/0xPolygonZero/zk_evm/pull/714
- feat: Enable more optional tables by @sai-deng in https://github.com/0xPolygonZero/zk_evm/pull/724
- fix: unused MemAfter table by @sai-deng in https://github.com/0xPolygonZero/zk_evm/pull/738
- fix: more robust SMT parsing by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/733
- Move opcode_count Under Test Configuration by @sai-deng in https://github.com/0xPolygonZero/zk_evm/pull/736
- feat: trait World for `trace_decoder` by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/732
- BlockInterval support for hash ranges by @sergerad in https://github.com/0xPolygonZero/zk_evm/pull/728
- chore: update codeowners by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/750
- ci: warn on outdated top level dependencies by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/757
- chore: remove conditional ci execution by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/754
- feat: add yaml linter by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/756
- Replace regex in trie diff main by @sergerad in https://github.com/0xPolygonZero/zk_evm/pull/758
- feat: add ci shellcheck by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/753
- Add faster STARK configuration for testing purposes by @sai-deng in https://github.com/0xPolygonZero/zk_evm/pull/739
- Add test config in zero bin by @sai-deng in https://github.com/0xPolygonZero/zk_evm/pull/742
- ci: update actions/checkout@v3 -> v4 by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/771
- Prune child context in create and call faults by @LindaGuiga in https://github.com/0xPolygonZero/zk_evm/pull/747
- Refactor recursion params by @sai-deng in https://github.com/0xPolygonZero/zk_evm/pull/769
- feat: use abort signal for proving tasks by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/748
- feat: github proving benchmark by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/701
- feat: prove stdio using amqp docker compose setup by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/763
- Fix witness endpoint for cdk by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/773
- Use test config in CI by @sai-deng in https://github.com/0xPolygonZero/zk_evm/pull/770
- Fix bytecode hashing for Type2 SMT by @Nashtare in https://github.com/0xPolygonZero/zk_evm/pull/782
- feat: Add env support to all leader prog args by @BGluth in https://github.com/0xPolygonZero/zk_evm/pull/786
- fix: follow from block interval by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/789
- Replace `ethereum_types` with `alloy::primitives` in `smt_trie` crate by @sergerad in https://github.com/0xPolygonZero/zk_evm/pull/772
- refactor: remove the `compat` crate by @0xaatif in https://github.com/0xPolygonZero/zk_evm/pull/795
- Oxidize prove_rpc.sh by @sergerad in https://github.com/0xPolygonZero/zk_evm/pull/796
- feat: revamp zero prove function by @atanmarko in https://github.com/0xPolygonZero/zk_evm/pull/793

## [0.6.0] - 2024-07-15

### Changed
- Implement EIP-4788 for Cancun ([#40](https://github.com/0xPolygonZero/zk_evm/pull/40))
- Implement Blob transactions (type-3) and BLOBHASH opcode ([#50](https://github.com/0xPolygonZero/zk_evm/pull/50))
- Fix beacons root contract bytecode ([#70](https://github.com/0xPolygonZero/zk_evm/pull/70))
- LxLy exit roots ([#90](https://github.com/0xPolygonZero/zk_evm/pull/90))
- Eip 1153 (TLOAD/TSTORE) ([#59](https://github.com/0xPolygonZero/zk_evm/pull/59))
- Remove blobbasefee from block header ([#100](https://github.com/0xPolygonZero/zk_evm/pull/100))
- Fix MCOPY from rebasing ([#103](https://github.com/0xPolygonZero/zk_evm/pull/103))
- Fix storage write for beacons root contract ([#102](https://github.com/0xPolygonZero/zk_evm/pull/102))
- EIP-4844 part 2: Point evaluation precompile ([#133](https://github.com/0xPolygonZero/zk_evm/pull/133))
- Some fixes to Cancun ([#187](https://github.com/0xPolygonZero/zk_evm/pull/187))
- Insert blob versioned hashes in signature payload for hashing ([#209](https://github.com/0xPolygonZero/zk_evm/pull/209))
- Fix KZG precompile context setup ([#210](https://github.com/0xPolygonZero/zk_evm/pull/210))
- Fix txn type encoding for receipts ([#214](https://github.com/0xPolygonZero/zk_evm/pull/214))
- Add blob gas fee burn for type-3 txns ([#219](https://github.com/0xPolygonZero/zk_evm/pull/219))
- Update decoder processing for cancun ([#207](https://github.com/0xPolygonZero/zk_evm/pull/207))
- cancun: Add a full block test ([#223](https://github.com/0xPolygonZero/zk_evm/pull/223))
- Fix KZG precompile I/O ([#213](https://github.com/0xPolygonZero/zk_evm/pull/213))
- Fix selfdestruct address listing ([#225](https://github.com/0xPolygonZero/zk_evm/pull/225))
- Fix withdrawals without txns and add test for empty block ([#228](https://github.com/0xPolygonZero/zk_evm/pull/228))
- doc: update README ([#242](https://github.com/0xPolygonZero/zk_evm/pull/242))
- Cleanup and bring back deadcode lint ([#232](https://github.com/0xPolygonZero/zk_evm/pull/232))
- fix(cancun): dummy payloads and public input retrieval ([#249](https://github.com/0xPolygonZero/zk_evm/pull/249))
- fix: encode calldata for EIP-4780 as U256 ([#253](https://github.com/0xPolygonZero/zk_evm/pull/253))
- fix: handle KZG precompile errors properly ([#251](https://github.com/0xPolygonZero/zk_evm/pull/251))
- fix(cancun): `mcopy` check offsets and overwrites ([#252](https://github.com/0xPolygonZero/zk_evm/pull/252))
- fix(cancun): correct search loop in transient storage ([#257](https://github.com/0xPolygonZero/zk_evm/pull/257))
- perf: Charge gas before tload search ([#272](https://github.com/0xPolygonZero/zk_evm/pull/272))
- fix: add check on decoded versioned hashes ([#278](https://github.com/0xPolygonZero/zk_evm/pull/278))
- fix: Add beacon roots touched slots into `state_access` with native tracer ([#353](https://github.com/0xPolygonZero/zk_evm/pull/353))
- feat(cancun): update test blocks ([#365](https://github.com/0xPolygonZero/zk_evm/pull/365))
- fix: failed to send proof ([#366](https://github.com/0xPolygonZero/zk_evm/pull/366))
- feat: cancun jerigon test network ([#367](https://github.com/0xPolygonZero/zk_evm/pull/367))
- fix(cancun): properly update accumulator in fake_exponential() ([#376](https://github.com/0xPolygonZero/zk_evm/pull/376))
- fix(cancun): tweak ranges in integration tests ([#377](https://github.com/0xPolygonZero/zk_evm/pull/377))
- `cancun`: cleanup pre-release ([#392](https://github.com/0xPolygonZero/zk_evm/pull/392))

## [0.5.0] - 2024-07-15

### Changed
- fix: docker images ([#108](https://github.com/0xPolygonZero/zk_evm/pull/108))
- feat: add transaction hash to zero trace ([#103](https://github.com/0xPolygonZero/zk_evm/pull/103))
- perf: add benchmarks for different components ([#273](https://github.com/0xPolygonZero/zk_evm/pull/273))
- fix: add check on decoded versioned hashes ([#278](https://github.com/0xPolygonZero/zk_evm/pull/278))
- fix: discard intermediate proofs ([#106](https://github.com/0xPolygonZero/zk_evm/pull/106))
- feat: stdio parallel proving ([#109](https://github.com/0xPolygonZero/zk_evm/pull/109))
- Fixes related to nightly and alloy ([#101](https://github.com/0xPolygonZero/zk_evm/pull/101))
- Introduce native tracer support ([#81](https://github.com/0xPolygonZero/zk_evm/pull/81))
- chore: bump alloy to v0.1.1 ([#111](https://github.com/0xPolygonZero/zk_evm/pull/111))
- Migrate `zero-bin` into `zk-evm`
- fix: Bring back Cargo.lock ([#280](https://github.com/0xPolygonZero/zk_evm/pull/280))
- ci: add labeler flag for new `zero-bin` crate + update `CODEOWNERS` ([#281](https://github.com/0xPolygonZero/zk_evm/pull/281))
- fix: only executables should choose a global allocator ([#301](https://github.com/0xPolygonZero/zk_evm/pull/301))
- doc: fix typos ([#298](https://github.com/0xPolygonZero/zk_evm/pull/298))
- misc: fix logging filename ([#305](https://github.com/0xPolygonZero/zk_evm/pull/305))
- refactor zero_bin leader cli ([#317](https://github.com/0xPolygonZero/zk_evm/pull/317))
- Removed non-existing dep public `__compat_primitive_types` ([#321](https://github.com/0xPolygonZero/zk_evm/pull/321))
- perf: Check for zero amount early in 'add_eth' ([#322](https://github.com/0xPolygonZero/zk_evm/pull/322))
- fix: interval ([#324](https://github.com/0xPolygonZero/zk_evm/pull/324))
- fix: optimize previous hashes retrieval ([#316](https://github.com/0xPolygonZero/zk_evm/pull/316))
- feat: add jerigon test workflow ([#303](https://github.com/0xPolygonZero/zk_evm/pull/303))
- fix: do not add selfdestruct journal entry for empty accounts ([#328](https://github.com/0xPolygonZero/zk_evm/pull/328))
- ci: add PR check job ([#332](https://github.com/0xPolygonZero/zk_evm/pull/332))
- Constrain FP254 operations and SUBMOD to be kernel-only ([#333](https://github.com/0xPolygonZero/zk_evm/pull/333))
- fix: add recipient to touched_addresses even when skipping empty transfer ([#336](https://github.com/0xPolygonZero/zk_evm/pull/336))
- Fixed leader crashing when `.env` not present ([#335](https://github.com/0xPolygonZero/zk_evm/pull/335))
- perf: reduce overhead in final iteration of memset ([#339](https://github.com/0xPolygonZero/zk_evm/pull/339))
- Make leader work no matter what the CWD is ([#307](https://github.com/0xPolygonZero/zk_evm/pull/307))
- Cleanup/clippy and update pass ([#341](https://github.com/0xPolygonZero/zk_evm/pull/341))
- Add `Columns` and `DerefColumns` derive macros ([#315](https://github.com/0xPolygonZero/zk_evm/pull/315))
- migrate compat to micro crate ([#308](https://github.com/0xPolygonZero/zk_evm/pull/308))
- fix: docker build for worker and leader ([#329](https://github.com/0xPolygonZero/zk_evm/pull/329))
- parse embedded short nodes ([#345](https://github.com/0xPolygonZero/zk_evm/pull/345))
- Add `LogicColumnsView` struct for `LogicStark` ([#347](https://github.com/0xPolygonZero/zk_evm/pull/347))
- fix: properly log final result when due ([#352](https://github.com/0xPolygonZero/zk_evm/pull/352))
- fix: Check valid range for s and add test ([#363](https://github.com/0xPolygonZero/zk_evm/pull/363))
- feat: add caching for `get_block` ([#346](https://github.com/0xPolygonZero/zk_evm/pull/346))
- refactor!: docker builds ([#357](https://github.com/0xPolygonZero/zk_evm/pull/357))
- fix: tweak fetching of previous block hashes ([#370](https://github.com/0xPolygonZero/zk_evm/pull/370))
- fix(evm_arithmetization): Adjust layout of `CpuGeneralColumnsView` ([#355](https://github.com/0xPolygonZero/zk_evm/pull/355))
- feat: skip range-checking `PUSH` operations in `KERNEL` mode ([#373](https://github.com/0xPolygonZero/zk_evm/pull/373))
- Fix iterator length when fetching block hashes ([#374](https://github.com/0xPolygonZero/zk_evm/pull/374))
- fix: scale withdrawals amount to gwei ([#371](https://github.com/0xPolygonZero/zk_evm/pull/371))
- refactor: frontend of `trace_decoder` ([#309](https://github.com/0xPolygonZero/zk_evm/pull/309))


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
