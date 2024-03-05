# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Clean up logging output upon Kernel failure ([#74](https://github.com/0xPolygonZero/zk_evm/pull/74))
- Fix CPU Cycle display in logs during simulations ([#77](https://github.com/0xPolygonZero/zk_evm/pull/77))
- Fix blake2 precompile ([#78](https://github.com/0xPolygonZero/zk_evm/pull/78))

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
