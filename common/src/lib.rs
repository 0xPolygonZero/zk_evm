use ethereum_types::{H256, U256};

/// The hash value of an account empty EVM code.
/// 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
pub const EMPTY_CODE_HASH: H256 = H256([
    197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202,
    130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112,
]);

/// The hash of an empty Merkle Patricia trie.
/// 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
pub const EMPTY_TRIE_HASH: H256 = H256([
    86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153,
    108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33,
]);

#[macro_export]
/// A convenience macro to check the feature flags activating chain specific
/// behaviors. Only one of these flags may be activated at a time.
macro_rules! check_chain_features {
    () => {
        #[cfg(any(
            all(feature = "cdk_erigon", feature = "polygon_pos"),
            all(feature = "cdk_erigon", feature = "eth_mainnet"),
            all(feature = "polygon_pos", feature = "eth_mainnet"),
            not(any(
                feature = "cdk_erigon",
                feature = "eth_mainnet",
                feature = "polygon_pos"
            ))
        ))]
        compile_error!("One and only one of the feature chains `cdk_erigon`, `polygon_pos` or `eth_mainnet` must be selected");
    };
}

/// Converts an amount in `ETH` to `wei` units.
pub fn eth_to_wei(eth: U256) -> U256 {
    // 1 ether = 10^18 wei.
    eth * U256::from(10).pow(18.into())
}

/// Converts an amount in `gwei` to `wei` units.
/// This also works for converting `ETH` to `gwei`.
pub fn gwei_to_wei(eth: U256) -> U256 {
    // 1 ether = 10^9 gwei = 10^18 wei.
    eth * U256::from(10).pow(9.into())
}

#[test]
fn test_eth_conversion() {
    assert_eq!(
        eth_to_wei(U256::one()),
        gwei_to_wei(gwei_to_wei(U256::one()))
    );
}
#[test]
fn test_empty_code_hash() {
    assert_eq!(EMPTY_CODE_HASH, keccak_hash::keccak([]));
}

#[test]
fn test_empty_trie_hash() {
    assert_eq!(
        EMPTY_TRIE_HASH,
        keccak_hash::keccak(bytes::Bytes::from_static(&rlp::NULL_RLP))
    );
}
