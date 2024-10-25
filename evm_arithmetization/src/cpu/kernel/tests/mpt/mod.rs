use ethereum_types::{BigEndianHash, H256, U256};
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::HashedPartialTrie;
use mpt_trie::partial_trie::PartialTrie;

use crate::generation::mpt::AccountRlp;
use crate::Node;

#[cfg(feature = "eth_mainnet")]
mod delete;
#[cfg(feature = "eth_mainnet")]
mod hash;
mod hex_prefix;
#[cfg(feature = "eth_mainnet")]
mod insert;
pub(crate) mod linked_list;
#[cfg(feature = "eth_mainnet")]
mod load;
#[cfg(feature = "eth_mainnet")]
mod read;

pub(crate) fn nibbles_64<T: Into<U256>>(v: T) -> Nibbles {
    let packed: U256 = v.into();
    Nibbles {
        count: 64,
        packed: packed.into(),
    }
}

pub(crate) fn nibbles_count<T: Into<U256>>(v: T, count: usize) -> Nibbles {
    let packed: U256 = v.into();
    Nibbles {
        count,
        packed: packed.into(),
    }
}

#[cfg(feature = "eth_mainnet")]
pub(crate) fn test_account_1() -> AccountRlp {
    AccountRlp {
        nonce: U256::from(1111),
        balance: U256::from(2222),
        storage_root: H256::from_uint(&U256::from(3333)),
        code_hash: H256::from_uint(&U256::from(4444)),
    }
}

#[cfg(feature = "eth_mainnet")]
pub(crate) fn test_account_1_empty_storage() -> AccountRlp {
    AccountRlp {
        nonce: U256::from(1111),
        balance: U256::from(2222),
        storage_root: HashedPartialTrie::from(Node::Empty).hash(),
        code_hash: H256::from_uint(&U256::from(4444)),
    }
}

#[cfg(feature = "cdk_erigon")]
pub(crate) fn test_account_1() -> AccountRlp {
    AccountRlp {
        nonce: U256::from(1111),
        balance: U256::from(2222),
        code_hash: U256::from(4444),
        code_length: 0.into(),
    }
}

#[cfg(feature = "cdk_erigon")]
pub(crate) fn test_account_1_empty_storage() -> AccountRlp {
    AccountRlp {
        nonce: U256::from(1111),
        balance: U256::from(2222),
        code_hash: U256::from(4444),
        code_length: 0.into(),
    }
}

pub(crate) fn test_account_1_rlp() -> Vec<u8> {
    rlp::encode(&test_account_1()).to_vec()
}

pub(crate) fn test_account_1_empty_storage_rlp() -> Vec<u8> {
    rlp::encode(&test_account_1_empty_storage()).to_vec()
}

#[cfg(feature = "eth_mainnet")]
pub(crate) fn test_account_2() -> AccountRlp {
    AccountRlp {
        nonce: U256::from(5555),
        balance: U256::from(6666),
        storage_root: H256::from_uint(&U256::from(7777)),
        code_hash: H256::from_uint(&U256::from(8888)),
    }
}

#[cfg(feature = "cdk_erigon")]
pub(crate) fn test_account_2() -> AccountRlp {
    AccountRlp {
        nonce: U256::from(5555),
        balance: U256::from(6666),
        code_hash: U256::from(8888),
        code_length: 0.into(),
    }
}

pub(crate) fn test_account_2_rlp() -> Vec<u8> {
    rlp::encode(&test_account_2()).to_vec()
}

/// A `PartialTrie` where an extension node leads to a leaf node containing an
/// account.
pub(crate) fn extension_to_leaf(value: Vec<u8>) -> HashedPartialTrie {
    Node::Extension {
        nibbles: 0xABC_u64.into(),
        child: Node::Leaf {
            nibbles: Nibbles {
                count: 3,
                packed: 0xDEF.into(),
            },
            value,
        }
        .into(),
    }
    .into()
}
