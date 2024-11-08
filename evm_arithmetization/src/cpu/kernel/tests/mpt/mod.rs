use either::Either;
use ethereum_types::{BigEndianHash, H256, U256};
use mpt_trie::nibbles::Nibbles;
use mpt_trie::partial_trie::HashedPartialTrie;
use mpt_trie::partial_trie::PartialTrie;

use crate::generation::mpt::EitherAccount;
use crate::generation::mpt::MptAccount;
use crate::generation::mpt::{Account, SmtAccount};
use crate::Node;

#[cfg(not(feature = "cdk_erigon"))]
mod delete;
#[cfg(not(feature = "cdk_erigon"))]
mod hash;
mod hex_prefix;
#[cfg(not(feature = "cdk_erigon"))]
mod insert;
pub(crate) mod linked_list;
#[cfg(not(feature = "cdk_erigon"))]
mod load;
#[cfg(not(feature = "cdk_erigon"))]
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

pub(crate) fn test_account_1_empty_storage() -> EitherAccount {
    if cfg!(feature = "cdk_erigon") {
        EitherAccount(Either::Right(SmtAccount {
            nonce: U256::from(1111),
            balance: U256::from(2222),
            code_hash: U256::from(4444),
            code_length: 0.into(),
        }))
    } else {
        EitherAccount(Either::Left(MptAccount {
            nonce: U256::from(1111),
            balance: U256::from(2222),
            storage_root: HashedPartialTrie::from(Node::Empty).hash(),
            code_hash: H256::from_uint(&U256::from(4444)),
        }))
    }
}

#[cfg(not(feature = "cdk_erigon"))]
pub(crate) fn test_account_1() -> MptAccount {
    MptAccount {
        nonce: U256::from(1111),
        balance: U256::from(2222),
        storage_root: H256::from_uint(&U256::from(3333)),
        code_hash: H256::from_uint(&U256::from(4444)),
    }
}

#[cfg(not(feature = "cdk_erigon"))]
pub(crate) fn test_account_1_rlp() -> Vec<u8> {
    test_account_1().rlp_encode().to_vec()
}

pub(crate) fn test_account_1_empty_storage_rlp() -> Vec<u8> {
    test_account_1_empty_storage().rlp_encode().to_vec()
}

#[cfg(not(feature = "cdk_erigon"))]
pub(crate) fn test_account_2() -> MptAccount {
    MptAccount {
        nonce: U256::from(5555),
        balance: U256::from(6666),
        storage_root: H256::from_uint(&U256::from(7777)),
        code_hash: H256::from_uint(&U256::from(8888)),
    }
}

#[cfg(not(feature = "cdk_erigon"))]
pub(crate) fn test_account_2_rlp() -> Vec<u8> {
    test_account_2().rlp_encode().to_vec()
}

/// A `PartialTrie` where an extension node leads to a leaf node containing an
/// account.
pub(crate) fn extension_to_leaf(value: Vec<u8>) -> HashedPartialTrie {
    Node::Extension {
        nibbles: Nibbles {
            count: 61,
            packed: 0xABC_u64.into(),
        },
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
