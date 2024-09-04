use std::collections::BTreeMap;

use alloy::{
    consensus::{Account, Eip658Value, Receipt, ReceiptWithBloom},
    primitives::{Address, Bloom, FixedBytes, Log, B256},
};
use alloy_compat::Compat as _;
use evm_arithmetization::proof::{BlockHashes, BlockMetadata};
pub use keccak_hash::keccak as k;
use keccak_hash::H256;
use key::TrieKey;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie as _};
use trace_decoder::{BlockLevelData, OtherBlockData, TxnInfo, TxnMeta, TxnTrace};

pub fn rcpt(success: bool, gas: u128, logs: impl Into<Vec<Log>>) -> ReceiptWithBloom {
    ReceiptWithBloom {
        receipt: Receipt {
            status: Eip658Value::Eip658(success),
            cumulative_gas_used: gas,
            logs: logs.into(),
        },
        logs_bloom: Bloom(FixedBytes::default()),
    }
}

pub fn txn(
    traces: impl Into<BTreeMap<Address, TxnTrace>>,
    byte_code: impl Into<Vec<u8>>,
    receipt: impl Into<ReceiptWithBloom>,
    gas: u64,
) -> TxnInfo {
    TxnInfo {
        traces: traces
            .into()
            .into_iter()
            .map(|(k, v)| (k.compat(), v))
            .collect(),
        meta: TxnMeta {
            byte_code: byte_code.into(),
            new_receipt_trie_node_byte: alloy::rlp::encode(receipt.into()),
            gas_used: gas,
        },
    }
}

pub fn hpt() -> HashedPartialTrie {
    HashedPartialTrie::default()
}

pub fn obd() -> OtherBlockData {
    OtherBlockData {
        b_data: BlockLevelData {
            b_meta: BlockMetadata::default(),
            b_hashes: BlockHashes {
                prev_hashes: Default::default(),
                cur_hash: Default::default(),
            },
            withdrawals: Vec::<(ethereum_types::Address, ethereum_types::U256)>::default(),
        },
        checkpoint_state_trie_root: Default::default(),
    }
}

pub fn acct() -> Account {
    Account {
        storage_root: HashedPartialTrie::default().hash().compat(),
        ..Default::default()
    }
}

pub fn stg(
    full: impl IntoIterator<Item = (H256, Vec<u8>)>,
    deferred: impl IntoIterator<Item = (TrieKey, B256)>,
) -> HashedPartialTrie {
    let mut hpt = hpt();
    for (k, v) in full {
        hpt.insert(TrieKey::from_hash(k).into_nibbles(), v).unwrap()
    }
    for (k, h) in deferred {
        hpt.insert(k.into_nibbles(), h.compat()).unwrap()
    }
    hpt
}

pub fn pos(addr: Address, slot_ix: u64) -> H256 {
    let address_left_padded = alloy::primitives::B256::left_padding_from(&**addr);
    let slot_ix_left_padded = alloy::primitives::U256::from(slot_ix).to_be_bytes::<32>();
    let concat = {
        let mut storage = [0; 64];
        for (ix, byte) in address_left_padded
            .0
            .into_iter()
            .chain(slot_ix_left_padded)
            .enumerate()
        {
            storage[ix] = byte
        }
        storage
    };
    k(concat)
}

/// Store the address next to the hash for reference when e.g debugging tries
macro_rules! characters {
    ($($name:ident = $addr:literal ($hash:literal);)*) => {
        $(
            pub const $name: alloy::primitives::Address = alloy::primitives::address!($addr);
        )*

        mod test_character_hashes {
            use alloy_compat::Compat as _;
            $(
                #[test]
                #[allow(non_snake_case)]
                fn $name() {
                    assert_eq!(keccak_hash::keccak(super::$name).compat(), alloy::primitives::b256!($hash))
                }
            )*
        }
    };
}

// Well known addresses for use in tests
characters! {
    ALICE   = "00000000000000000000000000000000000a11ce" ("98934450b0a9aefe4c16aba331967de160f1b92f655dbf45675997ac0ef2bcf3");
    BOB     = "0000000000000000000000000000000000000b0b" ("3034df95d8f0ea7db7ab950e22fc977fa82ae80174df73ee1c75c24246b96df3");
    CHARLIE = "000000000000000000000000000000000c44271e" ("82c4b3e30ae93f236e06c03afe07f4c69f1aa9d4bac5bb3f4731810828003f97");
    BEACON  = "000f3df6d732807ef1319fb7b8bb8522d0beac02" ("37d65eaa92c6bc4c13a5ec45527f0c18ea8932588728769ec7aecfe6d9f32e42");
}

#[allow(unused)]
pub mod key {
    use copyvec::CopyVec;
    use keccak_hash::H256;
    use u4::{AsNibbles, U4};
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub struct TrieKey(pub CopyVec<U4, 64>);

    impl TrieKey {
        pub const fn new() -> Self {
            Self(CopyVec::new())
        }
        pub fn into_nibbles(self) -> mpt_trie::nibbles::Nibbles {
            let mut theirs = mpt_trie::nibbles::Nibbles::new();
            let Self(ours) = self;
            for nibble in ours {
                theirs.push_nibble_back(nibble as _)
            }
            theirs
        }
        pub(super) fn from_hash(h: H256) -> Self {
            let mut v = CopyVec::new();
            for u4 in AsNibbles(h.0) {
                v.push(u4)
            }
            Self(v)
        }
    }

    impl std::str::FromStr for TrieKey {
        type Err = anyhow::Error;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let mut nibbles = CopyVec::new();
            for char in s.chars() {
                nibbles.try_push(U4::from_str_radix(char.encode_utf8(&mut [0; 4]), 16)?)?
            }
            Ok(Self(nibbles))
        }
    }

    macro_rules! key {
        () => {
            TrieKey::new()
        };
        ($lit:literal) => {{
            const {
                let s = $lit;
                let is_hex = alloy::hex::const_check_raw(s.as_bytes());
                assert!(is_hex, "string must be hex characters only");
                assert!(s.len() <= 64, "too many characters in string");
            };
            $lit.parse::<TrieKey>().unwrap()
        }};
    }
    pub(crate) use key;
}

pub mod repr {
    use std::{collections::BTreeMap, fmt, iter};

    use ::hex::ToHex as _;
    use ethereum_types::{Address, U256};
    use evm_arithmetization::{
        generation::TrieInputs,
        proof::{BlockHashes, BlockMetadata, TrieRoots},
    };
    use keccak_hash::H256;
    use mpt_trie::{
        nibbles::Nibbles,
        partial_trie::{HashedPartialTrie, Node},
    };
    use serde::{Serialize, Serializer};
    use stackstack::Stack;
    use u4::U4;

    #[derive(Serialize, PartialEq)]
    pub struct GenerationInputs {
        #[serde(skip_serializing_if = "is_default")]
        txn_number: U256,
        #[serde(skip_serializing_if = "is_default")]
        gas_before: U256,
        #[serde(skip_serializing_if = "is_default")]
        gas_after: U256,
        #[serde(with = "hex::slice", skip_serializing_if = "is_default")]
        txns: Vec<Vec<u8>>,
        #[serde(skip_serializing_if = "is_default")]
        withdrawals: Vec<(Address, U256)>,
        #[serde(skip_serializing_if = "is_default")]
        exit_roots: Vec<(U256, H256)>,

        #[serde(skip_serializing_if = "is_default")]
        state: Mpt,
        #[serde(skip_serializing_if = "is_default")]
        transaction: Mpt,
        #[serde(skip_serializing_if = "is_default")]
        receipts: Mpt,
        #[serde(skip_serializing_if = "is_default")]
        storage: BTreeMap<H256, Mpt>,

        #[serde(skip_serializing_if = "is_default")]
        checkpoint_root: H256,
        state_root: H256,
        transaction_root: H256,
        receipt_root: H256,

        #[serde(with = "hex::btree_map", skip_serializing_if = "is_default")]
        contract_code: BTreeMap<H256, Vec<u8>>,
        #[serde(skip_serializing_if = "is_default")]
        meta: BlockMetadata,
        #[serde(skip_serializing_if = "hashes_is_empty")]
        hashes: BlockHashes,

        #[serde(skip_serializing_if = "Option::is_none")]
        burn_addr: Option<Address>,
    }

    fn is_default<T: Default + PartialEq>(it: &T) -> bool {
        *it == T::default()
    }
    fn hashes_is_empty(it: &BlockHashes) -> bool {
        *it == BlockHashes {
            prev_hashes: vec![],
            cur_hash: H256::zero(),
        }
    }

    impl From<evm_arithmetization::generation::GenerationInputs> for GenerationInputs {
        fn from(value: evm_arithmetization::generation::GenerationInputs) -> Self {
            let evm_arithmetization::generation::GenerationInputs {
                txn_number_before,
                gas_used_before,
                gas_used_after,
                signed_txns,
                withdrawals,
                global_exit_roots,
                tries:
                    TrieInputs {
                        state_trie,
                        transactions_trie,
                        receipts_trie,
                        storage_tries,
                    },
                trie_roots_after:
                    TrieRoots {
                        state_root,
                        transactions_root,
                        receipts_root,
                    },
                checkpoint_state_trie_root,
                contract_code,
                block_metadata,
                block_hashes,
                burn_addr,
            } = value;
            Self {
                txn_number: txn_number_before,
                gas_before: gas_used_before,
                gas_after: gas_used_after,
                txns: signed_txns,
                withdrawals,
                exit_roots: global_exit_roots,
                state: Mpt::from_hashed_partial_trie(&state_trie),
                transaction: Mpt::from_hashed_partial_trie(&transactions_trie),
                receipts: Mpt::from_hashed_partial_trie(&receipts_trie),
                storage: storage_tries
                    .into_iter()
                    .map(|(k, v)| (k, Mpt::from_hashed_partial_trie(&v)))
                    .collect(),
                state_root,
                transaction_root: transactions_root,
                receipt_root: receipts_root,
                contract_code: contract_code.into_iter().collect(),
                meta: block_metadata,
                hashes: block_hashes,
                checkpoint_root: checkpoint_state_trie_root,
                burn_addr,
            }
        }
    }

    #[derive(Serialize, PartialEq)]
    struct Mpt(BTreeMap<MptPath, MptNode>);

    impl Mpt {
        pub fn from_hashed_partial_trie(hpt: &HashedPartialTrie) -> Self {
            let mut repr = BTreeMap::new();
            visit(Stack::new(), hpt, &mut repr);
            Self(repr)
        }
    }

    impl Default for Mpt {
        fn default() -> Self {
            Self::from_hashed_partial_trie(&HashedPartialTrie::default())
        }
    }

    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    struct MptPath(Vec<U4>);

    impl fmt::Display for MptPath {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let Self(v) = self;
            for u in v {
                f.write_fmt(format_args!("{u:x}"))?
            }
            Ok(())
        }
    }
    impl Serialize for MptPath {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.collect_str(self)
        }
    }

    impl FromIterator<U4> for MptPath {
        fn from_iter<II: IntoIterator<Item = U4>>(iter: II) -> Self {
            Self(iter.into_iter().collect())
        }
    }

    #[derive(PartialEq)]
    enum MptNode {
        Empty,
        Hash(H256),
        Value(Vec<u8>),
    }

    impl fmt::Display for MptNode {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                MptNode::Empty => f.write_str("empty"),
                MptNode::Hash(h) => {
                    f.write_fmt(format_args!("hash:{}", h.as_bytes().encode_hex::<String>()))
                }
                MptNode::Value(v) => {
                    f.write_fmt(format_args!("value:{}", v.encode_hex::<String>()))
                }
            }
        }
    }

    impl Serialize for MptNode {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.collect_str(self)
        }
    }

    fn visit(path: Stack<U4>, hpt: &HashedPartialTrie, repr: &mut BTreeMap<MptPath, MptNode>) {
        let key = path.iter().copied().collect();
        match &**hpt {
            Node::Empty => {
                repr.insert(key, MptNode::Empty);
            }
            Node::Hash(it) => {
                repr.insert(key, MptNode::Hash(*it));
            }
            Node::Branch { children, value } => {
                for (ix, child) in children.iter().enumerate() {
                    visit(path.pushed(U4::new(ix as u8).unwrap()), child, repr)
                }
                if !value.is_empty() {
                    repr.insert(key, MptNode::Value(value.clone()));
                }
            }
            Node::Extension { nibbles, child } => {
                path.with_all(iter_nibbles(*nibbles), |path| visit(*path, child, repr))
            }
            Node::Leaf { nibbles, value } => path.with_all(iter_nibbles(*nibbles), |path| {
                repr.insert(
                    path.iter().copied().collect(),
                    MptNode::Value(value.clone()),
                );
            }),
        }
    }

    fn iter_nibbles(mut nibbles: Nibbles) -> impl Iterator<Item = U4> {
        iter::from_fn(move || match nibbles.count {
            0 => None,
            _ => Some(U4::new(nibbles.pop_next_nibble_back()).unwrap()),
        })
    }

    mod hex {
        pub mod slice {
            pub fn serialize<S: serde::Serializer>(
                it: &[impl hex::ToHex],
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                serializer.collect_seq(it.iter().map(|it| it.encode_hex::<String>()))
            }
        }
        pub mod btree_map {
            use std::collections::BTreeMap;

            use serde::{ser::SerializeMap as _, Serialize};

            pub fn serialize<S: serde::Serializer>(
                it: &BTreeMap<impl Serialize, impl hex::ToHex>,
                serializer: S,
            ) -> Result<S::Ok, S::Error> {
                let mut serializer = serializer.serialize_map(Some(it.len()))?;
                for (k, v) in it {
                    serializer.serialize_entry(k, &v.encode_hex::<String>())?;
                }
                serializer.end()
            }
        }
    }
}
