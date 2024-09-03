use std::collections::{BTreeMap, BTreeSet, HashMap};

use alloy::{
    consensus::{Account, Eip658Value, Receipt, ReceiptWithBloom},
    primitives::{address, b256, Address, Bloom, FixedBytes, Log, B256},
};
use alloy_compat::Compat as _;
use evm_arithmetization::proof::{BlockHashes, BlockMetadata};
use keccak_hash::H256;
use key::TrieKey;
use mpt_trie::{
    nibbles::Nibbles,
    partial_trie::{HashedPartialTrie, PartialTrie as _},
};
use trace_decoder::{
    BlockLevelData, BlockTrace, BlockTraceTriePreImages, OtherBlockData,
    SeparateStorageTriesPreImage, SeparateTriePreImage, SeparateTriePreImages, TxnInfo, TxnMeta,
    TxnTrace,
};

const ALICE: Address = address!("00000000000000000000000000000000000a11ce");
const BOB: Address = address!("0000000000000000000000000000000000000b0b");
const CHARLIE: Address = address!("000000000000000000000000000000000c44271e");
const BEACON: Address = address!("000f3df6d732807ef1319fb7b8bb8522d0beac02");

#[test]
fn character_hashes() {
    t(
        ALICE,
        b256!("98934450b0a9aefe4c16aba331967de160f1b92f655dbf45675997ac0ef2bcf3"),
    );
    t(
        BOB,
        b256!("3034df95d8f0ea7db7ab950e22fc977fa82ae80174df73ee1c75c24246b96df3"),
    );
    t(
        CHARLIE,
        b256!("82c4b3e30ae93f236e06c03afe07f4c69f1aa9d4bac5bb3f4731810828003f97"),
    );
    t(
        BEACON,
        b256!("37d65eaa92c6bc4c13a5ec45527f0c18ea8932588728769ec7aecfe6d9f32e42"),
    );

    #[track_caller]
    fn t(address: Address, expected: B256) {
        assert_eq!(keccak_hash::keccak(address).compat(), expected)
    }
}

#[test]
fn empty2() {
    do_test(
        [(BEACON, acct()), (ALICE, acct())],
        [],
        [(BEACON, hpt())],
        [],
        [
            txn([], [], rcpt(true, 0, []), 0),
            txn([], [], rcpt(true, 0, []), 0),
        ],
        obd(),
    )
}
#[test]
fn pad1() {
    do_test(
        [(BEACON, acct()), (ALICE, acct())],
        [],
        [(BEACON, hpt())],
        [],
        [txn([], [], rcpt(true, 0, []), 0)],
        obd(),
    )
}

#[test]
#[ignore]
fn pad2() {
    do_test([(BEACON, acct())], [], [(BEACON, hpt())], [], [], obd());
}

fn rcpt(success: bool, gas: u128, logs: impl Into<Vec<Log>>) -> ReceiptWithBloom {
    ReceiptWithBloom {
        receipt: Receipt {
            status: Eip658Value::Eip658(success),
            cumulative_gas_used: gas,
            logs: logs.into(),
        },
        logs_bloom: Bloom(FixedBytes::default()),
    }
}

fn txn(
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

fn hpt() -> HashedPartialTrie {
    HashedPartialTrie::default()
}

fn obd() -> OtherBlockData {
    OtherBlockData {
        b_data: BlockLevelData {
            b_meta: BlockMetadata::default(),
            b_hashes: BlockHashes {
                prev_hashes: Vec::<H256>::default(),
                cur_hash: H256::default(),
            },
            withdrawals: Vec::<(ethereum_types::Address, ethereum_types::U256)>::default(),
        },
        checkpoint_state_trie_root: H256::default(),
    }
}

fn acct() -> Account {
    Account {
        storage_root: HashedPartialTrie::default().hash().compat(),
        ..Default::default()
    }
}

fn do_test(
    state: impl Into<BTreeMap<Address, Account>>,
    deferred_state: impl Into<BTreeMap<TrieKey, B256>>,
    storage: impl Into<HashMap<Address, HashedPartialTrie>>,
    code_db: impl Into<BTreeSet<Vec<u8>>>,
    txn_info: impl Into<Vec<TxnInfo>>,
    obd: impl Into<OtherBlockData>,
) {
    let obd = obd.into();
    let bt = BlockTrace {
        trie_pre_images: BlockTraceTriePreImages::Separate(SeparateTriePreImages {
            state: SeparateTriePreImage::Direct({
                let mut hpt = HashedPartialTrie::default();
                for (k, v) in state.into() {
                    hpt.insert(
                        Nibbles::from_h256_be(keccak_hash::keccak(k)),
                        alloy::rlp::encode(v),
                    )
                    .unwrap()
                }
                for (k, h) in deferred_state.into() {
                    hpt.insert(k.into_nibbles(), h.compat()).unwrap()
                }
                hpt
            }),
            storage: SeparateStorageTriesPreImage::MultipleTries(
                storage
                    .into()
                    .into_iter()
                    .map(|(k, v)| (keccak_hash::keccak(k), SeparateTriePreImage::Direct(v)))
                    .collect(),
            ),
        }),
        code_db: code_db.into(),
        txn_info: txn_info.into(),
    };

    eprintln!("generate reference...");
    let mut reference = trace_decoder::entrypoint_old(bt.clone(), obd.clone(), 1, false)
        .expect("couldn't generate reference");
    eprintln!("generate subject...");
    let subject =
        trace_decoder::entrypoint_new(bt, obd, 1, false).expect("couldn't generate subject");

    for gi in &mut reference {
        gi.contract_code.insert(keccak_hash::keccak([]), vec![]);
    }

    pretty_assertions::assert_str_eq!(
        str_repr(reference),
        str_repr(subject),
        "reference (left) != (right) subject"
    );

    #[track_caller]
    fn str_repr(src: Vec<evm_arithmetization::GenerationInputs>) -> String {
        serde_json::to_string_pretty(
            &src.into_iter()
                .map(repr::GenerationInputs::from)
                .collect::<Vec<_>>(),
        )
        .expect("unable to serialize")
    }
}

mod key {
    use copyvec::CopyVec;
    use u4::U4;
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub struct TrieKey(CopyVec<U4, 64>);

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

    const fn assert_trie_key(s: &str) {
        let is_hex = alloy::hex::const_check_raw(s.as_bytes());
        assert!(is_hex, "string must be hex characters only");
        assert!(s.len() <= 64, "too many characters in string");
    }

    macro_rules! key {
        () => {
            TrieKey::new()
        };
        ($lit:literal) => {{
            const { assert_trie_key($lit) };
            $lit.parse::<TrieKey>().unwrap()
        }};
    }
    pub(crate) use key;
}

mod repr {
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
