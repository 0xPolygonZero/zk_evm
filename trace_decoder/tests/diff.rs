use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::File,
    path::{Path, PathBuf},
};

use alloy::rpc::types::Header;
use anyhow::{ensure, Context as _};
use camino::Utf8Path;
use clap::Parser;
use ethereum_types::{Address, U256};
use evm_arithmetization::{
    generation::mpt::AccountRlp,
    proof::{BlockHashes, BlockMetadata},
};
use itertools::Itertools;
use keccak_hash::H256;
use mpt_trie::partial_trie::HashedPartialTrie;
use prover::BlockProverInput;
use serde::de::DeserializeOwned;
use trace_decoder::{
    BlockLevelData, BlockTrace, BlockTraceTriePreImages, OtherBlockData,
    SeparateStorageTriesPreImage, SeparateTriePreImage, SeparateTriePreImages, TxnInfo,
};
use u4::U4;

#[derive(Parser)]
struct Args {
    /// If omitted, a default set of vectors be loaded from the codebase.
    block_prover_input: Vec<PathBuf>,
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

mod repr {
    use std::{collections::BTreeMap, fmt, iter};

    use ethereum_types::{Address, U256};
    use evm_arithmetization::{
        generation::TrieInputs,
        proof::{BlockHashes, BlockMetadata, TrieRoots},
    };
    use hex::ToHex as _;
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
        txn_number: U256,
        gas_before: U256,
        gas_after: U256,
        #[serde(with = "crate::hex::slice")]
        txns: Vec<Vec<u8>>,
        withdrawals: Vec<(Address, U256)>,
        exit_roots: Vec<(U256, H256)>,

        state: ReprTrie,
        transaction: ReprTrie,
        receipts: ReprTrie,
        storage: BTreeMap<H256, ReprTrie>,

        checkpoint_root: H256,
        state_root: H256,
        transaction_root: H256,
        receipt_root: H256,

        #[serde(with = "crate::hex::btree_map")]
        contract_code: BTreeMap<H256, Vec<u8>>,
        meta: BlockMetadata,
        hashes: BlockHashes,
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
            } = value;
            Self {
                txn_number: txn_number_before,
                gas_before: gas_used_before,
                gas_after: gas_used_after,
                txns: signed_txns,
                withdrawals,
                exit_roots: global_exit_roots,
                state: ReprTrie::from_hashed_partial_trie(&state_trie),
                transaction: ReprTrie::from_hashed_partial_trie(&transactions_trie),
                receipts: ReprTrie::from_hashed_partial_trie(&receipts_trie),
                storage: storage_tries
                    .into_iter()
                    .map(|(k, v)| (k, ReprTrie::from_hashed_partial_trie(&v)))
                    .collect(),
                state_root,
                transaction_root: transactions_root,
                receipt_root: receipts_root,
                contract_code: contract_code.into_iter().collect(),
                meta: block_metadata,
                hashes: block_hashes,
                checkpoint_root: checkpoint_state_trie_root,
            }
        }
    }

    #[derive(Serialize, PartialEq)]
    struct ReprTrie(BTreeMap<ReprPath, ReprNode>);

    impl ReprTrie {
        pub fn from_hashed_partial_trie(hpt: &HashedPartialTrie) -> Self {
            let mut repr = BTreeMap::new();
            visit(Stack::new(), hpt, &mut repr);
            Self(repr)
        }
    }

    #[derive(PartialEq, Eq, PartialOrd, Ord)]
    struct ReprPath(Vec<U4>);

    impl fmt::Display for ReprPath {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let Self(v) = self;
            for u in v {
                f.write_fmt(format_args!("{u:x}"))?
            }
            Ok(())
        }
    }
    impl Serialize for ReprPath {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.collect_str(self)
        }
    }

    impl FromIterator<U4> for ReprPath {
        fn from_iter<II: IntoIterator<Item = U4>>(iter: II) -> Self {
            Self(iter.into_iter().collect())
        }
    }

    #[derive(PartialEq)]
    enum ReprNode {
        Empty,
        Hash(H256),
        Value(Vec<u8>),
    }

    impl fmt::Display for ReprNode {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                ReprNode::Empty => f.write_str("empty"),
                ReprNode::Hash(h) => {
                    f.write_fmt(format_args!("hash:{}", h.as_bytes().encode_hex::<String>()))
                }
                ReprNode::Value(v) => {
                    f.write_fmt(format_args!("value:{}", v.encode_hex::<String>()))
                }
            }
        }
    }

    impl Serialize for ReprNode {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.collect_str(self)
        }
    }

    fn visit(path: Stack<U4>, hpt: &HashedPartialTrie, repr: &mut BTreeMap<ReprPath, ReprNode>) {
        let key = path.iter().copied().collect();
        match &**hpt {
            Node::Empty => {
                repr.insert(key, ReprNode::Empty);
            }
            Node::Hash(it) => {
                repr.insert(key, ReprNode::Hash(*it));
            }
            Node::Branch { children, value } => {
                for (ix, child) in children.iter().enumerate() {
                    visit(path.pushed(U4::new(ix as u8).unwrap()), child, repr)
                }
                if !value.is_empty() {
                    repr.insert(key, ReprNode::Value(value.clone()));
                }
            }
            Node::Extension { nibbles, child } => {
                path.with_all(iter_nibbles(*nibbles), |path| visit(*path, child, repr))
            }
            Node::Leaf { nibbles, value } => path.with_all(iter_nibbles(*nibbles), |path| {
                repr.insert(
                    path.iter().copied().collect(),
                    ReprNode::Value(value.clone()),
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
}

fn do_test(trace: BlockTrace, other: OtherBlockData) {
    let reference = stringify(
        trace_decoder::entrypoint(trace.clone(), other.clone(), 1)
            .expect("couldn't generate reference"),
    );
    let subject = stringify(
        trace_decoder::entrypoint2(trace, other, non0::nonzero!(1))
            .expect("couldn't generate subject"),
    );

    pretty_assertions::assert_str_eq!(reference, subject);

    #[track_caller]
    fn stringify(src: Vec<evm_arithmetization::GenerationInputs>) -> String {
        serde_json::to_string_pretty(
            &src.into_iter()
                .map(repr::GenerationInputs::from)
                .collect::<Vec<_>>(),
        )
        .expect("unable to serialize")
    }
}

#[test]
fn test() {
    do_test(trace(), other());
}

fn state(
    full: impl Into<BTreeMap<Address, AccountRlp>>,
    deferred: impl Into<BTreeMap<Vec<U4>, H256>>,
) -> HashedPartialTrie {
    todo!()
}

fn storage(
    owner: Address,
    full: impl Into<BTreeMap<H256, Vec<u8>>>,
    deferred: impl Into<BTreeMap<Vec<U4>, H256>>,
) -> HashedPartialTrie {
    todo!()
}

fn trace(
    state: impl Into<HashedPartialTrie>,
    storage: impl Into<HashMap<H256, HashedPartialTrie>>,
    code_db: impl Into<BTreeSet<Vec<u8>>>,
    txn_info: impl Into<Vec<TxnInfo>>,
) -> BlockTrace {
    BlockTrace {
        trie_pre_images: BlockTraceTriePreImages::Separate(SeparateTriePreImages {
            state: SeparateTriePreImage::Direct(state.into()),
            storage: SeparateStorageTriesPreImage::MultipleTries(
                Into::<HashMap<H256, HashedPartialTrie>>::into(storage)
                    .into_iter()
                    .map(|(k, v)| (k, SeparateTriePreImage::Direct(v)))
                    .collect(),
            ),
        }),
        code_db: code_db.into(),
        txn_info: txn_info.into(),
    }
}
fn other() -> OtherBlockData {
    OtherBlockData {
        b_data: BlockLevelData {
            b_meta: BlockMetadata::default(),
            b_hashes: BlockHashes {
                prev_hashes: Vec::<H256>::default(),
                cur_hash: H256::default(),
            },
            withdrawals: Vec::<(Address, U256)>::default(),
        },
        checkpoint_state_trie_root: H256::default(),
    }
}

fn default_bpis() -> anyhow::Result<Vec<(String, BlockProverInput)>> {
    glob::glob(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/witnesses/zero_jerigon/*_header.json"
    ))
    .expect("valid glob pattern")
    .map(|res| {
        let header_path = res.context("filesystem error discovering test vectors")?;
        FilePair::load(&header_path).context(format!(
            "couldn't load case for header {}",
            header_path.display()
        ))
    })
    .map_ok(|FilePair { name, cases }| {
        cases
            .into_iter()
            .enumerate()
            .map(move |(ix, (_header, bpi))| (format!("{name}[{ix}]"), bpi))
    })
    .flatten_ok()
    .collect()
}

/// Test cases come in pairs of files, `foo_header.json` and `foo.json`.
struct FilePair {
    /// `foo`, in the above example.
    pub name: String,
    pub cases: Vec<(Header, BlockProverInput)>,
}

impl FilePair {
    /// `header_path` MUST end in `_header.json`
    fn load(header_path: &Path) -> anyhow::Result<Self> {
        let header_path = Utf8Path::from_path(header_path).context("non-UTF-8 path")?;
        let base = Utf8Path::new(
            header_path
                .as_str()
                .strip_suffix("_header.json")
                .context("bad header name")?,
        );
        let headers = json::<Vec<Header>>(header_path)?;
        let bodies = json::<Vec<BlockProverInput>>(base.with_extension("json"))?;
        ensure!(headers.len() == bodies.len(), "inconsistent file pair");
        anyhow::Ok(FilePair {
            name: base.file_name().context("inconsistent base name")?.into(),
            cases: headers.into_iter().zip(bodies).collect(),
        })
    }
}

fn json<T: DeserializeOwned>(path: impl AsRef<Path>) -> anyhow::Result<T> {
    fn _imp<T: DeserializeOwned>(path: impl AsRef<Path>) -> anyhow::Result<T> {
        let file = File::open(path)?;
        Ok(serde_path_to_error::deserialize(
            &mut serde_json::Deserializer::from_reader(file),
        )?)
    }

    _imp(&path).context(format!("couldn't load {}", path.as_ref().display()))
}
