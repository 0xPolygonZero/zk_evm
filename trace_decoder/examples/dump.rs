use std::io;

use anyhow::Context;
use itertools::Itertools;

#[derive(clap::Parser)]
struct Args {
    #[arg(long)]
    method: Method,
    #[arg(long, default_value_t = 1)]
    batch_size: usize,
    #[arg(long)]
    use_burn_addr: bool,
    #[arg(long)]
    pretty: bool,
    #[arg(long)]
    quiet: bool,
}

#[derive(clap::ValueEnum, Clone)]
enum Method {
    Old,
    New,
}

fn main() -> anyhow::Result<()> {
    let Args {
        method,
        batch_size,
        use_burn_addr,
        pretty,
        quiet,
    } = clap::Parser::parse();

    let entrypoint = match method {
        Method::Old => trace_decoder::entrypoint_old as fn(_, _, _, _) -> anyhow::Result<_>,
        Method::New => trace_decoder::entrypoint_new as _,
    };

    let out = Input::into_iter(serde_path_to_error::deserialize(
        &mut serde_json::Deserializer::from_reader(io::stdin()),
    )?)
    .enumerate()
    .map(
        |(
            ix,
            prover::BlockProverInput {
                block_trace,
                other_data,
            },
        )| {
            entrypoint(block_trace, other_data, batch_size, use_burn_addr)
                .context(format!("couldn't decode input at {ix}"))
        },
    )
    .map_ok(|it| {
        Vec::into_iter(it)
            .map(repr::GenerationInputs::from)
            .collect::<Vec<_>>()
    })
    .collect::<Result<Vec<_>, _>>()?;

    if !quiet {
        let printer = match pretty {
            true => serde_json::to_writer_pretty as fn(_, _) -> _,
            false => serde_json::to_writer as _,
        };

        printer(io::stdout(), &out)?;
    }

    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum Input<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> Input<T> {
    fn into_iter(self) -> impl Iterator<Item = T> {
        match self {
            Input::One(it) => vec![it].into_iter(),
            Input::Many(it) => it.into_iter(),
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

        state: Mpt,
        transaction: Mpt,
        receipts: Mpt,
        storage: BTreeMap<H256, Mpt>,

        checkpoint_root: H256,
        state_root: H256,
        transaction_root: H256,
        receipt_root: H256,

        #[serde(with = "crate::hex::btree_map")]
        contract_code: BTreeMap<H256, Vec<u8>>,
        meta: BlockMetadata,
        hashes: BlockHashes,

        #[serde(skip_serializing_if = "Option::is_none")]
        burn_addr: Option<Address>,
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
