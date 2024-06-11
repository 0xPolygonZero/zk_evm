use std::{
    collections::{HashMap, HashSet},
    iter,
};

use anyhow::{bail, Context};
use either::Either;
use evm_arithmetization_type_1::generation::mpt::AccountRlp;
use mpt_trie_type_1::partial_trie::PartialTrie as _;
use nunny::NonEmpty;

use super::execution::{Account, Branch, Code, Extension, Hash, Leaf, Node, Value};
use super::u4::U4;

pub struct Visitor {
    pub path: Vec<U4>,
    pub state: HashMap<Vec<U4>, mpt_trie_type_1::trie_ops::ValOrHash>,
    pub code: HashSet<NonEmpty<Vec<u8>>>,
    // TODO(0xaatif): this should really be a set
    pub storage: HashMap<primitive_types::H256, mpt_trie_type_1::partial_trie::HashedPartialTrie>,
}

impl Visitor {
    pub fn with_path<T>(
        &mut self,
        path: impl IntoIterator<Item = U4>,
        f: impl FnOnce(&mut Self) -> T,
    ) -> T {
        let len = self.path.len();
        self.path.extend(path);
        let ret = f(self);
        self.path.truncate(len);
        ret
    }
    pub fn visit_node(&mut self, it: Node) -> anyhow::Result<()> {
        match it {
            Node::Hash(Hash { raw_hash }) => {
                self.state.insert(
                    self.path.clone(),
                    mpt_trie_type_1::trie_ops::ValOrHash::Hash(raw_hash.into()),
                );
                Ok(())
            }
            Node::Leaf(it) => self.visit_leaf(it),
            Node::Extension(it) => self.visit_extension(it),
            Node::Branch(it) => self.visit_branch(it),
            Node::Code(Code { code }) => {
                self.code.insert(code);
                Ok(())
            }
            Node::Empty => Ok(()),
        }
    }
    pub fn visit_extension(&mut self, Extension { key, child }: Extension) -> anyhow::Result<()> {
        self.with_path(key, |this| this.visit_node(*child))
    }
    pub fn visit_branch(&mut self, Branch { children }: Branch) -> anyhow::Result<()> {
        for (ix, node) in children.into_iter().enumerate() {
            if let Some(node) = node {
                self.with_path(
                    iter::once(U4::new(ix.try_into().unwrap()).unwrap()),
                    |this| this.visit_node(*node),
                )?
            }
        }
        Ok(())
    }
    pub fn visit_leaf(&mut self, Leaf { key, value }: Leaf) -> anyhow::Result<()> {
        let key = self.path.iter().copied().chain(key).collect::<Vec<_>>();
        let value = match value {
            Either::Left(Value { raw_value }) => rlp::encode(raw_value.as_vec()),
            Either::Right(Account {
                nonce,
                balance,
                storage,
                code,
            }) => rlp::encode(&AccountRlp {
                nonce: nonce.into(),
                balance,
                code_hash: match code {
                    Some(Either::Left(Hash { raw_hash })) => raw_hash.into(),
                    Some(Either::Right(Code { code })) => {
                        let hash = crate::utils::hash(&code);
                        self.code.insert(code);
                        hash
                    }
                    None => crate::utils::hash(&[]),
                },
                storage_root: {
                    let storage = node2trie(match storage {
                        Some(it) => *it,
                        None => Node::Empty,
                    })
                    .with_context(|| {
                        format!(
                            "couldn't convert account storage to trie at path {:?}",
                            self.path
                        )
                    })?;
                    let storage_root = storage.hash();
                    self.storage.insert(storage_root, storage);
                    storage_root
                },
            }),
        };
        // TODO(0xaatif): do consistency checks here.
        self.state.insert(
            key,
            mpt_trie_type_1::trie_ops::ValOrHash::Val(value.to_vec()),
        );
        Ok(())
    }
}

pub fn node2trie(node: Node) -> anyhow::Result<mpt_trie_type_1::partial_trie::HashedPartialTrie> {
    let mut trie = mpt_trie_type_1::partial_trie::HashedPartialTrie::default();
    for (key, leaf) in iter_leaves(node) {
        let key = key.into_iter().fold(
            mpt_trie_type_1::nibbles::Nibbles::default(),
            |mut acc, el| {
                acc.push_nibble_back(el as u8);
                acc
            },
        );
        let value = match leaf {
            IterLeaf::Hash(Hash { raw_hash }) => {
                mpt_trie_type_1::trie_ops::ValOrHash::Hash(raw_hash.into())
            }
            IterLeaf::Value(Value { raw_value }) => mpt_trie_type_1::trie_ops::ValOrHash::Val(
                rlp::encode::<Vec<u8>>(raw_value.as_vec()).to_vec(),
            ),
            IterLeaf::Empty => continue,
            IterLeaf::Account(_) => bail!("unexpected Account when building storage trie"),
            IterLeaf::Code(_) => bail!("unexpected Code when building storage trie"),
        };
        trie.insert(key, value)
            .context("couldn't insert into trie")?;
    }
    Ok(trie)
}

pub enum IterLeaf {
    Hash(Hash),
    Value(Value),
    Empty,
    Account(Account),
    Code(Code),
}

/// Visit all the leaves of [`Node`], with paths to each leaf.
#[allow(clippy::type_complexity)]
pub fn iter_leaves(
    node: Node,
) -> Either<iter::Once<(Vec<U4>, IterLeaf)>, Box<dyn Iterator<Item = (Vec<U4>, IterLeaf)>>> {
    match node {
        Node::Hash(it) => Either::Left(iter::once((vec![], IterLeaf::Hash(it)))),
        Node::Leaf(Leaf { key, value }) => match value {
            Either::Left(it) => Either::Left(iter::once((key.into(), IterLeaf::Value(it)))),
            Either::Right(it) => Either::Left(iter::once((key.into(), IterLeaf::Account(it)))),
        },
        Node::Extension(Extension {
            key: parent_key,
            child,
        }) => Either::Right(Box::new(iter_leaves(*child).map(move |(child_key, v)| {
            (parent_key.clone().into_iter().chain(child_key).collect(), v)
        }))),
        Node::Branch(Branch { children }) => Either::Right(Box::new(
            children
                .into_iter()
                .enumerate()
                .flat_map(|(ix, child)| {
                    child.map(|it| (U4::new(ix.try_into().unwrap()).unwrap(), *it))
                })
                .flat_map(|(parent_key, child)| {
                    iter_leaves(child).map(move |(mut child_key, v)| {
                        child_key.insert(0, parent_key);
                        (child_key, v)
                    })
                }),
        )),
        Node::Code(it) => Either::Left(iter::once((vec![], IterLeaf::Code(it)))),
        Node::Empty => Either::Left(iter::once((vec![], IterLeaf::Empty))),
    }
}
