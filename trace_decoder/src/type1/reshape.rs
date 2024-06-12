use std::{
    collections::{BTreeMap, BTreeSet},
    iter,
};

use anyhow::{bail, Context as _};
use either::Either;
use evm_arithmetization_type_1::generation::mpt::AccountRlp;
use mpt_trie_type_1::{
    partial_trie::{HashedPartialTrie, PartialTrie as _},
    trie_ops::ValOrHash,
};
use nunny::NonEmpty;

use super::execution::{Account, Branch, Code, Execution, Extension, Hash, Leaf, Node, Value};
use super::{nibbles2nibbles, u4::U4};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reshape {
    pub state: HashedPartialTrie,
    pub code: BTreeSet<NonEmpty<Vec<u8>>>,
    pub storage: BTreeMap<primitive_types::H256, HashedPartialTrie>,
}

pub fn reshape(execution: Execution) -> anyhow::Result<Reshape> {
    let mut visitor = Visitor::default();
    visitor.visit_node(match execution {
        Execution::Leaf(it) => Node::Leaf(it),
        Execution::Extension(it) => Node::Extension(it),
        Execution::Branch(it) => Node::Branch(it),
        Execution::Empty => Node::Empty,
    })?;
    let Visitor { path, reshape } = visitor;
    assert_eq!(path, Vec::new());
    Ok(reshape)
}

#[derive(Default)]
struct Visitor {
    path: Vec<U4>,
    reshape: Reshape,
}

impl Visitor {
    fn with_path<T>(
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
    fn visit_node(&mut self, it: Node) -> anyhow::Result<()> {
        match it {
            Node::Hash(Hash { raw_hash }) => {
                insert(
                    &mut self.reshape.state,
                    self.path.clone(),
                    ValOrHash::Hash(raw_hash.into()),
                )
                .context(format!(
                    "couldn't convert save state to trie at path {:?}",
                    self.path
                ))?;
                Ok(())
            }
            Node::Leaf(it) => self.visit_leaf(it),
            Node::Extension(it) => self.visit_extension(it),
            Node::Branch(it) => self.visit_branch(it),
            Node::Code(Code { code }) => {
                self.reshape.code.insert(code);
                Ok(())
            }
            Node::Empty => Ok(()),
        }
    }
    fn visit_extension(&mut self, Extension { key, child }: Extension) -> anyhow::Result<()> {
        self.with_path(key, |this| this.visit_node(*child))
    }
    fn visit_branch(&mut self, Branch { children }: Branch) -> anyhow::Result<()> {
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
    fn visit_leaf(&mut self, Leaf { key, value }: Leaf) -> anyhow::Result<()> {
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
                        self.reshape.code.insert(code);
                        hash
                    }
                    None => crate::utils::hash(&[]),
                },
                storage_root: {
                    let storage = node2trie(match storage {
                        Some(it) => *it,
                        None => Node::Empty,
                    })
                    .context(format!(
                        "couldn't convert account storage to trie at path {:?}",
                        self.path
                    ))?;
                    let storage_root = storage.hash();
                    self.reshape.storage.insert(
                        primitive_types::H256::from_slice(&nibbles2nibbles(key.clone()).bytes_be()),
                        storage,
                    );
                    storage_root
                },
            }),
        };
        // TODO(0xaatif): do consistency checks here.
        insert(&mut self.reshape.state, key, ValOrHash::Val(value.to_vec())).context(format!(
            "couldn't save state to trie at path {:?}",
            self.path
        ))?;
        Ok(())
    }
}

fn insert(trie: &mut HashedPartialTrie, k: Vec<U4>, v: ValOrHash) -> anyhow::Result<()> {
    trie.insert(nibbles2nibbles(k), v)?;
    Ok(())
}

pub fn node2trie(node: Node) -> anyhow::Result<HashedPartialTrie> {
    let mut trie = HashedPartialTrie::default();
    for (k, v) in iter_leaves(node) {
        trie.insert(
            nibbles2nibbles(k),
            match v {
                IterLeaf::Hash(Hash { raw_hash }) => ValOrHash::Hash(raw_hash.into()),
                IterLeaf::Value(Value { raw_value }) => {
                    ValOrHash::Val(rlp::encode(raw_value.as_vec()).to_vec())
                }
                IterLeaf::Empty => continue,
                IterLeaf::Account(_) => bail!("unexpected Account node in storage trie"),
                IterLeaf::Code(_) => bail!("unexpected Code node in storage trie"),
            },
        )?;
    }
    Ok(trie)
}

#[derive(Default)]
struct Node2TrieVisitor {
    path: Vec<U4>,
    trie: HashedPartialTrie,
}

impl Node2TrieVisitor {
    fn with_path<T>(
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
    fn visit_node(&mut self, node: Node) -> anyhow::Result<()> {
        match node {
            Node::Branch(Branch { children }) => {
                for (ix, child) in children.into_iter().enumerate() {
                    if let Some(child) = child {
                        self.with_path(
                            iter::once(U4::new(ix.try_into().unwrap()).unwrap()),
                            |this| this.visit_node(*child),
                        )?;
                    }
                }
                Ok(())
            }
            Node::Code(_) => bail!("unexpected Code when building storage trie"),
            Node::Hash(Hash { raw_hash }) => {
                self.trie.insert(
                    nibbles2nibbles(self.path.clone()),
                    ValOrHash::Hash(raw_hash.into()),
                )?;
                Ok(())
            }
            Node::Leaf(Leaf {
                key,
                value: Either::Left(Value { raw_value }),
            }) => self.with_path(key, |this| {
                this.trie.insert(
                    nibbles2nibbles(this.path.clone()),
                    rlp::encode(raw_value.as_vec()).to_vec(),
                )?;
                Ok(())
            }),
            Node::Leaf(Leaf {
                value: Either::Right(_account),
                ..
            }) => bail!("unexpected Account Leaf when building storage trie"),
            Node::Extension(Extension { key, child }) => {
                self.with_path(key, |this| this.visit_node(*child))
            }
            Node::Empty => Ok(()),
        }
    }
}

enum IterLeaf {
    Hash(Hash),
    Value(Value),
    Empty,
    Account(Account),
    Code(Code),
}

/// Visit all the leaves of [`Node`], with paths to each leaf.
#[allow(clippy::type_complexity)]
fn iter_leaves(
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
