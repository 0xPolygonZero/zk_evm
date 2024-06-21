//! Frontend for the witness format emitted by the [`0xPolygonZero/erigon`](https://github.com/0xPolygonZero/erigon)
//! Ethereum node (a.k.a "jerigon").

use std::{
    array,
    collections::{HashMap, HashSet},
    iter,
};

use anyhow::{bail, ensure, Context as _};
use either::Either;
use mpt_trie::{
    partial_trie::{HashedPartialTrie, PartialTrie as _},
    trie_ops::ValOrHash,
};
use nunny::NonEmpty;
use u4::U4;

use crate::wire::{Instruction, SmtLeaf};

pub struct Frontend {
    pub state: HashedPartialTrie,
    pub code: HashSet<NonEmpty<Vec<u8>>>,
    pub storage: HashMap<ethereum_types::H256, HashedPartialTrie>,
}

pub fn frontend(instructions: impl IntoIterator<Item = Instruction>) -> anyhow::Result<Frontend> {
    let executions = execute(instructions)?;
    ensure!(
        executions.len() == 1,
        "only a single execution is supported"
    );
    let execution = executions.into_vec().remove(0);

    let mut visitor = Visitor {
        path: Vec::new(),
        frontend: Frontend {
            state: HashedPartialTrie::default(),
            code: HashSet::new(),
            storage: HashMap::new(),
        },
    };
    visitor.visit_node(match execution {
        Execution::Leaf(it) => Node::Leaf(it),
        Execution::Extension(it) => Node::Extension(it),
        Execution::Branch(it) => Node::Branch(it),
        Execution::Empty => Node::Empty,
    })?;
    let Visitor { path, frontend } = visitor;

    assert_eq!(Vec::<U4>::new(), path);

    Ok(frontend)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Hash {
    raw_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Value {
    raw_value: NonEmpty<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Account {
    nonce: u64,
    balance: ethereum_types::U256,
    storage: Option<Box<Node>>,
    code: Option<Either<Hash, Code>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Code {
    code: NonEmpty<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Leaf {
    key: NonEmpty<Vec<U4>>,
    value: Either<Value, Account>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Extension {
    key: NonEmpty<Vec<U4>>,
    child: Box<Node>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Branch {
    children: [Option<Box<Node>>; 16],
}

/// An interior execution node
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Node {
    Hash(Hash),
    // BUG: these are documented, but never constructed during execution
    // Value(Value),
    // Account(Account),
    Leaf(Leaf),
    Extension(Extension),
    Branch(Branch),
    Code(Code),
    // BUG: this is undocumented, see [`Instruction::EmptyRoot`]
    Empty,
}

/// A terminal node after [`execute`]-ing
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Execution {
    Leaf(Leaf),
    Extension(Extension),
    Branch(Branch),
    // BUG: this is undocumented, see [`Node::Empty`]
    Empty,
}

/// Execute all instructions in a stack machine, based on [this specification](https://gist.github.com/mandrigin/ff7eccf30d0ef9c572bafcb0ab665cff#the-bytes-layout).
///
/// That spec is why we return multiple [`Execution`]s, even though we only
/// support one.
fn execute(
    instructions: impl IntoIterator<Item = Instruction>,
) -> anyhow::Result<NonEmpty<Vec<Execution>>> {
    let mut witnesses = vec![];
    let mut stack = vec![];

    for instruction in instructions {
        match instruction {
            Instruction::EmptyRoot => stack.push(Node::Empty),
            Instruction::Hash { raw_hash } => stack.push(Node::Hash(Hash { raw_hash })),
            Instruction::Code { raw_code } => stack.push(Node::Code(Code { code: raw_code })),
            Instruction::Leaf { key, value } => stack.push(Node::Leaf(Leaf {
                key,
                value: Either::Left(Value { raw_value: value }),
            })),
            Instruction::Extension { key } => {
                let child = Box::new(stack.pop().context("no Node for Extension")?);
                stack.push(Node::Extension(Extension { key, child }))
            }
            Instruction::AccountLeaf {
                key,
                nonce,
                balance,
                has_code,
                has_storage,
            } => {
                // BUG: the spec sometimes writes Node::Account with 5 fields..
                // TODO(0xaatif): should these fields even be optional?
                let nonce = nonce.unwrap_or_default();
                let balance = balance.unwrap_or_default();
                let account = match (has_code, has_storage) {
                    (true, true) => {
                        let right = stack.pop();
                        let left = stack.pop();
                        match (left, right) {
                            (Some(Node::Hash(hash)), Some(storage)) => Account {
                                nonce,
                                balance,
                                storage: Some(Box::new(storage)),
                                code: Some(Either::Left(hash)),
                            },
                            (Some(Node::Code(code)), Some(storage)) => Account {
                                nonce,
                                balance,
                                storage: Some(Box::new(storage)),
                                code: Some(Either::Right(code)),
                            },
                            other => bail!(
                                "expected (Code | Hash, Node) for AccountLeaf, got {:?}",
                                other
                            ),
                        }
                    }
                    (false, true) => {
                        let storage =
                            Some(Box::new(stack.pop().context("no Node for AccountLeaf")?));
                        Account {
                            nonce,
                            balance,
                            storage,
                            code: None,
                        }
                    }
                    (true, false) => match stack.pop() {
                        Some(Node::Hash(it)) => Account {
                            nonce,
                            balance,
                            storage: None,
                            code: Some(Either::Left(it)),
                        },
                        Some(Node::Code(it)) => Account {
                            nonce,
                            balance,
                            storage: None,
                            code: Some(Either::Right(it)),
                        },
                        other => bail!("expected Code | Hash for AccountLeaf, got {:?}", other),
                    },
                    (false, false) => Account {
                        nonce,
                        balance,
                        storage: None,
                        code: None,
                    },
                };
                stack.push(Node::Leaf(Leaf {
                    key,
                    value: Either::Right(account),
                }))
            }
            Instruction::Branch { mask } => {
                use bitvec::{order::Lsb0, view::BitView as _};
                let mut children = array::from_fn(|_ix| None);
                for (ix, it) in mask.view_bits::<Lsb0>().iter().by_vals().enumerate().rev() {
                    if it {
                        *children.get_mut(ix).context("oob mask bit for Branch")? =
                            Some(Box::new(stack.pop().context("no Node for Branch")?));
                    }
                }
                stack.push(Node::Branch(Branch { children }))
            }
            Instruction::NewTrie => witnesses.push(finish_stack(&mut stack)?),
            Instruction::SmtLeaf(SmtLeaf { .. }) => {
                bail!("unexpected SmtLeaf instruction in type 1 format")
            }
        }
    }
    witnesses.push(finish_stack(&mut stack)?);

    NonEmpty::<Vec<_>>::new(witnesses)
        .ok()
        .context("no instructions to execute")
}

/// Narrow (a) [`Node`] to a subset of its variants, an [`Execution`].
fn finish_stack(v: &mut Vec<Node>) -> anyhow::Result<Execution> {
    match (v.len(), v.pop()) {
        (1, Some(node)) => match node {
            Node::Leaf(it) => Ok(Execution::Leaf(it)),
            Node::Extension(it) => Ok(Execution::Extension(it)),
            Node::Branch(it) => Ok(Execution::Branch(it)),
            Node::Empty => Ok(Execution::Empty),
            other => bail!(
                "expected stack to contain Leaf | Extension | Branch, got {:?}",
                other
            ),
        },
        (n, _) => bail!("expected a stack with a single element, got {}", n),
    }
}

/// Visit a [`Node`], keeping track of the path and decorating the [`Frontend`]
/// as appropriate.
struct Visitor {
    path: Vec<U4>,
    frontend: Frontend,
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
                self.frontend.state.insert(
                    nibbles2nibbles(self.path.clone()),
                    ValOrHash::Hash(raw_hash.into()),
                )?;
                Ok(())
            }
            Node::Leaf(it) => self.visit_leaf(it),
            Node::Extension(it) => self.visit_extension(it),
            Node::Branch(it) => self.visit_branch(it),
            Node::Code(Code { code }) => {
                self.frontend.code.insert(code);
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
            }) => rlp::encode(&evm_arithmetization::generation::mpt::AccountRlp {
                nonce: nonce.into(),
                balance,
                code_hash: match code {
                    Some(Either::Left(Hash { raw_hash })) => raw_hash.into(),
                    Some(Either::Right(Code { code })) => {
                        let hash = crate::hash(&code);
                        self.frontend.code.insert(code);
                        hash
                    }
                    None => crate::hash(&[]),
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
                    self.frontend.storage.insert(
                        ethereum_types::H256::from_slice(&nibbles2nibbles(key.clone()).bytes_be()),
                        storage,
                    );
                    storage_root
                },
            }),
        };
        // TODO(0xaatif): do consistency checks here.
        self.frontend
            .state
            .insert(nibbles2nibbles(key), ValOrHash::Val(value.to_vec()))?;
        Ok(())
    }
}

/// # Panics
/// - internally in [`mpt_trie`].
fn node2trie(node: Node) -> anyhow::Result<HashedPartialTrie> {
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
                IterLeaf::Account => bail!("unexpected Account node in storage trie"),
                IterLeaf::Code => bail!("unexpected Code node in storage trie"),
            },
        )?;
    }
    Ok(trie)
}

/// # Panics
/// - If `ours` is too deep.
fn nibbles2nibbles(ours: Vec<U4>) -> mpt_trie::nibbles::Nibbles {
    let mut theirs = mpt_trie::nibbles::Nibbles::default();
    for it in ours {
        theirs.push_nibble_back(it as u8)
    }
    theirs
}

/// Leaf in a [`Node`] tree, see [`iter_leaves`].
enum IterLeaf {
    Hash(Hash),
    Value(Value),
    Empty,
    // we don't attach information to these variants because they're error cases
    Account,
    Code,
}

/// Simple, inefficient visitor of all leaves of the [`Node`] tree.
#[allow(clippy::type_complexity)]
fn iter_leaves(node: Node) -> Box<dyn Iterator<Item = (Vec<U4>, IterLeaf)>> {
    match node {
        Node::Hash(it) => Box::new(iter::once((vec![], IterLeaf::Hash(it)))),
        Node::Leaf(Leaf { key, value }) => match value {
            Either::Left(it) => Box::new(iter::once((key.into(), IterLeaf::Value(it)))),
            Either::Right(_) => Box::new(iter::once((key.into(), IterLeaf::Account))),
        },
        Node::Extension(Extension {
            key: parent_key,
            child,
        }) => Box::new(iter_leaves(*child).map(move |(child_key, v)| {
            (parent_key.clone().into_iter().chain(child_key).collect(), v)
        })),
        Node::Branch(Branch { children }) => Box::new(
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
        ),
        Node::Code(_) => Box::new(iter::once((vec![], IterLeaf::Code))),
        Node::Empty => Box::new(iter::once((vec![], IterLeaf::Empty))),
    }
}

#[test]
fn test() {
    for (ix, case) in
        serde_json::from_str::<Vec<super::Case>>(include_str!("test_cases/zero_jerigon.json"))
            .unwrap()
            .into_iter()
            .enumerate()
    {
        println!("case {}", ix);
        let instructions = crate::wire::parse(&case.bytes).unwrap();
        let frontend = frontend(instructions).unwrap();
        assert_eq!(case.expected_state_root, frontend.state.hash());
    }
}
