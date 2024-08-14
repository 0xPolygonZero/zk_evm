//! Frontend for the witness format emitted by e.g the [`0xPolygonZero/erigon`](https://github.com/0xPolygonZero/erigon)
//! Ethereum node (a.k.a "jerigon").

use std::array;
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, ensure, Context as _};
use either::Either;
use evm_arithmetization::generation::mpt::AccountRlp;
use nunny::NonEmpty;
use u4::U4;

use crate::typed_mpt::{StateTrie, StorageTrie, TrieKey};
use crate::wire::{Instruction, SmtLeaf};

#[derive(Debug, Default, Clone)]
pub struct Frontend {
    pub state: StateTrie,
    pub code: BTreeSet<NonEmpty<Vec<u8>>>,
    /// The key here matches the [`TriePath`] inside [`Self::state`] for
    /// accounts which had inline storage.
    pub storage: BTreeMap<TrieKey, StorageTrie>,
}

pub fn frontend(instructions: impl IntoIterator<Item = Instruction>) -> anyhow::Result<Frontend> {
    let executions = execute(instructions)?;
    ensure!(
        executions.len() == 1,
        "only a single execution is supported"
    );
    let execution = executions.into_vec().remove(0);

    let mut frontend = Frontend::default();
    visit(
        &mut frontend,
        &stackstack::Stack::new(),
        match execution {
            Execution::Leaf(it) => Node::Leaf(it),
            Execution::Extension(it) => Node::Extension(it),
            Execution::Branch(it) => Node::Branch(it),
            Execution::Empty => Node::Empty,
        },
    )?;

    Ok(frontend)
}

fn visit(
    frontend: &mut Frontend,
    path: &stackstack::Stack<'_, U4>,
    node: Node,
) -> anyhow::Result<()> {
    match node {
        Node::Hash(Hash { raw_hash }) => {
            frontend
                .state
                .insert_hash_by_key(TrieKey::new(path.iter().copied())?, raw_hash.into())?;
        }
        Node::Leaf(Leaf { key, value }) => {
            let path = TrieKey::new(path.iter().copied().chain(key))?;
            match value {
                Either::Left(Value { .. }) => bail!("unsupported value node at top level"),
                Either::Right(Account {
                    nonce,
                    balance,
                    storage,
                    code,
                }) => {
                    let account = AccountRlp {
                        nonce: nonce.into(),
                        balance,
                        storage_root: {
                            let storage = node2storagetrie(match storage {
                                Some(it) => *it,
                                None => Node::Empty,
                            })?;
                            let storage_root = storage.root();
                            let clobbered = frontend.storage.insert(path, storage);
                            ensure!(clobbered.is_none(), "duplicate storage");
                            storage_root
                        },
                        code_hash: {
                            match code {
                                Some(Either::Left(Hash { raw_hash })) => raw_hash.into(),
                                Some(Either::Right(Code { code })) => {
                                    let hash = crate::hash(&code);
                                    frontend.code.insert(code);
                                    hash
                                }
                                None => crate::hash([]),
                            }
                        },
                    };
                    let clobbered = frontend.state.insert_by_key(path, account)?;
                    ensure!(clobbered.is_none(), "duplicate account");
                }
            }
        }
        Node::Extension(Extension { key, child }) => {
            path.with_all(key, |path| visit(frontend, path, *child))?
        }
        Node::Branch(Branch { children }) => {
            for (ix, node) in children.into_iter().enumerate() {
                if let Some(node) = node {
                    path.with(
                        U4::new(ix.try_into().expect("ix is in range 0..16"))
                            .expect("ix is in range 0..16"),
                        |path| visit(frontend, path, *node),
                    )?;
                }
            }
        }
        Node::Code(Code { code }) => {
            frontend.code.insert(code);
        }
        Node::Empty => {}
    }
    Ok(())
}

fn node2storagetrie(node: Node) -> anyhow::Result<StorageTrie> {
    fn visit(
        mpt: &mut StorageTrie,
        path: &stackstack::Stack<U4>,
        node: Node,
    ) -> anyhow::Result<()> {
        match node {
            Node::Hash(Hash { raw_hash }) => {
                mpt.insert_hash(TrieKey::new(path.iter().copied())?, raw_hash.into())?;
            }
            Node::Leaf(Leaf { key, value }) => {
                match value {
                    Either::Left(Value { raw_value }) => mpt.insert(
                        TrieKey::new(path.iter().copied().chain(key))?,
                        rlp::encode(&raw_value.as_slice()).to_vec(),
                    )?,
                    Either::Right(_) => bail!("unexpected account node in storage trie"),
                };
            }
            Node::Extension(Extension { key, child }) => {
                path.with_all(key, |path| visit(mpt, path, *child))?
            }
            Node::Branch(Branch { children }) => {
                for (ix, node) in children.into_iter().enumerate() {
                    if let Some(node) = node {
                        path.with(
                            U4::new(ix.try_into().expect("ix is in range 0..16"))
                                .expect("ix is in range 0..16"),
                            |path| visit(mpt, path, *node),
                        )?;
                    }
                }
            }
            Node::Code(_) => bail!("unexpected Code node in storage trie"),
            Node::Empty => {}
        }
        Ok(())
    }

    let mut mpt = StorageTrie::default();
    visit(&mut mpt, &stackstack::Stack::new(), node)?;
    Ok(mpt)
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
    // BUG(spec): these are documented, but never constructed during execution
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

#[test]
fn test_tries() {
    for (ix, case) in serde_json::from_str::<Vec<super::Case>>(include_str!(
        "../tests/data/tries/zero_jerigon.json"
    ))
    .unwrap()
    .into_iter()
    .enumerate()
    {
        println!("case {}", ix);
        let instructions = crate::wire::parse(&case.bytes).unwrap();
        let frontend = frontend(instructions).unwrap();
        assert_eq!(case.expected_state_root, frontend.state.root());

        for (path, acct) in &frontend.state {
            if acct.storage_root != StateTrie::default().root() {
                assert!(frontend.storage.contains_key(&path))
            }
        }
    }
}
