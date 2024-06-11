use std::array;

use anyhow::{bail, Context as _};
use either::Either;
use ethereum_types::U256;
use nunny::NonEmpty;

use super::{u4::U4, wire::Instruction};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash {
    pub raw_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Value {
    pub raw_value: NonEmpty<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Account {
    pub nonce: u64,
    pub balance: U256,
    pub storage: Option<Box<Node>>,
    pub code: Option<Either<Hash, Code>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Code {
    pub code: NonEmpty<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Leaf {
    pub key: NonEmpty<Vec<U4>>,
    pub value: Either<Value, Account>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Extension {
    pub key: NonEmpty<Vec<U4>>,
    pub child: Box<Node>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Branch {
    pub children: [Option<Box<Node>>; 16],
}

/// An interior execution node
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Node {
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
pub enum Execution {
    Leaf(Leaf),
    Extension(Extension),
    Branch(Branch),
    // BUG: this is undocumented, see [`Node::Empty`]
    Empty,
}

/// Stack machine
pub fn execute(
    instructions: impl IntoIterator<Item = Instruction>,
) -> anyhow::Result<NonEmpty<Vec<Execution>>> {
    let mut instructions = instructions
        .into_iter()
        .collect::<std::collections::VecDeque<_>>();
    let mut witnesses = vec![];
    let mut stack = vec![];

    while let Some(instruction) = instructions.pop_front() {
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
                    (true, true) => match pop2(&mut stack) {
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
                    },
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
        }
        println!(
            "stack: {:?}",
            stack.iter().cloned().map(node2node).collect::<Vec<_>>()
        );
        println!(
            "instructions: {:?}",
            instructions
                .iter()
                .cloned()
                .map(instruction2instruction)
                .collect::<Vec<_>>()
        );
    }
    witnesses.push(finish_stack(&mut stack)?);

    NonEmpty::<Vec<_>>::new(witnesses)
        .ok()
        .context("no instructions")
}

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

/// Makes it easier to write code that looks like the spec
fn pop2<T>(v: &mut Vec<T>) -> (Option<T>, Option<T>) {
    let right = v.pop();
    let left = v.pop();
    (left, right)
}

fn instruction2instruction(
    ours: Instruction,
) -> crate::compact::compact_prestate_processing::Instruction {
    use crate::compact::compact_prestate_processing::Instruction as Theirs;
    match ours {
        Instruction::Leaf { key, value } => Theirs::Leaf(nibbles2nibbles(key.into()), value.into()),
        Instruction::Extension { key } => Theirs::Extension(nibbles2nibbles(key.into())),
        Instruction::Branch { mask } => Theirs::Branch(mask.try_into().unwrap()),
        Instruction::Hash { raw_hash } => Theirs::Hash(raw_hash.into()),
        Instruction::Code { raw_code } => Theirs::Code(raw_code.into()),
        Instruction::AccountLeaf {
            key,
            nonce,
            balance,
            has_code,
            has_storage,
        } => Theirs::AccountLeaf(
            nibbles2nibbles(key.into()),
            nonce.unwrap_or_default().into(),
            balance.unwrap_or_default(),
            has_code,
            has_storage,
        ),
        Instruction::EmptyRoot => Theirs::EmptyRoot,
        Instruction::NewTrie => todo!(),
    }
}

fn nibbles2nibbles(ours: Vec<U4>) -> mpt_trie_type_1::nibbles::Nibbles {
    ours.into_iter().fold(
        mpt_trie_type_1::nibbles::Nibbles::default(),
        |mut acc, el| {
            acc.push_nibble_front(el as u8);
            acc
        },
    )
}

fn node2node(ours: Node) -> crate::compact::compact_prestate_processing::NodeEntry {
    use crate::compact::compact_prestate_processing::{
        AccountNodeCode, AccountNodeData, LeafNodeData, NodeEntry as Theirs, ValueNodeData,
    };
    match ours {
        Node::Hash(Hash { raw_hash }) => Theirs::Hash(raw_hash.into()),
        Node::Leaf(Leaf { key, value }) => Theirs::Leaf(
            nibbles2nibbles(key.into()),
            match value {
                Either::Left(Value { raw_value }) => {
                    LeafNodeData::Value(ValueNodeData(raw_value.into()))
                }
                Either::Right(Account {
                    nonce,
                    balance,
                    storage,
                    code,
                }) => LeafNodeData::Account(AccountNodeData {
                    nonce: nonce.into(),
                    balance,
                    storage_trie: storage.map(|it| super::reshape::node2trie(*it).unwrap()),
                    account_node_code: code.map(|it| match it {
                        Either::Left(Hash { raw_hash }) => {
                            AccountNodeCode::HashNode(raw_hash.into())
                        }
                        Either::Right(Code { code }) => AccountNodeCode::CodeNode(code.into()),
                    }),
                }),
            },
        ),
        Node::Extension(Extension { key, child }) => {
            Theirs::Extension(nibbles2nibbles(key.into()), Box::new(node2node(*child)))
        }
        Node::Branch(Branch { children }) => {
            Theirs::Branch(children.map(|it| it.map(|it| Box::new(node2node(*it)))))
        }
        Node::Code(Code { code }) => Theirs::Code(code.into()),
        Node::Empty => Theirs::Empty,
    }
}
