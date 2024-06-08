use std::array;

use anyhow::{bail, Context as _};
use either::Either;
use ethereum_types::U256;
use nunny::NonEmpty;

use super::Instruction;

#[derive(Debug)]
pub struct Hash {
    pub raw_hash: [u8; 32],
}

#[derive(Debug)]
pub struct Value {
    pub raw_value: NonEmpty<Vec<u8>>,
}

#[derive(Debug)]
pub struct Account {
    pub nonce: u64,
    pub balance: U256,
    pub storage: Option<Box<Node>>,
    pub code: Option<Either<Hash, Code>>,
}

#[derive(Debug)]
pub struct Code {
    pub code: NonEmpty<Vec<u8>>,
}

#[derive(Debug)]
pub struct Leaf {
    pub key: NonEmpty<Vec<u8>>,
    pub value: Either<Value, Account>,
}

#[derive(Debug)]
pub struct Extension {
    pub key: NonEmpty<Vec<u8>>,
    pub child: Box<Node>,
}

#[derive(Debug)]
pub struct Branch {
    pub children: [Option<Box<Node>>; 16],
}

#[derive(Debug)]
pub enum Node {
    Hash(Hash),
    Value(Value),
    Account(Account),
    Leaf(Leaf),
    Extension(Extension),
    Branch(Branch),
    Code(Code),
}

pub enum Witness {
    Leaf(Leaf),
    Extension(Extension),
    Branch(Branch),
}

pub fn forest(
    instructions: impl IntoIterator<Item = Instruction>,
) -> anyhow::Result<NonEmpty<Vec<Witness>>> {
    let mut witnesses = vec![];
    let mut stack = vec![];
    for instruction in instructions {
        match instruction {
            Instruction::EmptyRoot => todo!(),
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
                key, // BUG?(0xaatif): why is this unused?
                nonce,
                balance,
                has_code,
                has_storage,
            } => {
                // BUG: the spec sometimes writes Node::Account with 5 fields..
                // TODO(0xaatif): should these fields even be optional?
                let nonce = nonce.context("AccountLeaf has no nonce")?;
                let balance = balance.context("AccountLeaf has no balance")?;
                match (has_code, has_storage) {
                    (true, true) => match pop2(&mut stack) {
                        (Some(Node::Hash(hash)), Some(storage)) => {
                            stack.push(Node::Account(Account {
                                nonce,
                                balance,
                                storage: Some(Box::new(storage)),
                                code: Some(Either::Left(hash)),
                            }))
                        }
                        (Some(Node::Code(code)), Some(storage)) => {
                            stack.push(Node::Account(Account {
                                nonce,
                                balance,
                                storage: Some(Box::new(storage)),
                                code: Some(Either::Right(code)),
                            }))
                        }
                        other => bail!(
                            "expected (Code | Hash, Node) for AccountLeaf, got {:?}",
                            other
                        ),
                    },
                    (false, true) => {
                        let storage =
                            Some(Box::new(stack.pop().context("no Node for AccountLeaf")?));
                        stack.push(Node::Account(Account {
                            nonce,
                            balance,
                            storage,
                            code: None,
                        }))
                    }
                    (true, false) => match stack.pop() {
                        Some(Node::Hash(it)) => stack.push(Node::Account(Account {
                            nonce,
                            balance,
                            storage: None,
                            code: Some(Either::Left(it)),
                        })),
                        Some(Node::Code(it)) => stack.push(Node::Account(Account {
                            nonce,
                            balance,
                            storage: None,
                            code: Some(Either::Right(it)),
                        })),
                        other => bail!("expected Code | Hash for AccountLeaf, got {:?}", other),
                    },
                    (false, false) => stack.push(Node::Account(Account {
                        nonce,
                        balance,
                        storage: None,
                        code: None,
                    })),
                }
            }
            Instruction::Branch { mask } => {
                use bitvec::{order::Lsb0, view::BitView as _};
                let mut children = array::from_fn(|_ix| None);
                for (ix, it) in mask.view_bits::<Lsb0>().iter().by_vals().enumerate() {
                    if it {
                        *children.get_mut(ix).context("oob mask bit for Branch")? =
                            Some(Box::new(stack.pop().context("no Node for Branch")?));
                    }
                }
                stack.push(Node::Branch(Branch { children }))
            }
            Instruction::NewTrie => witnesses.push(finish_stack(&mut stack)?),
        }
    }
    witnesses.push(finish_stack(&mut stack)?);

    NonEmpty::<Vec<_>>::new(witnesses)
        .ok()
        .context("no instructions")?;
    todo!()
}

fn finish_stack(v: &mut Vec<Node>) -> anyhow::Result<Witness> {
    match (v.len(), v.pop()) {
        (1, Some(node)) => match node {
            Node::Leaf(it) => Ok(Witness::Leaf(it)),
            Node::Extension(it) => Ok(Witness::Extension(it)),
            Node::Branch(it) => Ok(Witness::Branch(it)),
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
