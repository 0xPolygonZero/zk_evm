//! Frontend for the witness format emitted by e.g [`0xPolygonHermez/cdk-erigon`](https://github.com/0xPolygonHermez/cdk-erigon/)
//! Ethereum node.

use std::collections::{BTreeMap, HashSet};

use anyhow::{bail, ensure, Context as _};
use ethereum_types::{Address, BigEndianHash as _, U256};
use itertools::EitherOrBoth;
use keccak_hash::H256;
use nunny::NonEmpty;
use plonky2::field::types::{Field, Field64 as _};
use smt_trie::keys::{key_balance, key_code, key_code_length, key_nonce, key_storage};
use stackstack::Stack;

use crate::{
    typed_mpt::SmtKey,
    wire::{Instruction, SmtLeaf, SmtLeafType},
};
type SmtTrie = smt_trie::smt::Smt<smt_trie::db::MemoryDb>;

/// Combination of all the [`SmtLeaf::node_type`]s
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct CollatedLeaf {
    pub balance: Option<ethereum_types::U256>,
    pub nonce: Option<ethereum_types::U256>,
    pub code: Option<ethereum_types::U256>,
    pub code_length: Option<ethereum_types::U256>,
    pub storage: BTreeMap<U256, U256>,
}

pub struct Frontend {
    pub trie: SmtTrie,
    pub code: HashSet<NonEmpty<Vec<u8>>>,
}

/// # Panics
/// - Liberally, both in this module and the [`smt_trie`] library. Therefore, do
///   NOT call this function on untrusted inputs.
pub fn frontend(instructions: impl IntoIterator<Item = Instruction>) -> anyhow::Result<Frontend> {
    let (node, code) = fold(instructions).context("couldn't fold smt from instructions")?;
    let trie = node2trie(node).context("couldn't construct trie and collation from folded node")?;
    Ok(Frontend { trie, code })
}

/// Node in a binary (SMT) tree.
///
/// This is an intermediary type on the way to [`SmtTrie`].
enum Node {
    Branch(EitherOrBoth<Box<Self>>),
    Hash([u8; 32]),
    Leaf(SmtLeaf),
}

/// Parse all instructions into a single [`Node`].
/// Also summarizes [`Instruction::Code`]s out-of-band.
///
/// See [`fold1`] for more.
fn fold(
    instructions: impl IntoIterator<Item = Instruction>,
) -> anyhow::Result<(Node, HashSet<NonEmpty<Vec<u8>>>)> {
    let mut code = HashSet::new();
    let mut instructions = instructions
        .into_iter()
        .filter_map(|instruction| match instruction {
            Instruction::Code { raw_code } => {
                code.insert(raw_code);
                None
            }
            other => Some(other),
        });
    let folded = fold1(&mut instructions)?.context("no instructions to fold")?;
    // this is lenient WRT trailing Code instructions
    ensure!(instructions.count() == 0, "leftover instructions");
    Ok((folded, code))
}

/// Pick a single [`Node`] from the instructions, or return [`None`] if
/// the instructions empty.
///
/// Instructions are parsed as a pre-order (root first) traversal of SMT nodes.
///
/// ```text
/// ┌────────┬──────┬──────┬──────────────────────────
/// │ Branch │ Hash │ Hash │ Untouched instructions...
/// └────────┴──────┴──────┴──────────────────────────
/// ^~~~~~~~~~~~~~~~~~~~~~~^
///  assembled into a Node
/// ```
fn fold1(instructions: impl IntoIterator<Item = Instruction>) -> anyhow::Result<Option<Node>> {
    let mut instructions = instructions.into_iter();
    match instructions.next() {
        Some(instruction) => match instruction {
            Instruction::Hash { raw_hash } => Ok(Some(Node::Hash(raw_hash))),
            Instruction::Branch { mask } => {
                let mut get_child =
                    || match fold1(&mut instructions as &mut dyn Iterator<Item = Instruction>) {
                        Ok(Some(it)) => Ok(Box::new(it)),
                        Ok(None) => bail!("no child for Branch"),
                        Err(e) => Err(e),
                    };

                Ok(Some(match mask {
                    // note that the single-child bits are reversed...
                    0b_01 => Node::Branch(EitherOrBoth::Left(get_child()?)),
                    0b_10 => Node::Branch(EitherOrBoth::Right(get_child()?)),
                    0b_11 => Node::Branch(EitherOrBoth::Both(get_child()?, get_child()?)),
                    other => bail!("unexpected bit pattern in Branch mask: {:#b}", other),
                }))
            }
            Instruction::SmtLeaf(it) => Ok(Some(Node::Leaf(it))),

            other => bail!("expected SmtLeaf | Branch | Hash, got {:?}", other),
        },
        None => Ok(None),
    }
}

fn node2trie(node: Node) -> anyhow::Result<SmtTrie> {
    let mut trie = SmtTrie::default();
    let mut hashes = BTreeMap::new();
    let mut leaves = BTreeMap::new();
    visit(&mut hashes, &mut leaves, Stack::new(), node)?;
    for (key, hash) in hashes {
        trie.set_hash(
            key.into_smt_bits(),
            smt_trie::smt::HashOut {
                elements: {
                    let ethereum_types::U256(arr) = hash.into_uint();
                    for u in arr {
                        ensure!(u < smt_trie::smt::F::ORDER);
                    }
                    arr.map(smt_trie::smt::F::from_canonical_u64)
                },
            },
        );
    }
    for (
        addr,
        CollatedLeaf {
            balance,
            nonce,
            code,
            code_length,
            storage,
        },
    ) in leaves
    {
        for (value, key_fn) in [
            (balance, key_balance as fn(_) -> _),
            (nonce, key_nonce),
            (code, key_code),
            (code_length, key_code_length),
        ] {
            if let Some(value) = value {
                trie.set(key_fn(addr), value);
            }
        }
        for (slot, value) in storage {
            trie.set(key_storage(addr, slot), value);
        }
    }
    Ok(trie)
}

fn visit(
    hashes: &mut BTreeMap<SmtKey, H256>,
    leaves: &mut BTreeMap<Address, CollatedLeaf>,
    path: Stack<bool>,
    node: Node,
) -> anyhow::Result<()> {
    match node {
        Node::Branch(children) => {
            let (left, right) = children.left_and_right();
            if let Some(left) = left {
                visit(hashes, leaves, path.pushed(false), *left)?;
            }
            if let Some(right) = right {
                visit(hashes, leaves, path.pushed(true), *right)?;
            }
        }
        Node::Hash(hash) => {
            hashes.insert(SmtKey::new(path.iter().copied())?, H256(hash));
        }
        Node::Leaf(SmtLeaf {
            node_type,
            address, // TODO(0xaatif): field should be fixed length
            value,   // TODO(0xaatif): field should be fixed length
        }) => {
            let address = Address::from_slice(&address);
            let collated = leaves.entry(address).or_default();
            let value = U256::from_big_endian(&value);
            macro_rules! ensure {
                ($expr:expr) => {
                    ::anyhow::ensure!($expr, "double write of field for address {}", address)
                };
            }
            match node_type {
                SmtLeafType::Balance => {
                    ensure!(collated.balance.is_none());
                    collated.balance = Some(value)
                }
                SmtLeafType::Nonce => {
                    ensure!(collated.nonce.is_none());
                    collated.nonce = Some(value)
                }
                SmtLeafType::Code => {
                    ensure!(collated.code.is_none());
                    collated.code = Some(value)
                }
                SmtLeafType::Storage(slot) => {
                    // TODO(0xaatif): ^ field should be fixed length
                    let clobbered = collated.storage.insert(U256::from_big_endian(&slot), value);
                    ensure!(clobbered.is_none())
                }
                SmtLeafType::CodeLength => {
                    ensure!(collated.code_length.is_none());
                    collated.code_length = Some(value)
                }
            };
        }
    }
    Ok(())
}

#[test]
fn test_tries() {
    for (ix, case) in
        serde_json::from_str::<Vec<super::Case>>(include_str!("cases/hermez_cdk_erigon.json"))
            .unwrap()
            .into_iter()
            .enumerate()
    {
        println!("case {}", ix);
        let instructions = crate::wire::parse(&case.bytes).unwrap();
        let frontend = frontend(instructions).unwrap();
        assert_eq!(case.expected_state_root, {
            let mut it = [0; 32];
            smt_trie::utils::hashout2u(frontend.trie.root).to_big_endian(&mut it);
            ethereum_types::H256(it)
        });
    }
}
