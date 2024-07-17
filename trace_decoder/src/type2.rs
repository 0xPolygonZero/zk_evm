//! Frontend for the witness format emitted by e.g [`0xPolygonHermez/cdk-erigon`](https://github.com/0xPolygonHermez/cdk-erigon/)
//! Ethereum node.

use std::{
    collections::{HashMap, HashSet},
    iter,
};

use anyhow::{bail, ensure, Context as _};
use bitvec::vec::BitVec;
use either::Either;
use ethereum_types::BigEndianHash as _;
use itertools::{EitherOrBoth, Itertools as _};
use nunny::NonEmpty;
use plonky2::field::types::Field;

use crate::wire::{Instruction, SmtLeaf, SmtLeafType};

type SmtTrie = smt_trie::smt::Smt<smt_trie::db::MemoryDb>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct CollatedLeaf {
    pub balance: Option<ethereum_types::U256>,
    pub nonce: Option<ethereum_types::U256>,
    pub code_hash: Option<ethereum_types::H256>,
    pub storage_root: Option<ethereum_types::H256>,
}

pub struct Frontend {
    pub trie: SmtTrie,
    pub code: HashSet<NonEmpty<Vec<u8>>>,
    pub collation: HashMap<ethereum_types::Address, CollatedLeaf>,
}

/// # Panics
/// - Liberally, both in this module and the [`smt_trie`] library. Therefore, do
///   NOT call this function on untrusted inputs.
pub fn frontend(instructions: impl IntoIterator<Item = Instruction>) -> anyhow::Result<Frontend> {
    let (node, code) = fold(instructions).context("couldn't fold smt from instructions")?;
    let (trie, collation) =
        node2trie(node).context("couldn't construct trie and collation from folded node")?;
    Ok(Frontend {
        trie,
        code,
        collation,
    })
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
                    0b0001 => Node::Branch(EitherOrBoth::Left(get_child()?)),
                    0b0010 => Node::Branch(EitherOrBoth::Right(get_child()?)),
                    0b0011 => Node::Branch(EitherOrBoth::Both(get_child()?, get_child()?)),
                    other => bail!("unexpected bit pattern in Branch mask: {:#b}", other),
                }))
            }
            Instruction::SmtLeaf(it) => Ok(Some(Node::Leaf(it))),

            other => bail!("expected SmtLeaf | Branch | Hash, got {:?}", other),
        },
        None => Ok(None),
    }
}

/// Pack a [`Node`] tree into an [`SmtTrie`].
/// Also summarizes the [`Node::Leaf`]s out-of-band.
///
/// # Panics
/// - if the tree is too deep.
/// - if [`SmtLeaf::address`] or [`SmtLeaf::value`] are the wrong length.
/// - if [`SmtLeafType::Storage`] is the wrong length.
/// - [`SmtTrie`] panics internally.
fn node2trie(
    node: Node,
) -> anyhow::Result<(SmtTrie, HashMap<ethereum_types::Address, CollatedLeaf>)> {
    let mut trie = SmtTrie::default();

    let (hashes, leaves) =
        iter_leaves(node).partition_map::<Vec<_>, Vec<_>, _, _, _>(|(path, leaf)| match leaf {
            Either::Left(it) => Either::Left((path, it)),
            Either::Right(it) => Either::Right(it),
        });

    for (path, hash) in hashes {
        // needs to be called before `set`, below, "to avoid any issues" according
        // to the smt docs.
        trie.set_hash(
            bits2bits(path),
            smt_trie::smt::HashOut {
                elements: {
                    let ethereum_types::U256(arr) = ethereum_types::H256(hash).into_uint();
                    arr.map(smt_trie::smt::F::from_canonical_u64)
                },
            },
        )
    }

    let mut collated = HashMap::<ethereum_types::Address, CollatedLeaf>::new();
    for SmtLeaf {
        node_type,
        address,
        value,
    } in leaves
    {
        let address = ethereum_types::Address::from_slice(&address);
        let collated = collated.entry(address).or_default();
        let value = ethereum_types::U256::from_big_endian(&value);
        let key = match node_type {
            SmtLeafType::Balance => {
                ensure!(collated.balance.is_none(), "double write of field");
                collated.balance = Some(value);
                smt_trie::keys::key_balance(address)
            }
            SmtLeafType::Nonce => {
                ensure!(collated.nonce.is_none(), "double write of field");
                collated.nonce = Some(value);
                smt_trie::keys::key_nonce(address)
            }
            SmtLeafType::Code => {
                ensure!(collated.code_hash.is_none(), "double write of field");
                collated.code_hash = Some({
                    let mut it = ethereum_types::H256::zero();
                    value.to_big_endian(it.as_bytes_mut());
                    it
                });
                smt_trie::keys::key_code(address)
            }
            SmtLeafType::Storage(it) => {
                ensure!(collated.storage_root.is_none(), "double write of field");
                // TODO(0xaatif): do we not do anything with the storage here?
                smt_trie::keys::key_storage(address, ethereum_types::U256::from_big_endian(&it))
            }
            SmtLeafType::CodeLength => smt_trie::keys::key_code_length(address),
        };
        trie.set(key, value)
    }
    Ok((trie, collated))
}

/// # Panics
/// - on overcapacity
fn bits2bits(ours: BitVec) -> smt_trie::bits::Bits {
    let mut theirs = smt_trie::bits::Bits::empty();
    for it in ours {
        theirs.push_bit(it)
    }
    theirs
}

/// Simple, inefficient visitor of all leaves of the [`Node`] tree.
#[allow(clippy::type_complexity)]
fn iter_leaves(node: Node) -> Box<dyn Iterator<Item = (BitVec, Either<[u8; 32], SmtLeaf>)>> {
    match node {
        Node::Hash(it) => Box::new(iter::once((BitVec::new(), Either::Left(it)))),
        Node::Branch(it) => {
            let (left, right) = it.left_and_right();
            let left = left
                .into_iter()
                .flat_map(|it| iter_leaves(*it).update(|(path, _)| path.insert(0, false)));
            let right = right
                .into_iter()
                .flat_map(|it| iter_leaves(*it).update(|(path, _)| path.insert(0, true)));
            Box::new(left.chain(right))
        }
        Node::Leaf(it) => Box::new(iter::once((BitVec::new(), Either::Right(it)))),
    }
}

#[test]
fn test_tries() {
    for (ix, case) in serde_json::from_str::<Vec<super::Case>>(include_str!(
        "../tests/data/tries/hermez_cdk_erigon.json"
    ))
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
