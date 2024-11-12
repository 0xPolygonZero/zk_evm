use core::{
    cmp,
    fmt::{self, Write as _},
    iter,
    str::FromStr,
};

use alloy_primitives::{B256, U256};
use anyhow::{bail, ensure};
use bitvec::{array::BitArray, order::Lsb0, view::BitViewSized};
use stackstack::Stack;

pub struct ShitSmt {
    root: Node,
}

impl ShitSmt {
    pub fn new() -> Self {
        Self {
            root: Node::Internal {
                left: None,
                right: None,
            },
        }
    }
    pub fn get(&self, key: U256) -> anyhow::Result<U256> {
        let mut current = &self.root;
        for dir in iter(key) {
            match (current, dir) {
                (
                    Node::Internal {
                        left: Some(child),
                        right: _,
                    },
                    Direction::Left,
                )
                | (
                    Node::Internal {
                        left: _,
                        right: Some(child),
                    },
                    Direction::Right,
                ) => current = child,
                (Node::Internal { .. }, _) => return Ok(U256::ZERO),
                (Node::Hash(h), _) => bail!("encountered hash {h}"),
                (Node::Leaf(_), _) => unreachable!(),
            }
        }
        match current {
            Node::Leaf(it) => Ok(*it),
            Node::Internal { .. } => unreachable!(),
            Node::Hash(h) => bail!("encountered hash {h}"),
        }
    }
    pub fn set(&mut self, key: U256, value: U256) -> anyhow::Result<()> {
        let mut current = &mut self.root;

        for dir in iter(key) {
            match current {
                Node::Internal { left, right } => {
                    let it = match dir {
                        Direction::Left => left,
                        Direction::Right => right,
                    };
                    current = it.get_or_insert(Box::new(Node::Internal {
                        left: None,
                        right: None,
                    }))
                }
                Node::Hash(h) => bail!("encountered hash {h}"),
                Node::Leaf(_) => unreachable!(),
            }
        }
        *current = Node::Leaf(value);
        Ok(())
    }
    pub fn set_hash(&mut self, path: SubtriePath, hash: B256) -> anyhow::Result<()> {
        let mut current = &mut self.root;
        for dir in path.into_iter().map(Direction::from) {
            match current {
                Node::Internal { left, right } => {
                    let it = match dir {
                        Direction::Left => left,
                        Direction::Right => right,
                    };
                    current = it.get_or_insert(Box::new(Node::Internal {
                        left: None,
                        right: None,
                    }))
                }
                Node::Hash(h) => bail!("encountered hash {h}"),
                Node::Leaf(_) => unreachable!(),
            }
        }
        *current = Node::Hash(hash);
        Ok(())
    }
    fn fold<T, E>(&self, mut f: impl FnMut(Fold<T>) -> Result<T, E>) -> Result<T, E> {
        fn _fold<T, E>(
            depth: usize,
            node: &Node,
            f: &mut dyn FnMut(Fold<T>) -> Result<T, E>,
        ) -> Result<T, E> {
            match node {
                Node::Internal { left, right } => {
                    let left = left
                        .as_deref()
                        .map(|it| _fold(depth + 1, it, f))
                        .transpose()?;
                    let right = right
                        .as_deref()
                        .map(|it| _fold(depth + 1, it, f))
                        .transpose()?;
                    f(Fold::Internal { left, right, depth })
                }
                Node::Hash(it) => f(Fold::Hash(*it)),
                Node::Leaf(it) => f(Fold::Value(*it)),
            }
        }
        _fold(0, &self.root, &mut f as &mut dyn FnMut(_) -> _)
    }
}

enum Fold<T> {
    Internal {
        left: Option<T>,
        right: Option<T>,
        depth: usize,
    },
    Hash(B256),
    Value(U256),
}

enum Node {
    Internal {
        left: Option<Box<Self>>,
        right: Option<Box<Self>>,
    },
    Hash(B256),
    Leaf(U256),
}

impl Default for ShitSmt {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ShitSmt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = f.debug_map();
        fn fmt(
            path: Stack<'_, Direction>,
            node: &Node,
            f: &mut fmt::DebugMap<'_, '_>,
        ) -> fmt::Result {
            struct Fmt<T>(T);
            impl fmt::Debug for Fmt<Stack<'_, Direction>> {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    for dir in &self.0 {
                        f.write_fmt(format_args!("{}", dir))?
                    }
                    Ok(())
                }
            }

            match node {
                Node::Internal { left, right } => {
                    for (dir, node) in [
                        left.as_deref().map(|it| (Direction::Left, it)),
                        right.as_deref().map(|it| (Direction::Right, it)),
                    ]
                    .into_iter()
                    .flatten()
                    {
                        fmt(path.pushed(dir), node, f)?;
                    }
                }
                Node::Hash(it) => {
                    f.entry(&Fmt(path), &format_args!("hash:{}", it));
                }
                Node::Leaf(it) => {
                    f.entry(&Fmt(path), &format_args!("value:{}", it));
                }
            }
            Ok(())
        }
        fmt(Stack::new(), &self.root, &mut map)?;
        map.finish()
    }
}

enum Direction {
    Left,
    Right,
}

impl From<bool> for Direction {
    fn from(value: bool) -> Self {
        match value {
            true => Direction::Left,
            false => Direction::Right,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_char(match self {
            Direction::Left => '1',
            Direction::Right => '0',
        })
    }
}

fn iter(key: U256) -> impl DoubleEndedIterator<Item = Direction> {
    key.into_limbs()
        .into_bitarray::<Lsb0>()
        .into_iter()
        .map(Direction::from)
}

/// Bounded sequence of bits,
/// used as a key for SMT tries.
#[derive(Clone, Copy)]
pub struct SubtriePath {
    bits: bitvec::array::BitArray<[u8; 32]>,
    len: usize,
}

impl fmt::Debug for SubtriePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.into_iter().map(|it| match it {
                true => 1,
                false => 0,
            }))
            .finish()
    }
}

impl fmt::Display for SubtriePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for bit in *self {
            f.write_str(match bit {
                true => "1",
                false => "0",
            })?
        }
        Ok(())
    }
}

impl FromStr for SubtriePath {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut components = vec![];
        for char in s.chars() {
            match char {
                '0' => components.push(false),
                '1' => components.push(true),
                _ => bail!("unexpected character {char}"),
            }
        }
        Self::new(components)
    }
}

impl SubtriePath {
    pub fn new(components: impl IntoIterator<Item = bool>) -> anyhow::Result<Self> {
        let mut bits = bitvec::array::BitArray::default();
        let mut len = 0;
        for (ix, bit) in components.into_iter().enumerate() {
            ensure!(
                bits.get(ix).is_some(),
                "expected at most {} components",
                bits.len()
            );
            bits.set(ix, bit);
            len += 1
        }
        Ok(Self { bits, len })
    }
}

impl From<[u8; 32]> for SubtriePath {
    fn from(bytes: [u8; 32]) -> Self {
        Self::new(BitArray::<_>::new(bytes)).expect("SmtKey has room for 256 bits")
    }
}

impl Ord for SubtriePath {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        iter::Iterator::cmp(self.into_iter(), *other)
    }
}
impl PartialOrd for SubtriePath {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Eq for SubtriePath {}
impl PartialEq for SubtriePath {
    fn eq(&self, other: &Self) -> bool {
        iter::Iterator::eq(self.into_iter(), *other)
    }
}

impl IntoIterator for SubtriePath {
    type Item = bool;

    type IntoIter = iter::Take<bitvec::array::IntoIter<[u8; 32], Lsb0>>;

    fn into_iter(self) -> Self::IntoIter {
        let Self { bits, len } = self;
        bits.into_iter().take(len)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use alloy_primitives::b256;
    use quickcheck::quickcheck;
    use ruint::Uint;

    use super::*;

    #[derive(derive_quickcheck_arbitrary::Arbitrary, Clone, Debug)]
    enum Op {
        Get(U256),
        Set(U256, U256),
    }

    #[test]
    fn set_hash() {
        let mut smt = ShitSmt::new();
        smt.set_hash([0; 32].into(), b256!()).unwrap();
        smt.get(Uint::from(0)).unwrap();
    }

    fn do_btree_map_like(ops: Vec<Op>, mut ours: ShitSmt, mut theirs: BTreeMap<U256, U256>) {
        for op in ops {
            match op {
                Op::Get(key) => {
                    assert_eq!(
                        ours.get(key).unwrap(),
                        theirs.get(&key).copied().unwrap_or_default()
                    )
                }
                Op::Set(key, value) => {
                    ours.set(key, value).unwrap();
                    theirs.insert(key, value);
                }
            }
        }
    }

    quickcheck! {
        fn btree_map_like(ops: Vec<Op>) -> () {
            do_btree_map_like(ops, ShitSmt::new(), BTreeMap::new());
        }
    }
}
