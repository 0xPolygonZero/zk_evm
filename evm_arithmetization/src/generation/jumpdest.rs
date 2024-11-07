//! EVM opcode 0x5B or 91 is [`JUMPDEST`] which encodes a a valid offset, that
//! opcodes `JUMP` and `JUMPI` can jump to. Jumps to non-[`JUMPDEST`]
//! instructions are invalid. During an execution a [`JUMPDEST`] may be visited
//! zero or more times. Offsets are measured in bytes with respect to the
//! beginning of some contract code, which is uniquely identified by its
//! `CodeHash`. Every time control flow is switches to another contract through
//! a `CALL`-like instruction a new call context, `Context`, is created. Thus,
//! the tripple (`CodeHash`,`Context`, `Offset`) uniquely identifies an visited
//! [`JUMPDEST`] offset of an execution.
//!
//! Since an operation like e.g. `PUSH 0x5B` does not encode a valid
//! [`JUMPDEST`] in its second byte, and `PUSH32
//! 5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B5B` does not
//! encode any valid [`JUMPDEST`] in bytes 1-32, some diligence must be
//! exercised when proving validity of jump operations.
//!
//! This module concerns itself with data structures for collecting these
//! offsets for [`JUMPDEST`] that was visited during an execution and are not
//! recording duplicity. The proofs, that each of these offsets are not rendered
//! invalid by `PUSH1`-`PUSH32` in any of the previous 32 bytes, are computed
//! later in `prove_context_jumpdests` on basis of these collections.
//!
//! [`JUMPDEST`]: https://www.evm.codes/?fork=cancun#5b

use std::cmp::max;
use std::{
    collections::{BTreeSet, HashMap},
    fmt::Display,
};

use derive_more::derive::{Deref, DerefMut};
use itertools::{sorted, Itertools};
use keccak_hash::H256;
use serde::{Deserialize, Serialize};

/// Each `CodeHash` can be called one or more times,
/// each time creating a new `Context`.
/// Each `Context` will contain one or more offsets of `JUMPDEST`.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize, Default, Deref, DerefMut)]
pub struct Context(pub HashMap<usize, BTreeSet<usize>>);

/// The result after proving a [`JumpDestTableWitness`].
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct JumpDestTableProcessed {
    pub contexts: HashMap<usize, Vec<usize>>,
    /// Translates batch index to a wittness index
    pub index: HashMap<usize, usize>,
    largest_batch_index: usize,
    largest_witness_index: usize,
}

/// Map `CodeHash -> (Context -> [JumpDests])`
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize, Default, Deref, DerefMut)]
pub struct JumpDestTableWitness(HashMap<H256, Context>);

impl Context {
    pub fn insert(&mut self, ctx: usize, offset: usize) {
        self.entry(ctx).or_default().insert(offset);
    }

    pub fn get(&self, ctx: usize) -> Option<&BTreeSet<usize>> {
        self.0.get(&ctx)
    }
}

impl JumpDestTableProcessed {
    pub fn new(ctx_map: HashMap<usize, Vec<usize>>) -> Self {
        Self {
            contexts: ctx_map,
            // mapping from batch indices to witness indices
            index: Default::default(),
            largest_batch_index: 0,
            largest_witness_index: 0,
        }
    }

    pub fn try_get_ctx_mut(&mut self, batch_ctx: &usize) -> Option<&mut Vec<usize>> {
        if *batch_ctx <= self.largest_batch_index {
            let witness_index = self.index[batch_ctx];
            return self.contexts.get_mut(&witness_index);
        }

        let mut new_witness_index = self.largest_witness_index;
        for i in new_witness_index + 1..*batch_ctx {
            if self.contexts.contains_key(&i) {
                new_witness_index = i;
                break;
            }
        }

        self.largest_witness_index = new_witness_index;
        self.largest_batch_index = *batch_ctx;
        self.index.insert(*batch_ctx, new_witness_index);
        self.contexts.get_mut(&new_witness_index)
    }

    pub fn remove_ctx(&mut self, batch_ctx: &usize) {
        let witness_index = self.index[batch_ctx];
        self.contexts.remove(&witness_index);
    }
}

impl JumpDestTableWitness {
    pub fn get(&self, code_hash: &H256) -> Option<&Context> {
        self.0.get(code_hash)
    }

    /// Insert `offset` into `ctx` under the corresponding `code_hash`.
    /// Creates the required `ctx` keys and `code_hash`. Idempotent.
    pub fn insert(&mut self, code_hash: H256, ctx: usize, offset: usize) {
        (*self).entry(code_hash).or_default().insert(ctx, offset);
    }

    pub fn extend(mut self, other: &Self, prev_max_ctx: usize) -> (Self, usize) {
        let mut curr_max_ctx = prev_max_ctx;

        for (code_hash, ctx_tbl) in (*other).iter() {
            for (ctx, jumpdests) in ctx_tbl.0.iter() {
                let batch_ctx = prev_max_ctx + ctx;
                curr_max_ctx = max(curr_max_ctx, batch_ctx);

                for offset in jumpdests {
                    self.insert(*code_hash, batch_ctx, *offset);
                }
            }
        }

        (self, curr_max_ctx)
    }

    pub fn merge<'a>(jdts: impl IntoIterator<Item = &'a JumpDestTableWitness>) -> (Self, usize) {
        jdts.into_iter()
            .fold((Default::default(), 0), |(acc, cnt), t| acc.extend(t, cnt))
    }
}

// The following Display instances are added to make it easier to read diffs.
impl Display for JumpDestTableWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\n=== JumpDestTableWitness ===")?;

        for (code, ctxtbls) in &self.0 {
            write!(f, "codehash: {:#x}\n{}", code, ctxtbls)?;
        }
        Ok(())
    }
}

impl Display for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v: Vec<_> = self.0.iter().sorted().collect();
        for (ctx, offsets) in v.into_iter() {
            write!(f, "     ctx: {:>4}:    [", ctx)?;
            for offset in offsets {
                write!(f, "{:#}, ", offset)?;
            }
            writeln!(f, "]")?;
        }
        Ok(())
    }
}

impl Display for JumpDestTableProcessed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\n=== JumpDestTableProcessed ===")?;

        let v = sorted(self.contexts.clone());
        for (ctx, code) in v {
            writeln!(f, "ctx: {:?} {:?}", ctx, code)?;
        }
        Ok(())
    }
}

impl FromIterator<(H256, usize, usize)> for JumpDestTableWitness {
    fn from_iter<T: IntoIterator<Item = (H256, usize, usize)>>(iter: T) -> Self {
        let mut jdtw = JumpDestTableWitness::default();
        for (code_hash, ctx, offset) in iter.into_iter() {
            jdtw.insert(code_hash, ctx, offset);
        }
        jdtw
    }
}

#[cfg(test)]
mod test {
    use keccak_hash::H256;

    use super::JumpDestTableWitness;

    #[test]
    fn test_extend_from_iter() {
        let code_hash = H256::default();

        let ctx_map = vec![
            (code_hash, 1, 1),
            (code_hash, 2, 2),
            (code_hash, 42, 3),
            (code_hash, 43, 4),
        ];
        let table1 = JumpDestTableWitness::from_iter(ctx_map);
        let table2 = table1.clone();

        let jdts = [&table1, &table2];
        let (actual, max_ctx) = JumpDestTableWitness::merge(jdts);

        let ctx_map_merged = vec![
            (code_hash, 1, 1),
            (code_hash, 2, 2),
            (code_hash, 42, 3),
            (code_hash, 43, 4),
            (code_hash, 44, 1),
            (code_hash, 45, 2),
            (code_hash, 85, 3),
            (code_hash, 86, 4),
        ];
        let expected = JumpDestTableWitness::from_iter(ctx_map_merged);

        assert_eq!(86, max_ctx);
        assert_eq!(expected, actual)
    }
}
