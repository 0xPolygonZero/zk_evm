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
    ops::{Deref, DerefMut},
};

use itertools::{sorted, Itertools};
use keccak_hash::H256;
use serde::{Deserialize, Serialize};

/// Each `CodeHash` can be called one or more times,
/// each time creating a new `Context`.
/// Each `Context` will contain one or more offsets of `JUMPDEST`.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContextJumpDests(pub HashMap<usize, BTreeSet<usize>>);

/// The result after proving a [`JumpDestTableWitness`].
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct JumpDestTableProcessed(HashMap<usize, Vec<usize>>);

/// Map `CodeHash -> (Context -> [JumpDests])`
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize, Default)]
pub struct JumpDestTableWitness(HashMap<H256, ContextJumpDests>);

impl ContextJumpDests {
    pub fn insert(&mut self, ctx: usize, offset: usize) {
        self.entry(ctx).or_default().insert(offset);
    }

    pub fn get(&self, ctx: usize) -> Option<&BTreeSet<usize>> {
        self.0.get(&ctx)
    }
}

impl JumpDestTableProcessed {
    pub fn new(ctx_map: HashMap<usize, Vec<usize>>) -> Self {
        Self(ctx_map)
    }
}

impl JumpDestTableWitness {
    pub fn get(&self, code_hash: &H256) -> Option<&ContextJumpDests> {
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

impl Display for JumpDestTableWitness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "\n=== JumpDestTableWitness ===")?;

        for (code, ctxtbls) in &self.0 {
            write!(f, "codehash: {:#x}\n{}", code, ctxtbls)?;
        }
        Ok(())
    }
}

impl Display for ContextJumpDests {
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

        let v = sorted(self.0.clone());
        for (ctx, code) in v {
            writeln!(f, "ctx: {:?} {:?}", ctx, code)?;
        }
        Ok(())
    }
}

impl Deref for ContextJumpDests {
    type Target = HashMap<usize, BTreeSet<usize>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ContextJumpDests {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for JumpDestTableProcessed {
    type Target = HashMap<usize, Vec<usize>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for JumpDestTableProcessed {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for JumpDestTableWitness {
    type Target = HashMap<H256, ContextJumpDests>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for JumpDestTableWitness {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod test {
    use keccak_hash::H256;

    use super::JumpDestTableWitness;

    #[test]
    fn test_extend() {
        let code_hash = H256::default();

        let mut table1 = JumpDestTableWitness::default();
        table1.insert(code_hash, 1, 1);
        table1.insert(code_hash, 2, 2);
        table1.insert(code_hash, 42, 3);
        table1.insert(code_hash, 43, 4);
        let table2 = table1.clone();

        let jdts = [&table1, &table2];
        let (actual, max_ctx) = JumpDestTableWitness::merge(jdts);

        let mut expected = JumpDestTableWitness::default();
        expected.insert(code_hash, 1, 1);
        expected.insert(code_hash, 2, 2);
        expected.insert(code_hash, 42, 3);
        expected.insert(code_hash, 43, 4);
        expected.insert(code_hash, 44, 1);
        expected.insert(code_hash, 45, 2);
        expected.insert(code_hash, 85, 3);
        expected.insert(code_hash, 86, 4);

        assert_eq!(86, max_ctx);
        assert_eq!(expected, actual)
    }
}