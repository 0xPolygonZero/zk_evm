use ethereum_types::{Address, U256};

use crate::types::{InsertCodeFunc, ResolveFunc};

#[derive(Debug)]
pub(crate) struct ProcessedBlockTrace<T> {
    pub(crate) spec: T,
    pub(crate) withdrawals: Vec<(Address, U256)>,
}

#[derive(Debug)]
pub struct CodeHashMeta<F, G>
where
    F: ResolveFunc,
    G: InsertCodeFunc,
{
    pub resolve_fn: F,
    pub insert_code_fn: G,
}

impl<F, G> CodeHashMeta<F, G>
where
    F: ResolveFunc,
    G: InsertCodeFunc,
{
    /// Returns a `CodeHashMeta` given the provided code hash resolving
    /// function.
    pub const fn new(resolve_fn: F, insert_code_fn: G) -> Self {
        Self {
            resolve_fn,
            insert_code_fn,
        }
    }
}
