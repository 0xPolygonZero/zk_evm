use ethereum_types::{Address, U256};

#[derive(Debug)]
pub(crate) struct ProcessedBlockTrace<T> {
    pub(crate) spec: T,
    pub(crate) withdrawals: Vec<(Address, U256)>,
}
