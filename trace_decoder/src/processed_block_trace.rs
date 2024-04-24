use ethereum_types::{Address, U256};

use crate::{
    decoding_traits::ProofGenIr,
    trace_protocol::{AtomicUnitInfo, BlockTrace},
};

#[derive(Debug)]
pub(crate) struct ProcessedBlockTrace<T> {
    pub(crate) spec: T,
    pub(crate) withdrawals: Vec<(Address, U256)>,
}
