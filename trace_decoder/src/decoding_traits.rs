use crate::{aliased_crate_types::GenerationInputs, types::OtherBlockData};

/// The smallest "chunk" that we can break a block into.
pub(crate) trait AtomicBlockUnit {}

// pub(crate) trait BlockTrace {

//     fn into_processable_block_trace(self) -> impl ProcessableBlockTrace;
// }

pub(crate) trait ProcessableBlockTrace {
    type Ir;
    type Error;

    // TODO: Consider having this return an iterator instead?
    fn into_proof_gen_ir(self, other_data: OtherBlockData) -> Result<Vec<Self::Ir>, Self::Error>;
}

pub(crate) trait ProofGenIr {}

#[derive(Debug)]
pub(crate) struct TxnUnit {}

impl AtomicBlockUnit for TxnUnit {}

#[derive(Debug)]
pub(crate) struct ContinuationUnit {}

impl AtomicBlockUnit for ContinuationUnit {}

// TODO: Wrap or use alias, don't do this... (?)
impl ProofGenIr for GenerationInputs {}
