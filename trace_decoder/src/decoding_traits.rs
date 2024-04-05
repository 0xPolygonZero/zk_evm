use std::iter::{empty, once};

use evm_arithmetization::GenerationInputs;

pub(crate) trait PrestateCompact {
    fn process() -> impl IrMutableState;
}

/// The smallest "chunk" that we can break a block into.
pub(crate) trait AtomicBlockUnit {}

pub(crate) trait IrMutableState {
    type Ir: ProofGenIr;

    fn produce_ir(
        self,
        block_atomic_units: impl Iterator<Item = impl AtomicBlockUnit>,
    ) -> impl Iterator<Item = Self::Ir>;
}

#[derive(Debug)]
pub(crate) struct TxnIrMutableState {}

impl IrMutableState for TxnIrMutableState {
    type Ir = GenerationInputs; // TODO: Swap this out with an alias...

    fn produce_ir(
        self,
        block_atomic_units: impl Iterator<Item = impl AtomicBlockUnit>,
    ) -> impl Iterator<Item = Self::Ir> {
        // TODO
        once(todo!())
    }
}

#[derive(Debug)]
pub(crate) struct ContinuationIrMutableState {}

impl IrMutableState for ContinuationIrMutableState {
    type Ir = GenerationInputs; // TODO: Swap this out with an alias...

    fn produce_ir(
        self,
        block_atomic_units: impl Iterator<Item = impl AtomicBlockUnit>,
    ) -> impl Iterator<Item = Self::Ir> {
        once(todo!())
    }
}

pub(crate) trait ProofGenIr {}

#[derive(Debug)]
pub(crate) struct TxnUnit {}

impl AtomicBlockUnit for TxnUnit {}

#[derive(Debug)]
pub(crate) struct ContinuationUnit {}

impl AtomicBlockUnit for ContinuationUnit {}

// TODO: Wrap or use alias, don't do this...
impl ProofGenIr for GenerationInputs {}
