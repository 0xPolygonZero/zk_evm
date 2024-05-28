//! Defines functions that processes a [BlockTrace] into the smt format so that
//! it is easier to turn the block transactions into IRs.

use std::collections::HashMap;

use ethereum_types::{Address, U256};

use crate::{
    aliased_crate_types::{AccountRlp, GenerationInputs},
    decoding::{ProcessedBlockTraceDecode, TraceDecodingResult},
    processed_block_trace::{BlockTraceProcessing, ProcessedBlockTrace, ProcessingMeta},
    trace_protocol::{BlockTrace, BlockTraceTriePreImages},
    types::{CodeHash, CodeHashResolveFunc, HashedAccountAddr, OtherBlockData},
};

pub(crate) type SmtProcessedBlockTrace =
    ProcessedBlockTrace<ProcedBlockTraceSmtSpec, SmtBlockTraceProcessing>;

/// Smt processed pre-image.
#[derive(Clone, Debug)]
pub struct SmtProcessedBlockTracePreImage {}

#[derive(Debug)]
pub(crate) struct ProcedBlockTraceSmtSpec {}

struct SmtBlockTraceProcessing;

impl BlockTraceProcessing for SmtBlockTraceProcessing {
    type ProcessedPreImage = SmtProcessedBlockTracePreImage;
    type Output = ProcedBlockTraceSmtSpec;

    fn process_block_trace(
        image: BlockTraceTriePreImages,
    ) -> TraceDecodingResult<Self::ProcessedPreImage> {
        todo!()
    }

    fn get_account_keys(
        image: &Self::ProcessedPreImage,
    ) -> impl Iterator<Item = (HashedAccountAddr, AccountRlp)> {
        todo!();

        std::iter::empty()
    }

    fn get_any_extra_code_hash_mappings(
        image: &Self::ProcessedPreImage,
    ) -> Option<&HashMap<CodeHash, Vec<u8>>> {
        todo!()
    }

    fn create_spec_output(image: Self::ProcessedPreImage) -> Self::Output {
        todo!()
    }
}

pub(crate) struct SmtBlockTraceDecoding;

impl ProcessedBlockTraceDecode for SmtBlockTraceDecoding {
    type Spec;
    type Ir;
    type TrieInputs;
    type StateTrie;
    type StorageTries;
    type ReceiptTrie;
    type TxnTrie;

    fn get_trie_pre_image(spec: &Self::Spec) -> crate::decoding::TrieState<Self> {
        todo!()
    }

    fn create_trie_subsets(
        tries: &crate::decoding::TrieState<Self>,
        nodes_used_by_txn: &crate::processed_block_trace::NodesUsedByTxn,
        txn_idx: crate::types::TxnIdx,
    ) -> TraceDecodingResult<crate::decoding::TrieState<Self>> {
        todo!()
    }

    fn create_dummy_ir(
        other_data: &OtherBlockData,
        extra_data: &crate::aliased_crate_types::ExtraBlockData,
        final_tries: &crate::decoding::TrieState<Self>,
        account_addrs_accessed: impl Iterator<Item = HashedAccountAddr>,
    ) -> Self::Ir {
        todo!()
    }

    fn create_trie_inputs(tries: crate::decoding::TrieState<Self>) -> Self::TrieInputs {
        todo!()
    }

    fn create_ir(
        txn_number_before: U256,
        gas_used_before: U256,
        gas_used_after: U256,
        signed_txn: Option<Vec<u8>>,
        withdrawals: Vec<(Address, U256)>,
        tries: Self::TrieInputs,
        trie_roots_after: crate::aliased_crate_types::TrieRoots,
        checkpoint_state_trie_root: crate::types::TrieRootHash,
        contract_code: HashMap<keccak_hash::H256, Vec<u8>>,
        block_metadata: crate::aliased_crate_types::BlockMetadata,
        block_hashes: crate::aliased_crate_types::BlockHashes,
    ) -> Self::Ir {
        todo!()
    }
}

impl BlockTrace {
    /// Process the block trace into SMT IR.
    pub fn into_proof_gen_smt_ir(
        self,
        _other_data: OtherBlockData,
    ) -> TraceDecodingResult<Vec<GenerationInputs>> {
        todo!()
    }

    /// Processes and returns the [GenerationInputs] for all transactions in the
    /// block.
    pub fn smt_into_proof_gen_ir<F>(
        self,
        p_meta: &ProcessingMeta<F>,
        other_data: OtherBlockData,
    ) -> TraceDecodingResult<Vec<GenerationInputs>>
    where
        F: CodeHashResolveFunc,
    {
        let processed_block_trace =
            self.into_smt_processed_block_trace(p_meta, other_data.b_data.withdrawals.clone())?;

        let res = processed_block_trace.into_proof_gen_ir(other_data)?;

        Ok(res)
    }

    fn into_smt_processed_block_trace<F>(
        self,
        p_meta: &ProcessingMeta<F>,
        withdrawals: Vec<(Address, U256)>,
    ) -> TraceDecodingResult<ProcessedBlockTrace<_, _>>
    where
        F: CodeHashResolveFunc,
    {
        self.into_processed_block_trace::<_, SmtBlockTraceProcessing, SmtBlockTraceDecoding>(
            p_meta,
            withdrawals,
        )
    }
}
