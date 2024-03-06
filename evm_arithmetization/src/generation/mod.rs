use std::collections::HashMap;

use anyhow::anyhow;
use ethereum_types::{Address, BigEndianHash, H256, U256};
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use serde::{Deserialize, Serialize};
use starky::config::StarkConfig;
use GlobalMetadata::{
    ReceiptTrieRootDigestAfter, ReceiptTrieRootDigestBefore, StateTrieRootDigestAfter,
    StateTrieRootDigestBefore, TransactionTrieRootDigestAfter, TransactionTrieRootDigestBefore,
};

use crate::all_stark::{AllStark, NUM_TABLES};
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::assembler::Kernel;
use crate::cpu::kernel::constants::context_metadata::ContextMetadata;
use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::generation::state::{GenerationState, State};
use crate::generation::trie_extractor::{get_receipt_trie, get_state_trie, get_txn_trie};
use crate::memory::segments::Segment;
use crate::proof::{
    BlockHashes, BlockMetadata, ExtraBlockData, MemCap, PublicValues, RegistersData, TrieRoots,
};
use crate::prover::{check_abort_signal, get_mem_after_value_from_row};
use crate::util::{h2u, u256_to_usize};
use crate::witness::errors::{ProgramError, ProverInputError};
use crate::witness::memory::{MemoryAddress, MemoryChannel, MemoryState};
use crate::witness::state::RegistersState;
use crate::witness::traces::Traces;

pub mod mpt;
pub(crate) mod prover_input;
pub(crate) mod rlp;
pub(crate) mod state;
mod trie_extractor;

use self::mpt::{load_all_mpts, TrieRootPtrs};
use crate::witness::util::{mem_write_log, mem_write_log_timestamp_zero};

/// Number of cycles to go after having reached the halting state. It is
/// equal to the number of cycles in `exc_stop` + 1.
pub const NUM_EXTRA_CYCLES_AFTER: usize = 79;
/// Memory values used to initialize `MemBefore`.
pub type MemBeforeValues = Vec<(MemoryAddress, U256)>;

/// Inputs needed for trace generation.
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct GenerationInputs {
    /// The index of the transaction being proven within its block.
    pub txn_number_before: U256,
    /// The cumulative gas used through the execution of all transactions prior
    /// the current one.
    pub gas_used_before: U256,
    /// The cumulative gas used after the execution of the current transaction.
    /// The exact gas used by the current transaction is `gas_used_after` -
    /// `gas_used_before`.
    pub gas_used_after: U256,

    /// A None would yield an empty proof, otherwise this contains the encoding
    /// of a transaction.
    pub signed_txn: Option<Vec<u8>>,
    /// Withdrawal pairs `(addr, amount)`. At the end of the txs, `amount` is
    /// added to `addr`'s balance. See EIP-4895.
    pub withdrawals: Vec<(Address, U256)>,
    pub tries: TrieInputs,
    /// Expected trie roots after the transactions are executed.
    pub trie_roots_after: TrieRoots,

    /// State trie root of the checkpoint block.
    /// This could always be the genesis block of the chain, but it allows a
    /// prover to continue proving blocks from certain checkpoint heights
    /// without requiring proofs for blocks past this checkpoint.
    pub checkpoint_state_trie_root: H256,

    /// Mapping between smart contract code hashes and the contract byte code.
    /// All account smart contracts that are invoked will have an entry present.
    pub contract_code: HashMap<H256, Vec<u8>>,

    /// Information contained in the block header.
    pub block_metadata: BlockMetadata,

    /// The hash of the current block, and a list of the 256 previous block
    /// hashes.
    pub block_hashes: BlockHashes,
}

/// A lighter version of [`GenerationInputs`], which have been trimmed
/// post pre-initialization processing.
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub(crate) struct GenerationInputsTrimmed {
    /// The index of the transaction being proven within its block.
    pub(crate) txn_number_before: U256,
    /// The cumulative gas used through the execution of all transactions prior
    /// the current one.
    pub(crate) gas_used_before: U256,
    /// The cumulative gas used after the execution of the current transaction.
    /// The exact gas used by the current transaction is `gas_used_after` -
    /// `gas_used_before`.
    pub(crate) gas_used_after: U256,

    /// Indicates whether there is an actual transaction or a dummy payload.
    pub(crate) has_txn: bool,

    /// Expected trie roots after the transactions are executed.
    pub(crate) trie_roots_after: TrieRoots,

    /// State trie root of the checkpoint block.
    /// This could always be the genesis block of the chain, but it allows a
    /// prover to continue proving blocks from certain checkpoint heights
    /// without requiring proofs for blocks past this checkpoint.
    pub(crate) checkpoint_state_trie_root: H256,

    /// Mapping between smart contract code hashes and the contract byte code.
    /// All account smart contracts that are invoked will have an entry present.
    pub(crate) contract_code: HashMap<H256, Vec<u8>>,

    /// Information contained in the block header.
    pub(crate) block_metadata: BlockMetadata,

    /// The hash of the current block, and a list of the 256 previous block
    /// hashes.
    pub(crate) block_hashes: BlockHashes,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct TrieInputs {
    /// A partial version of the state trie prior to these transactions. It
    /// should include all nodes that will be accessed by these
    /// transactions.
    pub state_trie: HashedPartialTrie,

    /// A partial version of the transaction trie prior to these transactions.
    /// It should include all nodes that will be accessed by these
    /// transactions.
    pub transactions_trie: HashedPartialTrie,

    /// A partial version of the receipt trie prior to these transactions. It
    /// should include all nodes that will be accessed by these
    /// transactions.
    pub receipts_trie: HashedPartialTrie,

    /// A partial version of each storage trie prior to these transactions. It
    /// should include all storage tries, and nodes therein, that will be
    /// accessed by these transactions.
    pub storage_tries: Vec<(H256, HashedPartialTrie)>,
}

pub struct SegmentData<F: RichField> {
    pub max_cpu_len_log: usize,
    pub starting_state: GenerationState<F>,
    pub memory_before: Vec<(MemoryAddress, U256)>,
    pub registers_before: RegistersData,
    pub registers_after: RegistersData,
}

impl GenerationInputs {
    /// Outputs a trimmed version of the `GenerationInputs`, that do not contain
    /// the fields that have already been processed during pre-initialization,
    /// namely: the input tries, the signed transaction, and the withdrawals.
    pub(crate) fn trim(&self) -> GenerationInputsTrimmed {
        GenerationInputsTrimmed {
            txn_number_before: self.txn_number_before,
            gas_used_before: self.gas_used_before,
            gas_used_after: self.gas_used_after,
            has_txn: self.signed_txn.is_some(),
            trie_roots_after: self.trie_roots_after.clone(),
            checkpoint_state_trie_root: self.checkpoint_state_trie_root,
            contract_code: self.contract_code.clone(),
            block_metadata: self.block_metadata.clone(),
            block_hashes: self.block_hashes.clone(),
        }
    }
}

fn apply_metadata_and_tries_memops<F: RichField + Extendable<D>, const D: usize>(
    state: &mut GenerationState<F>,
    inputs: &GenerationInputs,
    registers_before: &RegistersData,
    registers_after: &RegistersData,
) {
    let metadata = &inputs.block_metadata;
    let tries = &inputs.tries;
    let trie_roots_after = &inputs.trie_roots_after;
    let fields = [
        (
            GlobalMetadata::BlockBeneficiary,
            U256::from_big_endian(&metadata.block_beneficiary.0),
        ),
        (GlobalMetadata::BlockTimestamp, metadata.block_timestamp),
        (GlobalMetadata::BlockNumber, metadata.block_number),
        (GlobalMetadata::BlockDifficulty, metadata.block_difficulty),
        (
            GlobalMetadata::BlockRandom,
            metadata.block_random.into_uint(),
        ),
        (GlobalMetadata::BlockGasLimit, metadata.block_gaslimit),
        (GlobalMetadata::BlockChainId, metadata.block_chain_id),
        (GlobalMetadata::BlockBaseFee, metadata.block_base_fee),
        (
            GlobalMetadata::BlockCurrentHash,
            h2u(inputs.block_hashes.cur_hash),
        ),
        (GlobalMetadata::BlockGasUsed, metadata.block_gas_used),
        (GlobalMetadata::BlockGasUsedBefore, inputs.gas_used_before),
        (GlobalMetadata::BlockGasUsedAfter, inputs.gas_used_after),
        (GlobalMetadata::TxnNumberBefore, inputs.txn_number_before),
        (
            GlobalMetadata::TxnNumberAfter,
            inputs.txn_number_before + if inputs.signed_txn.is_some() { 1 } else { 0 },
        ),
        (
            GlobalMetadata::StateTrieRootDigestBefore,
            h2u(tries.state_trie.hash()),
        ),
        (
            GlobalMetadata::TransactionTrieRootDigestBefore,
            h2u(tries.transactions_trie.hash()),
        ),
        (
            GlobalMetadata::ReceiptTrieRootDigestBefore,
            h2u(tries.receipts_trie.hash()),
        ),
        (
            GlobalMetadata::StateTrieRootDigestAfter,
            h2u(trie_roots_after.state_root),
        ),
        (
            GlobalMetadata::TransactionTrieRootDigestAfter,
            h2u(trie_roots_after.transactions_root),
        ),
        (
            GlobalMetadata::ReceiptTrieRootDigestAfter,
            h2u(trie_roots_after.receipts_root),
        ),
        (GlobalMetadata::KernelHash, h2u(KERNEL.code_hash)),
        (GlobalMetadata::KernelLen, KERNEL.code.len().into()),
    ];

    let channel = MemoryChannel::GeneralPurpose(0);
    let mut ops = fields
        .map(|(field, val)| {
            mem_write_log(
                channel,
                // These fields are already scaled by their segment, and are in context 0 (kernel).
                MemoryAddress::new_bundle(U256::from(field as usize)).unwrap(),
                state,
                val,
            )
        })
        .to_vec();

    // Write the block's final block bloom filter.
    ops.extend((0..8).map(|i| {
        mem_write_log(
            channel,
            MemoryAddress::new(0, Segment::GlobalBlockBloom, i),
            state,
            metadata.block_bloom[i],
        )
    }));

    // Write previous block hashes.
    ops.extend(
        (0..256)
            .map(|i| {
                mem_write_log(
                    channel,
                    MemoryAddress::new(0, Segment::BlockHashes, i),
                    state,
                    h2u(inputs.block_hashes.prev_hashes[i]),
                )
            })
            .collect::<Vec<_>>(),
    );

    // Write initial registers.
    let registers_before = [
        registers_before.program_counter,
        registers_before.is_kernel,
        registers_before.stack_len,
        registers_before.stack_top,
        registers_before.context,
        registers_before.gas_used,
    ];
    ops.extend((0..registers_before.len()).map(|i| {
        mem_write_log(
            channel,
            MemoryAddress::new(0, Segment::RegistersStates, i),
            state,
            registers_before[i],
        )
    }));

    let length = registers_before.len();

    // Write final registers.
    let registers_after = [
        registers_after.program_counter,
        registers_after.is_kernel,
        registers_after.stack_len,
        registers_after.stack_top,
        registers_after.context,
        registers_after.gas_used,
    ];
    ops.extend((0..registers_before.len()).map(|i| {
        mem_write_log(
            channel,
            MemoryAddress::new(0, Segment::RegistersStates, length + i),
            state,
            registers_after[i],
        )
    }));

    state.memory.apply_ops(&ops);
    state.traces.memory_ops.extend(ops);
}

type TablesWithPVsAndFinalMem<F> = (
    [Vec<PolynomialValues<F>>; NUM_TABLES],
    PublicValues,
    Vec<Vec<F>>,
);
pub fn generate_traces<F: RichField + Extendable<D>, const D: usize>(
    all_stark: &AllStark<F, D>,
    inputs: GenerationInputs,
    config: &StarkConfig,
    segment_data: SegmentData<F>,
    timing: &mut TimingTree,
) -> anyhow::Result<TablesWithPVsAndFinalMem<F>> {
    // Initialize the state with the one at the end of the
    // previous segment execution, if any.

    let SegmentData {
        max_cpu_len_log,
        starting_state: mut state,
        memory_before,
        registers_before,
        registers_after,
    } = segment_data;

    for &(address, val) in &memory_before {
        state.memory.set(address, val);
    }

    apply_metadata_and_tries_memops(&mut state, &inputs, &registers_before, &registers_after);

    let cpu_res = timed!(
        timing,
        "simulate CPU",
        simulate_cpu(&mut state, max_cpu_len_log)
    );
    let (final_registers, mem_after) = if let Ok(res) = cpu_res {
        res
    } else {
        // Retrieve previous PC (before jumping to KernelPanic), to see if we reached
        // `hash_final_tries`. We will output debugging information on the final
        // tries only if we got a root mismatch.
        let previous_pc = state
            .traces
            .cpu
            .last()
            .expect("We should have CPU rows")
            .program_counter
            .to_canonical_u64() as usize;

        if KERNEL.offset_name(previous_pc).contains("hash_final_tries") {
            let state_trie_ptr = u256_to_usize(
                state
                    .memory
                    .read_global_metadata(GlobalMetadata::StateTrieRoot),
            )
            .map_err(|_| anyhow!("State trie pointer is too large to fit in a usize."))?;
            log::debug!(
                "Computed state trie: {:?}",
                get_state_trie::<HashedPartialTrie>(&state.memory, state_trie_ptr)
            );

            let txn_trie_ptr = u256_to_usize(
                state
                    .memory
                    .read_global_metadata(GlobalMetadata::TransactionTrieRoot),
            )
            .map_err(|_| anyhow!("Transactions trie pointer is too large to fit in a usize."))?;
            log::debug!(
                "Computed transactions trie: {:?}",
                get_txn_trie::<HashedPartialTrie>(&state.memory, txn_trie_ptr)
            );

            let receipt_trie_ptr = u256_to_usize(
                state
                    .memory
                    .read_global_metadata(GlobalMetadata::ReceiptTrieRoot),
            )
            .map_err(|_| anyhow!("Receipts trie pointer is too large to fit in a usize."))?;
            log::debug!(
                "Computed receipts trie: {:?}",
                get_receipt_trie::<HashedPartialTrie>(&state.memory, receipt_trie_ptr)
            );
        }

        cpu_res?;
        (RegistersState::default(), None)
    };

    log::info!(
        "Trace lengths (before padding): {:?}",
        state.traces.get_lengths()
    );

    let read_metadata = |field| state.memory.read_global_metadata(field);
    let trie_roots_before = TrieRoots {
        state_root: H256::from_uint(&read_metadata(StateTrieRootDigestBefore)),
        transactions_root: H256::from_uint(&read_metadata(TransactionTrieRootDigestBefore)),
        receipts_root: H256::from_uint(&read_metadata(ReceiptTrieRootDigestBefore)),
    };
    let trie_roots_after = TrieRoots {
        state_root: H256::from_uint(&read_metadata(StateTrieRootDigestAfter)),
        transactions_root: H256::from_uint(&read_metadata(TransactionTrieRootDigestAfter)),
        receipts_root: H256::from_uint(&read_metadata(ReceiptTrieRootDigestAfter)),
    };

    let gas_used_after = read_metadata(GlobalMetadata::BlockGasUsedAfter);
    let txn_number_after = read_metadata(GlobalMetadata::TxnNumberAfter);

    let extra_block_data = ExtraBlockData {
        checkpoint_state_trie_root: inputs.checkpoint_state_trie_root,
        txn_number_before: inputs.txn_number_before,
        txn_number_after,
        gas_used_before: inputs.gas_used_before,
        gas_used_after,
    };

    // `mem_before` and `mem_after` are initialized with an empty cap.
    // They will be set to the caps of `MemBefore` and `MemAfter`
    // respectively, while proving.
    let public_values = PublicValues {
        trie_roots_before,
        trie_roots_after,
        block_metadata: inputs.block_metadata,
        block_hashes: inputs.block_hashes,
        extra_block_data,
        registers_before,
        registers_after,
        mem_before: MemCap::default(),
        mem_after: MemCap::default(),
    };

    let (tables, final_values) = timed!(
        timing,
        "convert trace data to tables",
        state
            .traces
            .into_tables(all_stark, &memory_before, config, timing)
    );
    Ok((tables, public_values, final_values))
}

fn simulate_cpu<F: Field>(
    state: &mut GenerationState<F>,
    max_cpu_len_log: usize,
) -> anyhow::Result<(RegistersState, Option<MemoryState>)> {
    let (final_registers, mem_after) = state.run_cpu(Some(max_cpu_len_log))?;

    let pc = state.registers.program_counter;
    // Setting the values of padding rows.
    let mut row = CpuColumnsView::<F>::default();
    row.clock = F::from_canonical_usize(state.traces.clock() + 1);
    row.context = F::from_canonical_usize(state.registers.context);
    row.program_counter = F::from_canonical_usize(pc);
    row.is_kernel_mode = F::ONE;
    row.gas = F::from_canonical_u64(state.registers.gas_used);
    row.stack_len = F::from_canonical_usize(state.registers.stack_len);

    loop {
        // Padding to a power of 2.
        state.push_cpu(row);
        row.clock += F::ONE;
        if state.traces.clock().is_power_of_two() {
            break;
        }
    }

    log::info!("CPU trace padded to {} cycles", state.traces.clock());

    Ok((final_registers, mem_after))
}
