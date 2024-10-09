use std::collections::HashMap;
use std::fmt::Display;

use anyhow::anyhow;
use ethereum_types::{Address, BigEndianHash, H256, U256};
use keccak_hash::keccak;
use log::error;
use mpt_trie::partial_trie::{HashedPartialTrie, PartialTrie};
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::hash::hash_types::{RichField, NUM_HASH_OUT_ELTS};
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use segments::GenerationSegmentData;
use serde::{Deserialize, Serialize};
use starky::config::StarkConfig;
use GlobalMetadata::{
    ReceiptTrieRootDigestAfter, ReceiptTrieRootDigestBefore, StateTrieRootDigestAfter,
    StateTrieRootDigestBefore, TransactionTrieRootDigestAfter, TransactionTrieRootDigestBefore,
};

use crate::all_stark::{AllStark, NUM_TABLES};
use crate::cpu::columns::CpuColumnsView;
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::generation::state::{GenerationState, State};
use crate::generation::trie_extractor::{get_receipt_trie, get_state_trie, get_txn_trie};
use crate::memory::segments::{Segment, PREINITIALIZED_SEGMENTS_INDICES};
use crate::proof::{
    BlockHashes, BlockMetadata, ExtraBlockData, MemCap, PublicValues, RegistersData, TrieRoots,
};
use crate::util::{h2u, u256_to_usize};
use crate::witness::memory::{MemoryAddress, MemoryChannel, MemoryState};
use crate::witness::state::RegistersState;

pub(crate) mod linked_list;
pub mod mpt;
pub(crate) mod prover_input;
pub(crate) mod rlp;
pub(crate) mod segments;
pub(crate) mod state;
pub(crate) mod trie_extractor;

use crate::witness::util::mem_write_log;

/// Number of cycles to go after having reached the halting state. It is
/// equal to the number of cycles in `exc_stop` + 1.
pub const NUM_EXTRA_CYCLES_AFTER: usize = 82;
/// Number of cycles to go before starting the execution: it is the number of
/// cycles in `init`.
pub const NUM_EXTRA_CYCLES_BEFORE: usize = 64;
/// Memory values used to initialize `MemBefore`.
pub type MemBeforeValues = Vec<(MemoryAddress, U256)>;

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorWithTries<E = anyhow::Error> {
    pub inner: E,
    pub tries: Option<DebugOutputTries>,
}
impl<E: Display> Display for ErrorWithTries<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

impl<E: std::error::Error> std::error::Error for ErrorWithTries<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

impl<E> ErrorWithTries<E> {
    pub fn new(inner: E, tries: Option<DebugOutputTries>) -> Self {
        Self { inner, tries }
    }
}

/// Inputs needed for trace generation.
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(bound = "")]
pub struct GenerationInputs<F: RichField> {
    /// The index of the transaction being proven within its block.
    pub txn_number_before: U256,
    /// The cumulative gas used through the execution of all transactions prior
    /// the current one.
    pub gas_used_before: U256,
    /// The cumulative gas used after the execution of the current transaction.
    /// The exact gas used by the current transaction is `gas_used_after` -
    /// `gas_used_before`.
    pub gas_used_after: U256,

    /// A batch of individually RLP-encoded transactions, which may be empty for
    /// dummy payloads.
    pub signed_txns: Vec<Vec<u8>>,
    /// Target address for the base fee to be 'burnt', if there is one. If
    /// `None`, then the base fee is directly burnt.
    ///
    /// Note: this is only used  when feature `cdk_erigon` is activated.
    pub burn_addr: Option<Address>,
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

    /// Consolidated previous block hashes, at the checkpoint block.
    pub checkpoint_consolidated_hash: [F; NUM_HASH_OUT_ELTS],

    /// Mapping between smart contract code hashes and the contract byte code.
    /// All account smart contracts that are invoked will have an entry present.
    pub contract_code: HashMap<H256, Vec<u8>>,

    /// Information contained in the block header.
    pub block_metadata: BlockMetadata,

    /// The hash of the current block, and a list of the 256 previous block
    /// hashes.
    pub block_hashes: BlockHashes,

    /// The global exit root along with the l1blockhash to write to the GER
    /// manager.
    ///
    /// This is specific to `cdk-erigon`.
    pub ger_data: Option<(H256, H256)>,
}

/// A lighter version of [`GenerationInputs`], which have been trimmed
/// post pre-initialization processing.
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(bound = "")]
pub struct TrimmedGenerationInputs<F: RichField> {
    pub trimmed_tries: TrimmedTrieInputs,
    /// The index of the first transaction in this payload being proven within
    /// its block.
    pub txn_number_before: U256,
    /// The cumulative gas used through the execution of all transactions prior
    /// the current ones.
    pub gas_used_before: U256,
    /// The cumulative gas used after the execution of the current batch of
    /// transactions. The exact gas used by the current batch of transactions
    /// is `gas_used_after` - `gas_used_before`.
    pub gas_used_after: U256,

    /// The list of txn hashes contained in this batch.
    pub txn_hashes: Vec<H256>,

    /// Expected trie roots before these transactions are executed.
    pub trie_roots_before: TrieRoots,
    /// Expected trie roots after these transactions are executed.
    pub trie_roots_after: TrieRoots,

    /// State trie root of the checkpoint block.
    /// This could always be the genesis block of the chain, but it allows a
    /// prover to continue proving blocks from certain checkpoint heights
    /// without requiring proofs for blocks past this checkpoint.
    pub checkpoint_state_trie_root: H256,

    /// Consolidated previous block hashes, at the checkpoint block.
    pub checkpoint_consolidated_hash: [F; NUM_HASH_OUT_ELTS],

    /// Mapping between smart contract code hashes and the contract byte code.
    /// All account smart contracts that are invoked will have an entry present.
    pub contract_code: HashMap<H256, Vec<u8>>,

    /// Information contained in the block header.
    pub block_metadata: BlockMetadata,

    /// Address where the burnt fees are stored. Only used if the `cfg_erigon`
    /// feature is activated.
    pub burn_addr: Option<Address>,

    /// The hash of the current block, and a list of the 256 previous block
    /// hashes.
    pub block_hashes: BlockHashes,
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

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct TrimmedTrieInputs {
    /// A partial version of the state trie prior to these transactions. It
    /// should include all nodes that will be accessed by these
    /// transactions.
    pub state_trie: HashedPartialTrie,
    /// A partial version of each storage trie prior to these transactions. It
    /// should include all storage tries, and nodes therein, that will be
    /// accessed by these transactions.
    pub storage_tries: Vec<(H256, HashedPartialTrie)>,
}

impl TrieInputs {
    pub(crate) fn trim(&self) -> TrimmedTrieInputs {
        TrimmedTrieInputs {
            state_trie: self.state_trie.clone(),
            storage_tries: self.storage_tries.clone(),
        }
    }
}
impl<F: RichField> GenerationInputs<F> {
    /// Outputs a trimmed version of the `GenerationInputs`, that do not contain
    /// the fields that have already been processed during pre-initialization,
    /// namely: the input tries, the signed transaction, and the withdrawals.
    pub(crate) fn trim(&self) -> TrimmedGenerationInputs<F> {
        let txn_hashes = self
            .signed_txns
            .iter()
            .map(|tx_bytes| keccak(&tx_bytes[..]))
            .collect();

        TrimmedGenerationInputs {
            trimmed_tries: self.tries.trim(),
            txn_number_before: self.txn_number_before,
            gas_used_before: self.gas_used_before,
            gas_used_after: self.gas_used_after,
            txn_hashes,
            trie_roots_before: TrieRoots {
                state_root: self.tries.state_trie.hash(),
                transactions_root: self.tries.transactions_trie.hash(),
                receipts_root: self.tries.receipts_trie.hash(),
            },
            trie_roots_after: self.trie_roots_after.clone(),
            checkpoint_state_trie_root: self.checkpoint_state_trie_root,
            checkpoint_consolidated_hash: self.checkpoint_consolidated_hash,
            contract_code: self.contract_code.clone(),
            burn_addr: self.burn_addr,
            block_metadata: self.block_metadata.clone(),
            block_hashes: self.block_hashes.clone(),
        }
    }
}

/// Post transaction execution tries retrieved from the prover's memory.
/// Used primarily for error debugging in case of a failed execution.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DebugOutputTries {
    pub state_trie: HashedPartialTrie,
    pub transaction_trie: HashedPartialTrie,
    pub receipt_trie: HashedPartialTrie,
}

fn apply_metadata_and_tries_memops<F: RichField + Extendable<D>, const D: usize>(
    state: &mut GenerationState<F>,
    inputs: &TrimmedGenerationInputs<F>,
    registers_before: &RegistersData,
    registers_after: &RegistersData,
) {
    let metadata = &inputs.block_metadata;
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
        #[cfg(feature = "eth_mainnet")]
        (
            GlobalMetadata::BlockBlobGasUsed,
            metadata.block_blob_gas_used,
        ),
        #[cfg(feature = "eth_mainnet")]
        (
            GlobalMetadata::BlockExcessBlobGas,
            metadata.block_excess_blob_gas,
        ),
        #[cfg(feature = "eth_mainnet")]
        (
            GlobalMetadata::ParentBeaconBlockRoot,
            h2u(metadata.parent_beacon_block_root),
        ),
        (GlobalMetadata::BlockGasUsedBefore, inputs.gas_used_before),
        (GlobalMetadata::BlockGasUsedAfter, inputs.gas_used_after),
        (GlobalMetadata::TxnNumberBefore, inputs.txn_number_before),
        (
            GlobalMetadata::TxnNumberAfter,
            inputs.txn_number_before + inputs.txn_hashes.len(),
        ),
        (
            GlobalMetadata::StateTrieRootDigestBefore,
            h2u(inputs.trie_roots_before.state_root),
        ),
        (
            GlobalMetadata::TransactionTrieRootDigestBefore,
            h2u(inputs.trie_roots_before.transactions_root),
        ),
        (
            GlobalMetadata::ReceiptTrieRootDigestBefore,
            h2u(inputs.trie_roots_before.receipts_root),
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
        #[cfg(feature = "cdk_erigon")]
        (
            GlobalMetadata::BurnAddr,
            inputs
                .burn_addr
                .map_or_else(U256::max_value, |addr| U256::from_big_endian(&addr.0)),
        ),
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

pub(crate) fn debug_inputs<F: RichField>(inputs: &GenerationInputs<F>) {
    log::debug!("Input signed_txns: {:?}", &inputs.signed_txns);
    log::debug!("Input state_trie: {:?}", &inputs.tries.state_trie);
    log::debug!(
        "Input transactions_trie: {:?}",
        &inputs.tries.transactions_trie
    );
    log::debug!("Input receipts_trie: {:?}", &inputs.tries.receipts_trie);
    log::debug!("Input storage_tries: {:?}", &inputs.tries.storage_tries);
    log::debug!("Input contract_code: {:?}", &inputs.contract_code);
}

fn initialize_kernel_code_and_shift_table(memory: &mut MemoryState) {
    let mut code_addr = MemoryAddress::new(0, Segment::Code, 0);
    for &byte in &KERNEL.code {
        memory.set(code_addr, U256::from(byte));
        code_addr.increment();
    }

    let mut shift_addr = MemoryAddress::new(0, Segment::ShiftTable, 0);
    let mut shift_val = U256::one();
    for _ in 0..256 {
        memory.set(shift_addr, shift_val);
        shift_addr.increment();
        shift_val <<= 1;
    }
}

/// Returns the memory addresses and values that should comprise the state at
/// the start of the segment's execution.
/// Ignores zero values in non-preinitialized segments.
fn get_all_memory_address_and_values(memory_before: &MemoryState) -> Vec<(MemoryAddress, U256)> {
    let mut res = vec![];
    for (ctx_idx, ctx) in memory_before.contexts.iter().enumerate() {
        for (segment_idx, segment) in ctx.segments.iter().enumerate() {
            for (virt, value) in segment.content.iter().enumerate() {
                if let &Some(val) = value {
                    // We skip zero values in non-preinitialized segments.
                    if !val.is_zero() || PREINITIALIZED_SEGMENTS_INDICES.contains(&segment_idx) {
                        res.push((
                            MemoryAddress {
                                context: ctx_idx,
                                segment: segment_idx,
                                virt,
                            },
                            val,
                        ));
                    }
                }
            }
        }
    }
    res
}

pub struct TablesWithPVs<F: RichField> {
    pub tables: [Vec<PolynomialValues<F>>; NUM_TABLES],
    pub use_keccak_tables: bool,
    pub public_values: PublicValues<F>,
}

pub fn generate_traces<F: RichField + Extendable<D>, const D: usize>(
    all_stark: &AllStark<F, D>,
    inputs: &TrimmedGenerationInputs<F>,
    config: &StarkConfig,
    segment_data: &mut GenerationSegmentData,
    timing: &mut TimingTree,
) -> anyhow::Result<TablesWithPVs<F>> {
    let mut state = GenerationState::<F>::new_with_segment_data(inputs, segment_data)
        .map_err(|err| anyhow!("Failed to parse all the initial prover inputs: {:?}", err))?;

    initialize_kernel_code_and_shift_table(&mut segment_data.memory);

    // Retrieve initial memory addresses and values.
    let actual_mem_before = get_all_memory_address_and_values(&segment_data.memory);

    // Initialize the state with the one at the end of the
    // previous segment execution, if any.
    let GenerationSegmentData {
        max_cpu_len_log,
        registers_before,
        registers_after,
        ..
    } = segment_data;

    for &(address, val) in &actual_mem_before {
        state.memory.set(address, val);
    }

    let registers_before: RegistersData = RegistersData::from(*registers_before);
    let registers_after: RegistersData = RegistersData::from(*registers_after);
    apply_metadata_and_tries_memops(&mut state, inputs, &registers_before, &registers_after);

    timed!(
        timing,
        "simulate CPU",
        simulate_cpu(&mut state, *max_cpu_len_log)
    )?;

    let trace_lengths = state.traces.get_lengths();

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
        checkpoint_consolidated_hash: inputs.checkpoint_consolidated_hash,
        txn_number_before: inputs.txn_number_before,
        txn_number_after,
        gas_used_before: inputs.gas_used_before,
        gas_used_after,
    };

    let burn_addr = match cfg!(feature = "cdk_erigon") {
        true => {
            if let Some(burn_addr) = inputs.burn_addr {
                Some(U256::from_big_endian(&burn_addr.0))
            } else {
                Some(U256::MAX)
            }
        }
        false => None,
    };

    // `mem_before` and `mem_after` are initialized with an empty cap.
    // They will be set to the caps of `MemBefore` and `MemAfter`
    // respectively, while proving.
    let public_values = PublicValues {
        trie_roots_before,
        trie_roots_after,
        burn_addr,
        block_metadata: inputs.block_metadata.clone(),
        block_hashes: inputs.block_hashes.clone(),
        extra_block_data,
        registers_before,
        registers_after,
        mem_before: MemCap::default(),
        mem_after: MemCap::default(),
    };

    let use_keccak_tables = !state.traces.keccak_inputs.is_empty();

    let tables = timed!(
        timing,
        "convert trace data to tables",
        state.traces.into_tables(
            all_stark,
            &actual_mem_before,
            state.stale_contexts,
            trace_lengths,
            config,
            timing
        )
    );

    Ok(TablesWithPVs {
        tables,
        use_keccak_tables,
        public_values,
    })
}

fn simulate_cpu<F: RichField>(
    state: &mut GenerationState<F>,
    max_cpu_len_log: Option<usize>,
) -> anyhow::Result<(RegistersState, Option<MemoryState>)> {
    let (final_registers, mem_after) = state.run_cpu(max_cpu_len_log)?;

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

/// Collects the tries that have been obtained post transaction execution, as
/// they are represented in the prover's memory.
pub(crate) fn collect_debug_tries<F: RichField>(
    state: &GenerationState<F>,
) -> Option<DebugOutputTries> {
    let state_trie_ptr = u256_to_usize(
        state
            .memory
            .read_global_metadata(GlobalMetadata::StateTrieRoot),
    )
    .inspect_err(|e| error!("failed to retrieve state trie pointer: {e:?}"))
    .ok()?;

    let state_trie = get_state_trie::<HashedPartialTrie>(&state.memory, state_trie_ptr)
        .inspect_err(|e| error!("unable to retrieve state trie for debugging purposes: {e:?}"))
        .ok()?;

    let txn_trie_ptr = u256_to_usize(
        state
            .memory
            .read_global_metadata(GlobalMetadata::TransactionTrieRoot),
    )
    .inspect_err(|e| error!("failed to retrieve transactions trie pointer: {e:?}"))
    .ok()?;
    let transaction_trie = get_txn_trie::<HashedPartialTrie>(&state.memory, txn_trie_ptr)
        .inspect_err(|e| {
            error!("unable to retrieve transaction trie for debugging purposes: {e:?}",)
        })
        .ok()?;

    let receipt_trie_ptr = u256_to_usize(
        state
            .memory
            .read_global_metadata(GlobalMetadata::ReceiptTrieRoot),
    )
    .inspect_err(|e| error!("failed to retrieve receipts trie pointer: {e:?}"))
    .ok()?;
    let receipt_trie = get_receipt_trie::<HashedPartialTrie>(&state.memory, receipt_trie_ptr)
        .inspect_err(|e| error!("unable to retrieve receipt trie for debugging purposes: {e:?}"))
        .ok()?;

    Some(DebugOutputTries {
        state_trie,
        transaction_trie,
        receipt_trie,
    })
}
