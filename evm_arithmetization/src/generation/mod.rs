use std::collections::HashMap;

use anyhow::{anyhow, Context as _};
use ethereum_types::{Address, BigEndianHash, H256, U256};
use keccak_hash::keccak;
use log::log_enabled;
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
use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::generation::state::GenerationState;
use crate::generation::trie_extractor::{get_receipt_trie, get_state_trie, get_txn_trie};
use crate::memory::segments::Segment;
use crate::proof::{BlockHashes, BlockMetadata, ExtraBlockData, PublicValues, TrieRoots};
use crate::util::{h2u, u256_to_usize};
use crate::witness::memory::{MemoryAddress, MemoryChannel};

pub mod mpt;
pub(crate) mod prover_input;
pub(crate) mod rlp;
pub(crate) mod state;
mod trie_extractor;

use self::state::State;
use crate::witness::util::mem_write_log;

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
    /// Global exit roots pairs `(timestamp, root)`.
    pub global_exit_roots: Vec<(U256, H256)>,
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

pub fn tx_hash(signed_txn: &[u8]) -> anyhow::Result<H256> {
    let hash = keccak(signed_txn);
    Ok(hash)
}

impl GenerationInputs {
    pub fn tx_hash(&self) -> anyhow::Result<H256> {
        let signed_tx = self
            .signed_txn
            .as_ref()
            .context("GenerationInputs contained no signed transaction.")?
            .as_slice();
        tx_hash(signed_tx)
    }
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

fn apply_metadata_and_tries_memops<F: RichField + Extendable<D>, const D: usize>(
    state: &mut GenerationState<F>,
    inputs: &GenerationInputs,
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
        (
            GlobalMetadata::BlockBlobGasUsed,
            metadata.block_blob_gas_used,
        ),
        (
            GlobalMetadata::BlockExcessBlobGas,
            metadata.block_excess_blob_gas,
        ),
        (
            GlobalMetadata::ParentBeaconBlockRoot,
            h2u(metadata.parent_beacon_block_root),
        ),
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

    state.memory.apply_ops(&ops);
    state.traces.memory_ops.extend(ops);
}

pub(crate) fn debug_inputs(inputs: &GenerationInputs) {
    log::debug!("Input signed_txn: {:?}", &inputs.signed_txn);
    log::debug!("Input state_trie: {:?}", &inputs.tries.state_trie);
    log::debug!(
        "Input transactions_trie: {:?}",
        &inputs.tries.transactions_trie
    );
    log::debug!("Input receipts_trie: {:?}", &inputs.tries.receipts_trie);
    log::debug!("Input storage_tries: {:?}", &inputs.tries.storage_tries);
    log::debug!("Input contract_code: {:?}", &inputs.contract_code);
}

pub fn generate_traces<F: RichField + Extendable<D>, const D: usize>(
    all_stark: &AllStark<F, D>,
    inputs: GenerationInputs,
    config: &StarkConfig,
    timing: &mut TimingTree,
) -> anyhow::Result<([Vec<PolynomialValues<F>>; NUM_TABLES], PublicValues)> {
    debug_inputs(&inputs);
    let mut state = GenerationState::<F>::new(inputs.clone(), &KERNEL.code)
        .map_err(|err| anyhow!("Failed to parse all the initial prover inputs: {:?}", err))?;

    apply_metadata_and_tries_memops(&mut state, &inputs);

    let cpu_res = timed!(timing, "simulate CPU", simulate_cpu(&mut state));
    if cpu_res.is_err() {
        let _ = output_debug_tries(&state);

        cpu_res?;
    }

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

    let public_values = PublicValues {
        trie_roots_before,
        trie_roots_after,
        block_metadata: inputs.block_metadata,
        block_hashes: inputs.block_hashes,
        extra_block_data,
    };

    let tables = timed!(
        timing,
        "convert trace data to tables",
        state.traces.into_tables(all_stark, config, timing)
    );
    Ok((tables, public_values))
}

fn simulate_cpu<F: Field>(state: &mut GenerationState<F>) -> anyhow::Result<()> {
    state.run_cpu()?;

    let pc = state.registers.program_counter;
    // Setting the values of padding rows.
    let mut row = CpuColumnsView::<F>::default();
    row.clock = F::from_canonical_usize(state.traces.clock());
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

    Ok(())
}

/// Outputs the tries that have been obtained post transaction execution, as
/// they are represented in the prover's memory.
/// This will do nothing if the CPU execution failed outside of the final trie
/// root checks.
pub(crate) fn output_debug_tries<F: RichField>(state: &GenerationState<F>) -> anyhow::Result<()> {
    if !log_enabled!(log::Level::Debug) {
        return Ok(());
    }

    // Retrieve previous PC (before jumping to KernelPanic), to see if we reached
    // `perform_final_checks`. We will output debugging information on the final
    // tries only if we got a root mismatch.
    let previous_pc = state.get_registers().program_counter;

    let label = KERNEL.offset_name(previous_pc);

    if label.contains("check_state_trie")
        || label.contains("check_txn_trie")
        || label.contains("check_receipt_trie")
    {
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

    Ok(())
}

#[cfg(test)]
mod test {
    use std::str::FromStr as _;

    use anyhow::Context;
    use keccak_hash::H256;

    use crate::generation::tx_hash;

    #[test]
    fn four_tx_hash() -> anyhow::Result<()> {
        // type 0
        let legacy_txn: Vec<u8> = hex::decode("f902ed82019f850169b62d9a8305833c9477edae6a5f332605720688c7fda7476476e8f83f80b902840938b20b0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000b8cf3bc88f84a2723c12182e87b5c769a1b6f607000000000000000000000000eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0000000000000000000000001ce4f7a715a979f9bbdb2336af0d6204f7c53380000000000000000000000000bcba53e786f120fe39a71051f6bf5b4c2c5104fa0000000000000000000000000000000000000000007ac2f089d0029563794f1b000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000050000000000000000000000000799e39644f207baf37185479e0c23d0e5ed11dcc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000000010000000000000000000000001ce4f7a715a979f9bbdb2336af0d6204f7c53380000000000000000000000000b8cf3bc88f84a2723c12182e87b5c769a1b6f607000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000007a250d5630b4cf539739df2c5dacb4c659f2488d000000000000000000000000000000000000000000000000000000000000000026a036b15a66a40fffb09d63dba6214d67a50ec5d04232aa14bb4c110e62303c130da02af7397b8bef4fb36fadcedaeb0874ecd53d26a06ad760e2f179bea0851c5d59").context("Decoding failed.")?;
        let legacy_txn_hash_expected: H256 =
            H256::from_str("0x081ed7d1da9faaecb12993dea3759c9ad23a5fd5c5600022683611283ac6c0be")?;
        let legacy_txn_hash_actual: H256 = tx_hash(legacy_txn.as_slice())?;
        assert_eq!(legacy_txn_hash_expected, legacy_txn_hash_actual);

        // type 1
        let accesslist_txn: Vec<u8> = hex::decode("01f9067001828ec78501ab1bd4668306beea94507888e987257a8dde6f8afa46375cefe2cbf50480b863a50671e648b0735fc4d839469181cddf3dde4e67430000000007acaa49961a0ec3e54d0047085f17cebf8cdc29c82c693cd06c1f2778185e16ccd4de64e395cc2a60594a405d53811d3bc4766596efd80fd545a270000000000000024e3554eabd5641f905a1f90162940671e648b0735fc4d839469181cddf3dde4e6743f9014aa00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000001a00000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000004a00000000000000000000000000000000000000000000000000000000000000008a03c4cf9c63d47d18f0a83dc90ceb5fd87e60f81a67aafaf5609f450c921e744eda03c4cf9c63d47d18f0a83dc90ceb5fd87e60f81a67aafaf5609f450c921e744eea03c4cf9c63d47d18f0a83dc90ceb5fd87e60f81a67aafaf5609f450c921e744efa03c4cf9c63d47d18f0a83dc90ceb5fd87e60f81a67aafaf5609f450c921e744f0a063187d71e139eee983a88d0737447c7451979b3dbb75903c76b5fe430d36588ef8dd9429c82c693cd06c1f2778185e16ccd4de64e395ccf8c6a00000000000000000000000000000000000000000000000000000000000000006a00000000000000000000000000000000000000000000000000000000000000007a00000000000000000000000000000000000000000000000000000000000000008a00000000000000000000000000000000000000000000000000000000000000009a0000000000000000000000000000000000000000000000000000000000000000aa0000000000000000000000000000000000000000000000000000000000000000cf901a4943927fb89f34bbee63351a6340558eebf51a19fb8f9018ca0000000000000000000000000000000000000000000000000000000000000000ba0000000000000000000000000000000000000000000000000000000000000000fa00000000000000000000000000000000000000000000000000000000000000012a0000000000000000000000000000000000000000000000000000000000000001aa010d44b0bde62a9d490a5edd1503dfcf0ded66a4c66ee606adc14b078d0bd18fda0166197492d1e5f4ede4fe5a3bae992b43e273c5dd2c8314b5452a5ba38c446cba037437be2e2ee09d8cae6237d7f6c8ef17ed5c62a6541b1c64619cdc5acdbcd5ca06581f40612bdfeff1fc7e024f2d4fb0d8ca9ad109b4dd13bf17e6ff1306ab9aaa07462ac6f29a3a8bf799fb76a7136b25f3163a3d1ad6c65e8e7cfe3d00fa146fba075d6b601dfe1221e2b82174deffe01373f1d82d2a4c7b0f6a0e1a0efe25ad7aea0d13476813b99b0de93901da9d8b1625d7021304a0ad8d49e22c476fed7483057a0f236804949d526aafe0c8511209e95d7532929b3614e64bab541d3e5281952daf8dd9460594a405d53811d3bc4766596efd80fd545a270f8c6a00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000004a0000000000000000000000000000000000000000000000000000000000000003aa0000000000000000000000000000000000000000000000000000000000000003ba00d190fc5d3ec8c2cdab9f50db5100a3713fe91b91a02f95d6d19b71ca86e0166f859946b175474e89094c44da98b954eedeac495271d0ff842a0995f3b129dd3291868ddb9cf202c75cd985227d50e309847fbab0f8da403b19ca0d796a0a7dad74b169b00922b28b102a5b607b7a71f1f8749a95d6b27f351fa8cf87a94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f863a06945806c4d8be8875501d6ae87f5c4b9b74545a109810dd27c0b0ae604b64be6a0a0792aff6148a3f4f528f236857989ef699d426ca14bf6f2116eab30c342d3d9a0f762dfe765e313d39f5dd6e34e29a9ef0af51578e67f7f482bb4f8efd984976b80a09676515f4ba1f5b0b6e2a520b5f3e7cfc16240c08579c8a25323cc95fc174e0aa05fe4758e5358a7ac0884c81f52806cd0d765748bdce84bb181a7ca1457e75c6c").unwrap();
        let accesslist_txn_hash_expected: H256 =
            H256::from_str("0x2d50abc7283174efbab8b7581a2b16bd9f1b540fac2377868c5102b659881a2c")?;
        let accesslist_txn_hash_actual: H256 = tx_hash(accesslist_txn.as_slice())?;
        assert_eq!(accesslist_txn_hash_expected, accesslist_txn_hash_actual);

        // type 2
        let feemarket_txn: Vec<u8> = hex::decode("02f8d20182af3d847735940084f7aeb0ce8307a120946f1cdbbb4d53d226cf4b917bf768b94acbab616880b864f5537ede000000000000000000000000767fe9edc9e0df98e07454847909b5e959d7ca0e00000000000000000000000008dc8ffc2db71ea07537d1328b3be0799b6043960000000000000000000000000000000000000000000000077d5aebff37f80000c080a095d29381f45785f07b88d0d62cec774249f33cb49b0745aaf122e07a6d0ac415a0425440d7ba9f23d55ef15d3ac94da0807f594103a537e289c0c407b727f74578").unwrap();
        let feemarket_txn_hash_expected: H256 =
            H256::from_str("0x864ae98fa9584d40e02419b74e89ddd16f8d4de155fe3d75b184ef6a4e529ad2")?;
        let feemarket_txn_hash_actual: H256 = tx_hash(feemarket_txn.as_slice())?;
        assert_eq!(feemarket_txn_hash_expected, feemarket_txn_hash_actual);

        // type 3
        let blob_txn: Vec<u8> = hex::decode("03f9049f01830837e4843b9aca0085213f9eed7283036a2b941c479675ad559dc151f6ec7ed3fbf8cee79582b680b8a43e5aa082000000000000000000000000000000000000000000000000000000000008fff2000000000000000000000000000000000000000000000000000000000016a443000000000000000000000000e64a54e2533fd126c2e452c5fab544d80e2e4eb5000000000000000000000000000000000000000000000000000000000aafdc87000000000000000000000000000000000000000000000000000000000aafde27f902c0f8dd941c479675ad559dc151f6ec7ed3fbf8cee79582b6f8c6a00000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000001a0000000000000000000000000000000000000000000000000000000000000000aa0b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103a0360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbca0a10aa54071443520884ed767b0684edf43acec528b7da83ab38ce60126562660f90141948315177ab297ba92a06054ce80a67ed4dbd7ed3af90129a00000000000000000000000000000000000000000000000000000000000000006a00000000000000000000000000000000000000000000000000000000000000007a00000000000000000000000000000000000000000000000000000000000000009a0000000000000000000000000000000000000000000000000000000000000000aa0b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103a0360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbca0a66cc928b5edb82af9bd49922954155ab7b0942694bea4ce44661d9a873fc679a0a66cc928b5edb82af9bd49922954155ab7b0942694bea4ce44661d9a873fc67aa0f652222313e28459528d920b65115c16c04f3efc82aaedc97be59f3f3792b181f89b94e64a54e2533fd126c2e452c5fab544d80e2e4eb5f884a00000000000000000000000000000000000000000000000000000000000000004a00000000000000000000000000000000000000000000000000000000000000005a0e85fd79f89ff278fc57d40aecb7947873df9f0beac531c8f71a98f630e1eab62a07686888b19bb7b75e46bb1aa328b65150743f4899443d722f0adf8e252ccda410af8c6a0014527d555d949b3afcfa246e16eb0e0aef9e9da60b7a0266f1da43b3fd8e8cfa0016d80efa350ab1fc156b505ab619bee3f6245b8f7d4d60bf11c9d8b0105b02fa00176b14180ebfaa132142ff163eb2aaf2985af7da011d195e39fe8b0faf1e960a00134da09304a6a66b691bc48d351b976203cd419778d142f19e68e904f07a5aea00181b4581a9fc316eadc58e4d6d362e316e259643913339a3e46b7c9d742ac30a00112fa6c9dfaceaff1868ef19d01c4a1da99e6e02162fe7dacf94ec441da697701a04dfd139f20fdefc834fbdce2e120ca8ed1a4688d8843df8fc2de1df8c6d0a0f3a06ec282ea1c2c55e467425c380c17f0f8ef664d8e2de8a39b18d6c83b8d6a9afa").unwrap();
        let blob_txn_hash_expected: H256 =
            H256::from_str("0x2ea19986a6866b6efd2ac292fa8132b0bbf1fcc478560525ce43d6c300323652")?;
        let blob_txn_hash_actual: H256 = tx_hash(blob_txn.as_slice())?;
        assert_eq!(blob_txn_hash_expected, blob_txn_hash_actual);

        Ok(())
    }
}
