//! The trace protocol for sending proof information to a prover scheduler.
//!
//! Because parsing performance has a very negligible impact on overall proof
//! generation latency & throughput, the overall priority of this protocol is
//! ease of implementation for clients. The flexibility comes from giving
//! multiple ways to the client to provide the data for the protocol, where the
//! implementors can pick whichever way is the most convenient for them.
//!
//! It might not be obvious why we need traces for each txn in order to generate
//! proofs. While it's true that we could just run all the txns of a block in an
//! EVM to generate the traces ourselves, there are a few major downsides:
//! - The client is likely a full node and already has to run the txns in an EVM
//!   anyways.
//! - We want this protocol to be as agnostic as possible to the underlying
//!   chain that we're generating proofs for, and running our own EVM would
//!   likely cause us to loose this genericness.
//!
//! While it's also true that we run our own zk-EVM (plonky2) to generate
//! proofs, it's critical that we are able to generate txn proofs in parallel.
//! Since generating proofs with plonky2 is very slow, this would force us to
//! sequentialize the entire proof generation process. So in the end, it's ideal
//! if we can get this information sent to us instead.

use std::collections::HashMap;

use ethereum_types::{Address, U256};

use crate::types::{Bloom, CodeHash, HashedAccountAddress, StorageAddr, StorageVal};

/// Core payload needed to generate a proof for a block. Note that the scheduler
/// may need to request some additional data from the client along with this in
/// order to generate a proof.
#[derive(Debug)]
pub struct BlockTrace {
    /// State trie pre-image.
    pub state_trie: TriePreImage,

    /// Map of hashed account addr --> storage trie pre-image.
    pub storage_tries: StorageTriesPreImage,

    /// All contract code used by txns in the block.
    pub contract_code: BlockUsedContractCode,

    /// Traces and other info per txn. The index of the txn corresponds to the
    /// slot in this vec.
    pub txn_info: Vec<TxnInfo>,
}

/// Minimal hashed out tries needed by all txns in the block.
#[derive(Debug)]
pub enum TriePreImage {
    Uncompressed(TrieUncompressed),
    Compact(TrieCompact),
    Direct(TrieDirect),
}

// TODO
/// Bulkier format that is quicker to process.
#[derive(Debug)]
pub struct TrieUncompressed {}

// TODO
/// Compact representation of a trie (will likely be very close to https://github.com/ledgerwatch/erigon/blob/devel/docs/programmers_guide/witness_formal_spec.md)
#[derive(Debug)]
pub struct TrieCompact {}

// TODO
/// Trie format that is in exactly the same format of our internal trie format.
/// This is the fastest format for us to processes.
#[derive(Debug)]
pub struct TrieDirect {}

#[derive(Debug)]
pub enum StorageTriesPreImage {
    /// A single hash map that contains all node hashes from all storage tries
    /// involved in the block. We can reconstruct the individual storage tries
    /// by the storage root hash in the state entries.
    SingleTrie(TriePreImage),

    /// Each storage trie is sent over in a hashmap with the hashed account
    /// address as a key.
    MultipleTries(HashMap<HashedAccountAddress, TriePreImage>),
}

/// Contract code hit by txns in the block.
#[derive(Debug)]
pub enum BlockUsedContractCode {
    /// Contains a map of the code hash to the actual contract code.
    Full(HashMap<CodeHash, Vec<u8>>),

    /// Only contains the code hashes that were used. It's up to the prover
    /// generation scheduler to get the code for each hash. This is the more
    /// data efficient option.
    Digests(Vec<CodeHash>),
}

/// Info specific to txns in the block.
#[derive(Debug)]
pub struct TxnInfo {
    /// Trace data for the txn. This is used by the protocol to:
    /// - Mutate it's own trie state between txns to arrive at the correct trie
    ///   state for the start of each txn.
    /// - Create minimal partial tries needed for proof gen based on what state
    ///   the txn accesses. (eg. What trie nodes are accessed).
    pub traces: HashMap<Address, TxnTrace>,

    /// Data that is specific to the txn as a whole.
    pub meta: TxnMeta,
}

#[derive(Debug)]
pub struct TxnMeta {
    /// Txn byte code.
    pub byte_code: Vec<u8>,

    /// Rlped bytes of the new txn node inserted into the txn trie by this txn.
    pub new_txn_trie_node_byte: Vec<u8>,

    /// Rlped bytes of the new receipt node inserted into the receipt trie by
    /// this txn.
    pub new_receipt_trie_node_byte: Vec<u8>,

    /// Gas used by this txn (Note: not cumulative gas used).
    pub gas_used: u64,

    /// Bloom after txn execution.
    pub bloom: Bloom,
}

/// A "trace" specific to an account for a txn.
///
/// Specifically, since we can not execute the txn before proof generation, we
/// rely on a separate EVM to run the txn and supply this data for us.
#[derive(Debug)]
pub struct TxnTrace {
    /// If the balance changed, then the new balance will appear here.
    pub balance: Option<U256>,

    /// If the nonce changed, then the new nonce will appear here.
    pub nonce: Option<U256>,

    /// Account addresses that were only read by the txn.
    ///
    /// Note that if storage is written to, then it does not need to appear in
    /// this list (but is also fine if it does).
    pub storage_read: Option<Vec<StorageAddr>>,

    /// Account storage addresses that were mutated by the txn along with their
    /// new value.
    pub storage_written: Option<HashMap<StorageAddr, StorageVal>>,

    /// Contract code that this address accessed.
    pub code_usage: Option<ContractCodeUsage>,
}

/// Contract code access type. Used by txn traces.
#[derive(Debug)]
pub enum ContractCodeUsage {
    /// Contract was read.
    Read(CodeHash),

    /// Contract was created (and these are the bytes). Note that this new
    /// contract code will not appear in the [`BlockTrace`] map.
    Write(Vec<u8>),
}
