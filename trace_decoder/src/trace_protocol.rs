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
use mpt_trie::partial_trie::HashedPartialTrie;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, FromInto, TryFromInto};

use crate::{
    deserializers::ByteString,
    types::{CodeHash, HashedAccountAddr, StorageAddr, StorageVal},
    utils::hash,
};

/// Core payload needed to generate a proof for a block. Note that the scheduler
/// may need to request some additional data from the client along with this in
/// order to generate a proof.
#[derive(Debug, Deserialize, Serialize)]
pub struct BlockTrace {
    /// The trie pre-images (state & storage) in multiple possible formats.
    pub trie_pre_images: BlockTraceTriePreImages,

    /// The code_db is a map of code hashes to the actual code. This is needed
    /// to execute transactions.
    pub code_db: Option<HashMap<CodeHash, Vec<u8>>>,

    /// Traces and other info per txn. The index of the txn corresponds to the
    /// slot in this vec.
    pub txn_info: Vec<TxnInfo>,
}

/// Minimal hashed out tries needed by all txns in the block.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockTraceTriePreImages {
    /// The trie pre-image with separate state/storage tries.
    Separate(SeparateTriePreImages),
    /// The trie pre-image with combined state/storage tries.
    Combined(CombinedPreImages),
}

/// State/Storage trie pre-images that are separate.
#[derive(Debug, Deserialize, Serialize)]
pub struct SeparateTriePreImages {
    /// State trie.
    pub state: SeparateTriePreImage,
    /// Storage trie.
    pub storage: SeparateStorageTriesPreImage,
}

/// A trie pre-image where state & storage are separate.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeparateTriePreImage {
    /// Storage or state trie in a bulkier format, that can be processed faster.
    Uncompressed(TrieUncompressed),
    /// Storage or state trie format that can be processed as is, as it
    /// corresponds to the internal format.
    Direct(TrieDirect),
}

/// A trie pre-image where both state & storage are combined into one payload.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CombinedPreImages {
    /// Compact combined state and storage tries.
    pub compact: TrieCompact,
}

// TODO
/// Bulkier format that is quicker to process.
#[derive(Debug, Deserialize, Serialize)]
pub struct TrieUncompressed {}

// TODO
#[serde_as]
/// Compact representation of a trie (will likely be very close to <https://github.com/ledgerwatch/erigon/blob/devel/docs/programmers_guide/witness_formal_spec.md>)
#[derive(Debug, Deserialize, Serialize)]
pub struct TrieCompact(#[serde_as(as = "FromInto<ByteString>")] pub Vec<u8>);

// TODO
/// Trie format that is in exactly the same format of our internal trie format.
/// This is the fastest format for us to processes.
#[derive(Debug, Deserialize, Serialize)]
pub struct TrieDirect(pub HashedPartialTrie);

/// A trie pre-image where state and storage are separate.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeparateStorageTriesPreImage {
    /// A single hash map that contains all node hashes from all storage tries
    /// involved in the block. We can reconstruct the individual storage tries
    /// by the storage root hash in the state entries.
    SingleTrie(TrieUncompressed),

    /// Each storage trie is sent over in a hashmap with the hashed account
    /// address as a key.
    MultipleTries(HashMap<HashedAccountAddr, SeparateTriePreImage>),
}

/// Info specific to txns in the block.
#[derive(Debug, Deserialize, Serialize)]
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

/// Structure holding metadata for one transaction.
#[serde_as]
#[derive(Debug, Deserialize, Serialize)]
pub struct TxnMeta {
    /// Txn byte code.
    #[serde_as(as = "FromInto<ByteString>")]
    pub byte_code: Vec<u8>,

    /// Rlped bytes of the new txn value inserted into the txn trie by
    /// this txn. Note that the key is not included and this is only the rlped
    /// value of the node!
    #[serde_as(as = "FromInto<ByteString>")]
    pub new_txn_trie_node_byte: Vec<u8>,

    /// Rlped bytes of the new receipt value inserted into the receipt trie by
    /// this txn. Note that the key is not included and this is only the rlped
    /// value of the node!
    #[serde_as(as = "TryFromInto<ByteString>")]
    pub new_receipt_trie_node_byte: Vec<u8>,

    /// Gas used by this txn (Note: not cumulative gas used).
    pub gas_used: u64,
}

/// A "trace" specific to an account for a txn.
///
/// Specifically, since we can not execute the txn before proof generation, we
/// rely on a separate EVM to run the txn and supply this data for us.
#[derive(Debug, Deserialize, Serialize)]
pub struct TxnTrace {
    /// If the balance changed, then the new balance will appear here. Will be
    /// `None` if no change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<U256>,

    /// If the nonce changed, then the new nonce will appear here. Will be
    /// `None` if no change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<U256>,

    /// Account addresses that were only read by the txn.
    ///
    /// Note that if storage is written to, then it does not need to appear in
    /// this list (but is also fine if it does).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_read: Option<Vec<StorageAddr>>,

    /// Account storage addresses that were mutated by the txn along with their
    /// new value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_written: Option<HashMap<StorageAddr, StorageVal>>,

    /// Contract code that this address accessed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_usage: Option<ContractCodeUsage>,

    /// True if the account existed before this txn but self-destructed at the
    /// end of this txn.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_destructed: Option<bool>,
}

/// Contract code access type. Used by txn traces.
#[serde_as]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractCodeUsage {
    /// Contract was read.
    Read(CodeHash),

    /// Contract was created (and these are the bytes). Note that this new
    /// contract code will not appear in the [`BlockTrace`] map.
    Write(#[serde_as(as = "FromInto<ByteString>")] ByteString),
}

impl ContractCodeUsage {
    pub(crate) fn get_code_hash(&self) -> CodeHash {
        match self {
            ContractCodeUsage::Read(hash) => *hash,
            ContractCodeUsage::Write(bytes) => hash(bytes),
        }
    }
}
