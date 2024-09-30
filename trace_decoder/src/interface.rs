//! Public types for this crate.
//!
//! These are all in one place because they're about to be heavily refactored in [#401](https://github.com/0xPolygonZero/zk_evm/issues/401).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use ethereum_types::{Address, U256};
use evm_arithmetization::proof::{BlockHashes, BlockMetadata};
use evm_arithmetization::ConsolidatedHash;
use evm_arithmetization::{
    generation::InputStateTrie,
    proof::{BlockHashes, BlockMetadata},
};
use keccak_hash::H256;
use mpt_trie::partial_trie::HashedPartialTrie;
use serde::{Deserialize, Serialize};

use crate::Field;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum EvmType {
    Type1,
    Type2,
}

/// Core payload needed to generate proof for a block.
/// Additional data retrievable from the blockchain node (using standard ETH RPC
/// API) may be needed for proof generation.
///
/// The trie preimages are the hashed partial tries at the
/// start of the block. A [TxnInfo] contains all the transaction data
/// necessary to generate an IR.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockTrace {
    /// The state and storage trie pre-images (i.e. the tries before
    /// the execution of the current block) in multiple possible formats.
    pub trie_pre_images: BlockTraceTriePreImages,

    /// A collection of contract code.
    /// This will be accessed by its hash internally.
    #[serde(default)]
    pub code_db: BTreeSet<Vec<u8>>,

    /// Traces and other info per transaction. The index of the transaction
    /// within the block corresponds to the slot in this vec.
    pub txn_info: Vec<TxnInfo>,
}

/// Minimal hashed out tries needed by all txns in the block.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockTraceTriePreImages {
    /// The trie pre-image with separate state/storage tries.
    Separate(SeparateTriePreImages),
    /// The trie pre-image with combined state/storage tries.
    Combined(CombinedPreImages),
}

/// State/Storage trie pre-images that are separate.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SeparateTriePreImages {
    /// State trie.
    pub state: SeparateStateTriePreImage,
    /// Storage trie.
    pub storage: Option<SeparateStorageTriesPreImage>,
}

/// A trie pre-image where state & storage are separate.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeparateStateTriePreImage {
    /// Storage or state trie format that can be processed as is, as it
    /// corresponds to the internal format.
    Direct(InputStateTrie),
}

/// A trie pre-image where both state & storage are combined into one payload.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct CombinedPreImages {
    pub evm_type: EvmType,
    /// Compact combined state and storage tries.
    #[serde(with = "crate::hex")]
    pub compact: Vec<u8>,
}

/// A trie pre-image where state and storage are separate.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SeparateStorageTriesPreImage {
    /// Each storage trie is sent over in a hashmap with the hashed account
    /// address as a key.
    MultipleTries(HashMap<H256, HashedPartialTrie>),
}

/// Info specific to txns in the block.
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct TxnInfo {
    /// Trace data for the txn. This is used by the protocol to:
    /// - Mutate it's own trie state between txns to arrive at the correct trie
    ///   state for the start of each txn.
    /// - Create minimal partial tries needed for proof gen based on what state
    ///   the txn accesses. (eg. What trie nodes are accessed).
    pub traces: BTreeMap<Address, TxnTrace>,

    /// Data that is specific to the txn as a whole.
    pub meta: TxnMeta,
}

/// Structure holding metadata for one transaction.
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub struct TxnMeta {
    /// Txn byte code. This is also the raw RLP bytestring inserted into the txn
    /// trie by this txn. Note that the key is not included and this is only
    /// the rlped value of the node!
    #[serde(with = "crate::hex")]
    pub byte_code: Vec<u8>,

    /// Rlped bytes of the new receipt value inserted into the receipt trie by
    /// this txn. Note that the key is not included and this is only the rlped
    /// value of the node!
    #[serde(with = "crate::hex")]
    pub new_receipt_trie_node_byte: Vec<u8>,

    /// Gas used by this txn (Note: not cumulative gas used).
    pub gas_used: u64,
}

/// A "trace" specific to an account for a txn.
///
/// Specifically, since we can not execute the txn before proof generation, we
/// rely on a separate EVM to run the txn and supply this data for us.
#[derive(Clone, Debug, Deserialize, Serialize, Default, PartialEq)]
pub struct TxnTrace {
    /// If the balance changed, then the new balance will appear here. Will be
    /// `None` if no change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub balance: Option<U256>,

    /// If the nonce changed, then the new nonce will appear here. Will be
    /// `None` if no change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<U256>,

    /// <code>hash([Address])</code> of storages read by the transaction.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub storage_read: BTreeSet<H256>,

    /// <code>hash([Address])</code> of storages written by the transaction,
    /// with their new value.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub storage_written: BTreeMap<H256, U256>,

    /// Contract code that this account has accessed or created
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_usage: Option<ContractCodeUsage>,

    /// True if the account got self-destructed at the end of this txn.
    #[serde(default, skip_serializing_if = "is_false")]
    pub self_destructed: bool,
}

fn is_false(b: &bool) -> bool {
    !b
}

/// Contract code access type. Used by txn traces.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ContractCodeUsage {
    /// Contract was read.
    Read(H256),

    /// Contract was created (and these are the bytes). Note that this new
    /// contract code will not appear in the [`BlockTrace`] map.
    Write(#[serde(with = "crate::hex")] Vec<u8>),
}

/// Other data that is needed for proof gen.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OtherBlockData {
    /// Data that is specific to the block.
    pub b_data: BlockLevelData,
    /// State trie root hash at the checkpoint.
    pub checkpoint_state_trie_root: H256,
    /// Consolidated block hashes at the checkpoint.
    pub checkpoint_consolidated_hash: ConsolidatedHash,
    /// Address where the burnt fees are stored.
    ///
    /// Only used if the `cfg_erigon` feature is activated.
    pub burn_addr: Option<Address>,
    /// The global exit root along with the l1blockhash to write to the GER
    /// manager.
    ///
    /// Only used if the `cfg_erigon` feature is activated.
    pub ger_data: Option<(H256, H256)>,
}

/// Data that is specific to a block and is constant for all txns in a given
/// block.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockLevelData {
    /// All block data excluding block hashes and withdrawals.
    pub b_meta: BlockMetadata,
    /// Block hashes: the previous 256 block hashes and the current block hash.
    pub b_hashes: BlockHashes,
    /// Block withdrawal addresses and values.
    pub withdrawals: Vec<(Address, U256)>,
}
