use bytes::Bytes;
use eth_trie_utils::nibbles::Nibbles;
use ethereum_types::{H256, U256};
use plonky2_evm::{
    generation::{mpt::LogRlp, GenerationInputs},
    proof::{BlockHashes, BlockMetadata, TrieRoots},
};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use rlp_derive::{RlpDecodable, RlpEncodable};
use serde::{Deserialize, Serialize};

use crate::proof_gen_types::ProofBeforeAndAfterDeltas;

pub type BlockHeight = u64;
pub type Bloom = [U256; 8];
pub type CodeHash = H256;
pub type HashedAccountAddr = H256;
pub type HashedNodeAddr = H256;
pub type HashedStorageAddr = H256;
pub type HashedStorageAddrNibbles = Nibbles;
pub type StorageAddr = H256;
pub type StorageAddrNibbles = H256;
pub type StorageVal = U256;
pub type TrieRootHash = H256;
pub type TxnIdx = usize;

pub trait CodeHashResolveFunc = Fn(&CodeHash) -> Vec<u8>;

// 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
pub(crate) const EMPTY_CODE_HASH: H256 = H256([
    197, 210, 70, 1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202,
    130, 39, 59, 123, 250, 216, 4, 93, 133, 164, 112,
]);

/// 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
pub(crate) const EMPTY_TRIE_HASH: H256 = H256([
    86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248, 110, 91, 72, 224, 27, 153,
    108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33,
]);

pub(crate) const EMPTY_ACCOUNT_BYTES_RLPED: [u8; 70] = [
    248, 68, 128, 128, 160, 86, 232, 31, 23, 27, 204, 85, 166, 255, 131, 69, 230, 146, 192, 248,
    110, 91, 72, 224, 27, 153, 108, 173, 192, 1, 98, 47, 181, 227, 99, 180, 33, 160, 197, 210, 70,
    1, 134, 247, 35, 60, 146, 126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59,
    123, 250, 216, 4, 93, 133, 164, 112,
];

// This is just `rlp(0)`.
pub(crate) const ZERO_STORAGE_SLOT_VAL_RLPED: [u8; 1] = [128];

/// An `IR` (Intermediate Representation) for a given txn in a block that we can
/// use to generate a proof for that txn.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TxnProofGenIR {
    pub txn_idx: TxnIdx,
    pub gen_inputs: GenerationInputs,
}

/// Other data that is needed for proof gen.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OtherBlockData {
    pub b_data: BlockLevelData,
    pub genesis_state_trie_root: TrieRootHash,
}

/// Data that is specific to a block and is constant for all txns in a given
/// block.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BlockLevelData {
    pub b_meta: BlockMetadata,
    pub b_hashes: BlockHashes,
}
impl TxnProofGenIR {
    pub fn b_height(&self) -> BlockHeight {
        self.gen_inputs.block_metadata.block_number.as_u64()
    }

    pub fn txn_idx(&self) -> TxnIdx {
        self.txn_idx
    }

    pub fn deltas(&self) -> ProofBeforeAndAfterDeltas {
        ProofBeforeAndAfterDeltas {
            gas_used_before: self.gen_inputs.gas_used_before,
            gas_used_after: self.gen_inputs.gas_used_after,
        }
    }

    /// Creates a dummy proof, corresponding to no actual transaction.
    ///
    /// These can be used to pad a block if the number of transactions in the
    /// block is below `2`. Dummy proofs will always be executed at the start
    /// of a block.
    pub fn create_dummy(b_height: BlockHeight) -> Self {
        let trie_roots_after = TrieRoots {
            state_root: EMPTY_TRIE_HASH,
            transactions_root: EMPTY_TRIE_HASH,
            receipts_root: EMPTY_TRIE_HASH,
        };

        let block_metadata = BlockMetadata {
            block_number: b_height.into(),
            ..Default::default()
        };

        let gen_inputs = GenerationInputs {
            trie_roots_after,
            block_metadata,
            ..Default::default()
        };

        Self {
            txn_idx: 0,
            gen_inputs,
        }
    }

    /// Copy relevant fields of the `TxnProofGenIR` to a new `TxnProofGenIR`
    /// with a different `b_height`.
    ///
    /// This can be used to pad a block if there is only one transaction in the
    /// block. Block proofs need a minimum of two transactions. Dummy proofs
    /// will always be executed at the start of a block.
    pub fn dummy_with_at(&self, b_height: BlockHeight) -> Self {
        let mut dummy = Self::create_dummy(b_height);

        dummy.gen_inputs.gas_used_before = self.gen_inputs.gas_used_after;
        dummy.gen_inputs.gas_used_after = self.gen_inputs.gas_used_after;

        dummy.gen_inputs.trie_roots_after = self.gen_inputs.trie_roots_after.clone();
        dummy
    }
}

// TODO: Replace with enum...
pub type TxnType = u8;

#[derive(Clone, Debug)]
pub enum ReceiptRlp {
    Legacy(ReceiptRlpCommon),
    Other(TxnType, ReceiptRlpCommon),
}

impl ReceiptRlp {
    pub fn bloom(&self) -> &Bytes {
        match self {
            ReceiptRlp::Legacy(c) => &c.bloom,
            ReceiptRlp::Other(_, c) => &c.bloom,
        }
    }
}

impl Encodable for ReceiptRlp {
    fn rlp_append(&self, s: &mut RlpStream) {
        let common = match self {
            ReceiptRlp::Legacy(c) => c,
            ReceiptRlp::Other(t_byte, c) => {
                s.append(t_byte);
                c
            }
        };

        s.append(common);
    }
}

// TODO: Make a bit nicer...
impl Decodable for ReceiptRlp {
    fn decode(rlp: &Rlp) -> Result<Self, DecoderError> {
        println!("-RLP- {}", rlp);

        let list_rlp = rlp.as_list()?;

        Ok(match list_rlp.len() {
            4 => Self::Legacy(rlp::decode(rlp.as_raw())?),
            5 => Self::Other(list_rlp[0], rlp::decode(&list_rlp[1..])?),
            _ => panic!("Malformed receipt rlp!"),
        })
    }
}

#[derive(Clone, Debug, RlpDecodable, RlpEncodable)]
pub struct ReceiptRlpCommon {
    pub status: bool,
    pub cum_gas_used: U256,
    pub bloom: Bytes,
    pub logs: Vec<LogRlp>,
}
