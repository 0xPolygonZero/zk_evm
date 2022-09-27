use bytes::Bytes;
use keccak_hash::keccak;
use rlp::RlpStream;

use crate::partial_trie::PartialTrie;

pub type TrieHash = ethereum_types::H256;

/// A node type used for calculating the hash of a trie.
#[derive(Debug)]
enum EncodedNode {
    /// Node that is RLPed but not hashed.
    Raw(Bytes),
    /// Node that is hashed.
    Hashed([u8; 32]),
}

impl PartialTrie {
    /// Calculates the hash of a node.
    /// Since the tries within this library are not rlp encoded, this first rlp
    /// encodes each node and applies keccak256 hashing for any rlp output that
    /// is larger than 32 bytes.
    pub fn calc_hash(&self) -> TrieHash {
        let trie_hash_bytes = self.rlp_encode_and_hash_node();

        let h = match trie_hash_bytes {
            EncodedNode::Raw(b) => hash(&b),
            EncodedNode::Hashed(h) => h,
        };

        keccak_hash::H256::from_slice(&h)
    }

    fn rlp_encode_and_hash_node(&self) -> EncodedNode {
        match self {
            PartialTrie::Empty => EncodedNode::Raw(Bytes::from_static(&rlp::NULL_RLP)),
            PartialTrie::Hash(h) => {
                // TODO: Just do a move instead once we move to `H256`...
                let mut byte_buf = [0; 32];
                h.to_big_endian(byte_buf.as_mut());

                EncodedNode::Hashed(byte_buf)
            }
            PartialTrie::Branch { children, value } => {
                let mut stream = RlpStream::new_list(17);

                for c in children {
                    Self::append_to_stream(&mut stream, c.rlp_encode_and_hash_node());
                }

                match value.is_empty() {
                    false => stream.append_empty_data(),
                    true => stream.append(value),
                };

                Self::hash_bytes_if_large_enough(stream.out().into())
            }
            PartialTrie::Extension { nibbles, child } => {
                let mut stream = RlpStream::new_list(2);

                stream.append(&nibbles.to_hex_prefix_encoding(false));
                Self::append_to_stream(&mut stream, child.rlp_encode_and_hash_node());

                Self::hash_bytes_if_large_enough(stream.out().into())
            }
            PartialTrie::Leaf { nibbles, value } => {
                let hex_prefix_k = nibbles.to_hex_prefix_encoding(true);

                let mut stream = RlpStream::new_list(2);
                stream.append(&hex_prefix_k);
                stream.append(value);

                Self::hash_bytes_if_large_enough(stream.out().into())
            }
        }
    }

    fn hash_bytes_if_large_enough(bytes: Bytes) -> EncodedNode {
        match bytes.len() > 32 {
            false => EncodedNode::Raw(bytes),
            true => EncodedNode::Hashed(hash(&bytes)),
        }
    }

    fn append_to_stream(s: &mut RlpStream, node: EncodedNode) {
        match node {
            EncodedNode::Raw(b) => s.append(&b),
            EncodedNode::Hashed(h) => s.append_raw(&h, 1),
        };
    }
}

fn hash(bytes: &Bytes) -> [u8; 32] {
    keccak(bytes).0
}

#[cfg(test)]
mod tests {
    use std::{iter::once, str::FromStr, sync::Arc};

    use bytes::BufMut;
    use eth_trie::{EthTrie, MemoryDB, Trie};
    use ethereum_types::{BigEndianHash, U256};
    use rand::{rngs::StdRng, SeedableRng};

    use crate::{
        partial_trie::{Nibbles, PartialTrie},
        testing_utils::gen_u256,
        trie_builder::InsertEntry,
        trie_hashing::TrieHash,
    };

    const NULL_TRIE_HASH_STR: &str =
        "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";

    const EMPTY_BYTES_HASH_STR: &str =
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

    fn str_to_trie_hash(s: &'static str) -> TrieHash {
        TrieHash::from_uint(&U256::from(s))
    }

    /// Gets the root hash for each insert by using an established eth trie
    /// library as a ground truth.
    fn get_correct_trie_root_hashes_after_each_insert(
        entries: impl Iterator<Item = InsertEntry>,
    ) -> impl Iterator<Item = TrieHash> {
        let db = Arc::new(MemoryDB::new(true));
        let mut truth_trie = EthTrie::new(db);

        entries.map(move |e| {
            truth_trie.insert(&e.nibbles.bytes(), &e.v).unwrap();
            let h = truth_trie.root_hash().unwrap();

            // Kind of silly... Both of these types are identical except that one is
            // re-exported. Cargo is generating crate version mismatch errors. Not sure how
            // else to solve...
            ethereum_types::H256(h.0)
        })
    }

    fn get_bytes_for_dummy_account_entry(nonce: u32, balance: U256, storage_root: U256) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend(nonce.to_be_bytes());
        append_u256_to_byte_buf(&mut bytes, balance);
        append_u256_to_byte_buf(&mut bytes, storage_root);
        append_u256_to_byte_buf(&mut bytes, U256::from_str(EMPTY_BYTES_HASH_STR).unwrap());

        bytes
    }

    fn append_u256_to_byte_buf(buf: &mut Vec<u8>, v: U256) {
        let mut v_bytes = [0; 32];
        v.to_big_endian(&mut v_bytes);

        buf.put_slice(&v_bytes);
    }

    #[test]
    fn empty_hash_is_correct() {
        let trie = PartialTrie::Empty;
        assert_eq!(str_to_trie_hash(NULL_TRIE_HASH_STR), trie.calc_hash());
    }

    #[test]
    fn single_account_leaf_hash_is_correct() {
        let account_entry_key =
            Nibbles::from_str("2fe4900ed4983da6f16363c47c8ee8ee3c327829").unwrap();

        let account_entry_val_bytes = get_bytes_for_dummy_account_entry(
            1,
            9001.into(),
            U256::from_str(EMPTY_BYTES_HASH_STR).unwrap(),
        );

        let ins_entry = InsertEntry {
            nibbles: account_entry_key,
            v: account_entry_val_bytes,
        };

        let truth_val = get_correct_trie_root_hashes_after_each_insert(once(ins_entry.clone()))
            .next()
            .unwrap();
        let our_hash = PartialTrie::construct_trie_from_inserts(once(ins_entry)).calc_hash();

        assert_eq!(truth_val, our_hash);
    }

    #[test]
    fn single_leaf_hash_is_correct() {
        let mut rng = StdRng::seed_from_u64(0);
        let ins_entry = InsertEntry {
            nibbles: gen_u256(&mut rng).into(),
            v: vec![1],
        };

        let truth_val = get_correct_trie_root_hashes_after_each_insert(once(ins_entry.clone()))
            .next()
            .unwrap();
        let our_hash = PartialTrie::construct_trie_from_inserts(once(ins_entry)).calc_hash();

        assert_eq!(truth_val, our_hash);
    }
}
