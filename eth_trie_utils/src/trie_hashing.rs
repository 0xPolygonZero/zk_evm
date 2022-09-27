use bytes::Bytes;
use keccak_hash::keccak;
use rlp::RlpStream;

use crate::partial_trie::PartialTrie;

pub type TrieHash = ethereum_types::H256;

/// theA node type used for calculating the hash of a trie.
#[derive(Debug)]
enum EncodedNode {
    /// Node that is RLPed but not hashed.
    Raw(Bytes),
    /// Node that is hashed.
    Hashed([u8; 32]),
}

impl PartialTrie {
    /// Calculates the hash of a node.
    /// Assumes that all leaf values are already rlp encoded.
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
            PartialTrie::Hash(h) => EncodedNode::Hashed(h.0),
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
    use keccak_hash::{KECCAK_EMPTY, KECCAK_NULL_RLP};
    use rand::{rngs::StdRng, SeedableRng};
    use rlp::Encodable;

    use crate::{
        partial_trie::{Nibbles, PartialTrie},
        testing_utils::gen_u256,
        trie_builder::InsertEntry,
        trie_hashing::{hash, TrieHash},
    };

    const NULL_TRIE_HASH_STR: &str =
        "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";

    const EMPTY_BYTES_HASH_STR: &str =
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

    #[derive(Copy, Clone, Debug)]
    struct U256Rlpable(U256);

    impl From<U256> for U256Rlpable {
        fn from(v: U256) -> Self {
            Self(v)
        }
    }

    impl Encodable for U256Rlpable {
        fn rlp_append(&self, s: &mut rlp::RlpStream) {
            let mut buf = [0; 32];
            let leading_empty_bytes = self.0.leading_zeros() as usize / 8;
            self.0.to_big_endian(&mut buf);

            // let x = &buf[leading_empty_bytes..];
            // s.append(&x);
            s.encoder().encode_value(&buf[leading_empty_bytes..]);

            // // TODO: Rough hack. Clean up before release...
            // let mut be_bytes = [0; 32];
            // self.0.to_big_endian(&mut be_bytes);

            // s.append(&get_slice_removing_any_trailing_zero_bytes_be(&
            // be_bytes));
        }
    }

    fn str_to_trie_hash(s: &'static str) -> TrieHash {
        TrieHash::from_uint(&U256::from(s))
    }

    #[derive(Debug)]
    struct AccountEntry {
        nonce: u64,
        balance: U256Rlpable,
        storage_root: Option<U256Rlpable>,
        code_hash: Option<U256Rlpable>,
    }

    impl Encodable for AccountEntry {
        fn rlp_append(&self, s: &mut rlp::RlpStream) {
            s.begin_list(4);

            s.append(&self.nonce);
            s.append(&self.balance);

            match self.storage_root {
                Some(v) => s.append(&v),
                None => s.append(&KECCAK_NULL_RLP.0.as_slice()),
            };

            match self.code_hash {
                Some(v) => s.append(&v),
                None => s.append(&KECCAK_EMPTY.0.as_slice()),
            };
        }
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

        let x = hash(&account_entry_key.bytes().into());

        let acc = AccountEntry {
            balance: U256::zero().into(),
            nonce: 0,
            code_hash: None,
            storage_root: None,
        };

        let rlp_bytes = rlp::encode(&acc);

        let ins_entry = InsertEntry {
            nibbles: Nibbles::from(U256::from(x)),
            v: rlp_bytes.into(),
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
