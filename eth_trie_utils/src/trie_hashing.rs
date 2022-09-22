use std::iter::once;

use bytes::{BufMut, Bytes, BytesMut};
use keccak_hash::{keccak, H256};

use crate::{
    partial_trie::{Nibbles, PartialTrie},
    utils::is_even,
};

pub type TrieHash = H256;

impl PartialTrie {
    /// Calculates the hash of a node.
    /// Since the tries within this library are not rlp encoded, this first rlp
    /// encodes each node and applies keccak256 hashing for any rlp output that
    /// is larger than 32 bytes.
    pub fn calc_hash(&self) -> H256 {
        let trie_hash_bytes = self.rlp_encode_and_hash_node();
        H256::from_slice(&trie_hash_bytes)
    }

    fn rlp_encode_and_hash_node(&self) -> Bytes {
        match self {
            PartialTrie::Empty => Bytes::from_static(&rlp::EMPTY_LIST_RLP),
            PartialTrie::Hash(h) => {
                let mut byte_buf = BytesMut::new();
                h.to_big_endian(byte_buf.as_mut());
                let rlp = rlp::encode(&byte_buf).into();

                // Always at least 32 bytes long.
                hash(&rlp)
            }
            PartialTrie::Branch { children, value } => {
                let bytes_iter = children
                    .iter()
                    .map(|c| c.rlp_encode_and_hash_node())
                    .chain(once(Bytes::from_iter(value.iter().cloned())));
                let mut bytes = BytesMut::new();
                bytes.extend(bytes_iter);

                Self::rlp_encode_and_hash_if_large_enough(bytes.into())
            }
            PartialTrie::Extension { nibbles, child } => {
                let hex_prefix_k = Self::convert_nibbles_to_hex_prefix_encoding(nibbles, false);
                let mut bytes = BytesMut::new();

                bytes.put(hex_prefix_k);
                bytes.put(child.rlp_encode_and_hash_node());

                Self::rlp_encode_and_hash_if_large_enough(bytes.into())
            }
            PartialTrie::Leaf { nibbles, value } => {
                let hex_prefix_k = Self::convert_nibbles_to_hex_prefix_encoding(nibbles, true);
                let mut bytes = BytesMut::new();

                bytes.put(hex_prefix_k);
                bytes.extend(value.iter());

                Self::rlp_encode_and_hash_if_large_enough(bytes.into())
            }
        }
    }

    /// Rlp encode and hash if at least 32 bytes.
    fn rlp_encode_and_hash_if_large_enough(bytes: Bytes) -> Bytes {
        let rlp_bytes = rlp::encode(&bytes);

        match rlp_bytes.len() < 32 {
            false => rlp_bytes.into(),
            true => hash(&rlp_bytes.into()),
        }
    }

    /// Converts `Nibbles` to hex-prefix encoding.
    /// This appends an extra nibbles to the end which encodes if the node is
    /// even and if it's a leaf (terminator) or not.
    fn convert_nibbles_to_hex_prefix_encoding(n: &Nibbles, is_leaf: bool) -> Bytes {
        let num_nibbles = n.count + 1;
        let num_bytes = (num_nibbles + 1) / 2;

        let mut bytes = BytesMut::zeroed(num_bytes);

        let is_even = is_even(n.count);
        let odd_bit = match is_even {
            false => 0,
            true => 1,
        };

        let term_bit = match is_leaf {
            false => 0,
            true => 1,
        };

        let flags: u8 = odd_bit | (term_bit << 1);
        n.packed.to_big_endian(&mut bytes);

        // Invert since we are now considering the bytes with the flags at the end.
        match !is_even {
            false => bytes.put_u8(flags),
            true => bytes[num_bytes] |= flags << 4,
        }

        bytes.into()
    }
}

fn hash(bytes: &Bytes) -> Bytes {
    let hash = keccak(bytes);
    Bytes::new().slice_ref(&hash.0)
}
