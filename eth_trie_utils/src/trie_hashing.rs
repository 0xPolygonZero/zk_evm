use bytes::Bytes;
use ethereum_types::H256;
use keccak_hash::keccak;
use rlp::RlpStream;

use crate::partial_trie::PartialTrie;

/// The node type used for calculating the hash of a trie.
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
    pub fn calc_hash(&self) -> H256 {
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

                for c in children.iter() {
                    Self::append_to_stream(&mut stream, c.rlp_encode_and_hash_node());
                }

                match value.is_empty() {
                    false => stream.append(value),
                    true => stream.append_empty_data(),
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
        match bytes.len() >= 32 {
            false => EncodedNode::Raw(bytes),
            true => EncodedNode::Hashed(hash(&bytes)),
        }
    }

    fn append_to_stream(s: &mut RlpStream, node: EncodedNode) {
        match node {
            EncodedNode::Raw(b) => s.append_raw(&b, 1),
            EncodedNode::Hashed(h) => s.append(&h.as_ref()),
        };
    }
}

fn hash(bytes: &Bytes) -> [u8; 32] {
    keccak(bytes).0
}

#[cfg(test)]
mod tests {
    use std::{fs, iter::once, str::FromStr, sync::Arc};

    use bytes::Bytes;
    use eth_trie::{EthTrie, MemoryDB, Trie};
    use ethereum_types::{H160, H256, U256};
    use rlp::Encodable;
    use rlp_derive::RlpEncodable;
    use serde::Deserialize;

    use crate::{
        partial_trie::{Nibble, PartialTrie, WrappedNode},
        testing_utils::{
            common_setup, entry, generate_n_random_fixed_even_nibble_padded_trie_entries,
            generate_n_random_fixed_trie_entries, generate_n_random_variable_keys, large_entry,
            TestInsertValEntry,
        },
        trie_hashing::hash,
    };

    const PYEVM_TRUTH_VALS_JSON_PATH: &str = "test_data/pyevm_account_ground_truth.json";
    const NUM_INSERTS_FOR_ETH_TRIE_CRATE_MASSIVE_TEST: usize = 1000;
    const NODES_PER_BRANCH_FOR_HASH_REPLACEMENT_TEST: usize = 200;

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

            s.encoder().encode_value(&buf[leading_empty_bytes..]);
        }
    }

    /// Eth test account entry. As a separate struct to allow easy RLP encoding.
    #[derive(Debug, RlpEncodable)]
    struct AccountEntry {
        nonce: u64,
        balance: U256,
        storage_root: H256,
        code_hash: H256,
    }

    /// Raw deserialized JSON parsed from the PyEVM output.
    #[derive(Debug, Deserialize)]
    struct PyEvmTrueValEntryRaw {
        address: String,
        balance: String,
        nonce: u64,
        code_hash: String,
        storage_root: String,
        final_state_root: String,
    }

    impl From<PyEvmTrueValEntryRaw> for PyEvmTrueValEntry {
        fn from(r: PyEvmTrueValEntryRaw) -> Self {
            PyEvmTrueValEntry {
                account_key: H256(hash(&Bytes::copy_from_slice(
                    H160::from_str(&r.address).unwrap().as_bytes(),
                ))),
                balance: U256::from_str(&r.balance).unwrap(),
                nonce: r.nonce,
                code_hash: H256::from_str(&r.code_hash).unwrap(),
                storage_root: H256::from_str(&r.storage_root).unwrap(),
                final_state_root: H256::from_str(&r.final_state_root).unwrap(),
            }
        }
    }

    /// Parsed PyEVM output in a format that the tests can use.
    #[derive(Clone, Debug)]
    struct PyEvmTrueValEntry {
        account_key: H256,
        balance: U256,
        nonce: u64,
        code_hash: H256,
        storage_root: H256,
        final_state_root: H256,
    }

    impl PyEvmTrueValEntry {
        fn account_entry(&self) -> AccountEntry {
            AccountEntry {
                nonce: self.nonce,
                balance: self.balance,
                storage_root: self.storage_root,
                code_hash: self.code_hash,
            }
        }
    }

    // Inefficient, but good enough for tests.
    fn load_pyevm_truth_vals() -> Vec<PyEvmTrueValEntry> {
        let bytes = fs::read(PYEVM_TRUTH_VALS_JSON_PATH).unwrap();
        let raw = serde_json::from_slice::<Vec<PyEvmTrueValEntryRaw>>(&bytes).unwrap();

        raw.into_iter().map(|r| r.into()).collect()
    }

    fn create_truth_trie() -> EthTrie<MemoryDB> {
        let db = Arc::new(MemoryDB::new(true));
        EthTrie::new(db)
    }

    /// Gets the root hash for each insert by using an established eth trie
    /// library as a ground truth.
    fn get_lib_trie_root_hashes_after_each_insert(
        entries: impl Iterator<Item = TestInsertValEntry>,
    ) -> impl Iterator<Item = H256> {
        let mut truth_trie = create_truth_trie();

        entries.map(move |(k, v)| {
            truth_trie.insert(&k.bytes_be(), &v).unwrap();
            let h = truth_trie.root_hash().unwrap();

            // Kind of silly... Both of these types are identical except that one is
            // re-exported. Cargo is generating crate version mismatch errors. Not sure how
            // else to solve...
            ethereum_types::H256(h.0)
        })
    }

    fn get_root_hashes_for_our_trie_after_each_insert(
        entries: impl Iterator<Item = TestInsertValEntry>,
    ) -> impl Iterator<Item = H256> {
        let mut trie = PartialTrie::Empty;

        entries.map(move |(k, v)| {
            trie.insert(k, v);
            trie.calc_hash()
        })
    }

    fn insert_entries_into_our_and_lib_tries_and_assert_equal_hashes(
        entries: &[TestInsertValEntry],
    ) {
        let truth_hashes = get_lib_trie_root_hashes_after_each_insert(entries.iter().cloned());
        let our_hashes = get_root_hashes_for_our_trie_after_each_insert(entries.iter().cloned());

        for (our_h, lib_h) in our_hashes.zip(truth_hashes) {
            assert_eq!(our_h, lib_h)
        }
    }

    #[test]
    fn empty_hash_is_correct() {
        common_setup();

        let trie = PartialTrie::Empty;
        assert_eq!(keccak_hash::KECCAK_NULL_RLP, trie.calc_hash());
    }

    #[test]
    fn single_account_leaf_hash_is_correct() {
        common_setup();

        let acc_and_hash_entry = &load_pyevm_truth_vals()[0];
        let acc_entry = acc_and_hash_entry.account_entry();
        let rlp_bytes = rlp::encode(&acc_entry);

        let ins_entry = (acc_and_hash_entry.account_key.into(), rlp_bytes.into());

        let py_evm_truth_val = acc_and_hash_entry.final_state_root;
        let eth_trie_lib_truth_val =
            get_lib_trie_root_hashes_after_each_insert(once(ins_entry.clone()))
                .next()
                .unwrap();
        let our_hash = PartialTrie::from_iter(once(ins_entry)).calc_hash();

        assert_eq!(py_evm_truth_val, our_hash);
        assert_eq!(eth_trie_lib_truth_val, our_hash);
    }

    #[test]
    fn single_leaf_hash_is_correct() {
        common_setup();
        insert_entries_into_our_and_lib_tries_and_assert_equal_hashes(&[entry(0x9001)]);
    }

    #[test]
    fn two_variable_length_keys_with_overlap_produces_correct_hash() {
        common_setup();
        let entries = [entry(0x1234), entry(0x12345678)];

        insert_entries_into_our_and_lib_tries_and_assert_equal_hashes(&entries);
    }

    #[test]
    fn two_variable_length_keys_with_no_overlap_produces_correct_hash() {
        common_setup();
        let entries = [entry(0x1234), entry(0x5678)];

        insert_entries_into_our_and_lib_tries_and_assert_equal_hashes(&entries);
    }

    #[test]
    fn massive_random_data_insert_fixed_keys_hashes_agree_with_eth_trie() {
        common_setup();
        insert_entries_into_our_and_lib_tries_and_assert_equal_hashes(
            &generate_n_random_fixed_trie_entries(NUM_INSERTS_FOR_ETH_TRIE_CRATE_MASSIVE_TEST, 0)
                .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn massive_random_data_insert_variable_keys_hashes_agree_with_eth_trie() {
        common_setup();
        insert_entries_into_our_and_lib_tries_and_assert_equal_hashes(
            &generate_n_random_fixed_even_nibble_padded_trie_entries(
                NUM_INSERTS_FOR_ETH_TRIE_CRATE_MASSIVE_TEST,
                0,
            )
            .collect::<Vec<_>>(),
        );
    }

    #[test]
    fn massive_account_insert_hashes_agree_with_eth_trie_and_py_evm() {
        common_setup();

        let py_evm_truth_vals = load_pyevm_truth_vals();

        let entries: Vec<_> = py_evm_truth_vals
            .iter()
            .map(|e| (e.account_key.into(), rlp::encode(&e.account_entry()).into()))
            .collect();

        let our_insert_hashes =
            get_root_hashes_for_our_trie_after_each_insert(entries.iter().cloned());
        let lib_insert_hashes = get_lib_trie_root_hashes_after_each_insert(entries.iter().cloned());
        let pyevm_insert_hashes = py_evm_truth_vals.into_iter().map(|e| e.final_state_root);

        for ((our_h, lib_h), pyevm_h) in our_insert_hashes
            .zip(lib_insert_hashes)
            .zip(pyevm_insert_hashes)
        {
            assert_eq!(our_h, lib_h);
            assert_eq!(our_h, pyevm_h);
        }
    }

    #[test]
    fn massive_trie_data_deletion_agrees_with_eth_trie() {
        common_setup();

        let entries: Vec<_> = generate_n_random_fixed_even_nibble_padded_trie_entries(
            NUM_INSERTS_FOR_ETH_TRIE_CRATE_MASSIVE_TEST,
            8,
        )
        .collect();

        let mut our_trie = PartialTrie::from_iter(entries.iter().cloned());
        let mut truth_trie = create_truth_trie();

        for (k, v) in entries.iter() {
            truth_trie.insert(&k.bytes_be(), v).unwrap();
        }

        let half_entries = entries.len() / 2;
        let entries_to_delete = entries.into_iter().take(half_entries);
        for (k, _) in entries_to_delete {
            our_trie.delete(k);
            truth_trie.remove(&k.bytes_be()).unwrap();

            let truth_root_hash = H256(truth_trie.root_hash().unwrap().0);
            assert_eq!(our_trie.calc_hash(), truth_root_hash);
        }
    }

    #[test]
    fn replacing_branch_of_leaves_with_hash_nodes_produced_same_hash() {
        let mut trie = PartialTrie::from_iter(
            [
                large_entry(0x1),
                large_entry(0x2),
                large_entry(0x3),
                large_entry(0x4),
            ]
            .into_iter(),
        );

        let orig_hash = trie.calc_hash();

        let children = get_branch_children_expected(&mut trie);
        children[1] = PartialTrie::Hash(children[1].calc_hash()).into();
        children[4] = PartialTrie::Hash(children[4].calc_hash()).into();

        let new_hash = trie.calc_hash();
        assert_eq!(orig_hash, new_hash);
    }

    fn get_branch_children_expected(node: &mut PartialTrie) -> &mut [WrappedNode; 16] {
        match node {
            PartialTrie::Branch { children, .. } => children,
            _ => unreachable!(),
        }
    }

    #[test]
    fn replacing_part_of_a_trie_with_a_hash_node_produces_same_hash() {
        let entries = (0..16).flat_map(|i| {
            generate_n_random_variable_keys(NODES_PER_BRANCH_FOR_HASH_REPLACEMENT_TEST, i).map(
                move |(mut k, v)| {
                    // Force all keys to be under a given branch at root.
                    k.truncate_n_nibbles_front_mut(1);
                    k.push_nibble_front(i as Nibble);

                    (k, v)
                },
            )
        });

        let mut trie = PartialTrie::from_iter(entries);
        let orig_hash = trie.calc_hash();

        let root_branch_children = match &mut trie {
            PartialTrie::Branch { children, .. } => children,
            _ => unreachable!(),
        };

        // Replace every even branch node in the root with a hash node.
        for i in (0..16).step_by(2) {
            let child_hash = root_branch_children[i].calc_hash();
            root_branch_children[i] = PartialTrie::Hash(child_hash).into();
        }

        let new_hash = trie.calc_hash();
        assert_eq!(orig_hash, new_hash);
    }
}
