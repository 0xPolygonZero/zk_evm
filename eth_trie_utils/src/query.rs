use log::trace;

use crate::partial_trie::{Nibbles, PartialTrie};

impl PartialTrie {
    /// Get a node if it exists in the trie.
    pub fn get(&self, mut n: Nibbles) -> Option<&[u8]> {
        self.get_intern(&mut n)
    }

    fn get_intern(&self, curr_nibbles: &mut Nibbles) -> Option<&[u8]> {
        match self {
            PartialTrie::Empty | PartialTrie::Hash(_) => {
                trace!("Get traversed {:?}", self);
                None
            }
            // Note: If we end up supporting non-fixed sized keys, then we need to also check value.
            PartialTrie::Branch { children, value } => {
                // Check against branch value.
                if curr_nibbles.is_empty() {
                    return (!value.is_empty()).then_some(value.as_slice());
                }

                let nib = curr_nibbles.pop_next_nibble();
                trace!("Get traversed Branch (nibble: {:x})", nib);
                children[nib as usize].get_intern(curr_nibbles)
            }
            PartialTrie::Extension { nibbles, child } => {
                trace!("Get traversed Extension (nibbles: {:?})", nibbles);
                let r = curr_nibbles.pop_next_nibbles(nibbles.count);

                match r.nibbles_are_identical_up_to_smallest_count(nibbles) {
                    false => None,
                    true => child.get_intern(curr_nibbles),
                }
            }
            PartialTrie::Leaf { nibbles, value } => {
                trace!("Get traversed Leaf (nibbles: {:?})", nibbles);
                match nibbles.nibbles_are_identical_up_to_smallest_count(curr_nibbles) {
                    false => None,
                    true => Some(value),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use log::debug;

    use crate::{
        partial_trie::PartialTrie,
        testing_utils::{
            common_setup, entry_with_value, generate_n_random_fixed_trie_entries,
            generate_n_random_variable_keys, get_entries_in_trie,
        },
    };

    const TRIE_SIZE: usize = 100000;
    const COW_TEST_TRIE_SIZE: usize = 500;

    #[test]
    fn two_variable_length_keys_with_overlap_is_queryable() {
        common_setup();

        let entries = [entry_with_value(0x1234, 1), entry_with_value(0x12345678, 2)];
        let trie = PartialTrie::from_iter(entries.iter().cloned());

        assert_eq!(trie.get(0x1234.into()), Some([1].as_slice()));
        assert_eq!(trie.get(0x12345678.into()), Some([2].as_slice()));
    }

    #[test]
    fn get_massive_trie_works() {
        common_setup();

        let random_entries: Vec<_> =
            generate_n_random_fixed_trie_entries(TRIE_SIZE, 9001).collect();
        let trie = PartialTrie::from_iter(random_entries.iter().cloned());

        for (k, v) in random_entries.into_iter() {
            debug!("Attempting to retrieve {:?}...", (k, &v));
            let res = trie.get(k);

            assert_eq!(res, Some(v.as_slice()));
        }
    }

    #[test]
    fn held_trie_cow_references_do_not_change_as_trie_changes() {
        let entries = generate_n_random_variable_keys(COW_TEST_TRIE_SIZE, 9002);

        let mut all_nodes_in_trie_after_each_insert = Vec::new();
        let mut root_node_after_each_insert = Vec::new();

        let mut trie = PartialTrie::default();
        for (k, v) in entries {
            trie = trie.clone().insert(k, v);

            all_nodes_in_trie_after_each_insert.push(get_entries_in_trie(&trie));
            root_node_after_each_insert.push(trie.clone());
        }

        for (old_trie_nodes_truth, old_root_node) in all_nodes_in_trie_after_each_insert
            .into_iter()
            .zip(root_node_after_each_insert.into_iter())
        {
            let nodes_retrieved = get_entries_in_trie(&old_root_node);
            assert_eq!(old_trie_nodes_truth, nodes_retrieved)
        }
    }
}
