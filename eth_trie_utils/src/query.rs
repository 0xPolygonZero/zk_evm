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
        testing_utils::{common_setup, entry_with_value, generate_n_random_fixed_trie_entries},
    };

    const TRIE_SIZE: usize = 100000;

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
}
