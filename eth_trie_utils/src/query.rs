use log::trace;

use crate::{
    partial_trie::{Nibbles, PartialTrie},
    types::EthAddress,
};

impl PartialTrie {
    pub fn get(&self, eth_addr: EthAddress) -> Option<&[u8]> {
        let mut n = eth_addr.into();
        self.get_intern(&mut n)
    }

    fn get_intern(&self, curr_nib: &mut Nibbles) -> Option<&[u8]> {
        trace!("GET INTERN");

        match self {
            PartialTrie::Empty | PartialTrie::Hash(_) => None,
            // Note: If we end up supporting non-fixed sized keys, then we need to also check value.
            PartialTrie::Branch { children, .. } => {
                let nib = curr_nib.pop_next_nibble();
                trace!("Get Branch (nibble: 0x{})", nib);
                children[nib as usize].get_intern(curr_nib)
            }
            PartialTrie::Extension { nibbles, child } => {
                trace!("Get Extension (nibbles: {:?})", nibbles);
                let r = curr_nib.pop_next_nibbles(nibbles.count);

                match r.nibbles_are_substring_of_the_other(nibbles) {
                    false => None,
                    true => {
                        curr_nib.pop_next_nibbles(nibbles.count);
                        child.get_intern(curr_nib)
                    }
                }
            }
            PartialTrie::Leaf { nibbles, value } => {
                trace!("Get Leaf (nibbles: {:?})", nibbles);
                match nibbles.nibbles_are_substring_of_the_other(curr_nib) {
                    false => None,
                    true => Some(value),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        testing_utils::generate_n_random_trie_entries, trie_builder::construct_trie_from_inserts,
    };

    const TRIE_SIZE: usize = 27;

    #[test]
    fn get_works() {
        let random_entries: Vec<_> = generate_n_random_trie_entries(TRIE_SIZE).collect();
        let t = construct_trie_from_inserts(random_entries.iter().cloned());

        let all_entries_inserted = random_entries
            .iter()
            .all(|e| t.get(e.nibbles.into()) == Some(&e.v));
        assert!(all_entries_inserted);
    }
}
