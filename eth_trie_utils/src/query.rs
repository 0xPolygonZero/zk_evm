use log::trace;

use crate::{
    partial_trie::{Nibbles, PartialTrie},
    types::EthAddress,
    utils::nibbles,
};

impl PartialTrie {
    pub fn get(&self, eth_addr: EthAddress) -> Option<&[u8]> {
        let mut n = eth_addr.into();
        self.get_intern(&mut n)
    }

    fn get_intern(&self, curr_nib: &mut Nibbles) -> Option<&[u8]> {
        match self {
            PartialTrie::Empty | PartialTrie::Hash(_) => {
                trace!("Get traversed {:?}", self);
                None
            }
            // Note: If we end up supporting non-fixed sized keys, then we need to also check value.
            PartialTrie::Branch { children, .. } => {
                let nib = curr_nib.pop_next_nibble();
                trace!("Get traversed Branch (nibble: {})", nibbles(nib as u64));
                children[nib as usize].get_intern(curr_nib)
            }
            PartialTrie::Extension { nibbles, child } => {
                trace!("Get traversed Extension (nibbles: {:?})", nibbles);
                let r = curr_nib.pop_next_nibbles(nibbles.count);

                match r.nibbles_are_identical_up_to_smallest_count(nibbles) {
                    false => None,
                    true => child.get_intern(curr_nib),
                }
            }
            PartialTrie::Leaf { nibbles, value } => {
                trace!("Get traversed Leaf (nibbles: {:?})", nibbles);
                match nibbles.nibbles_are_identical_up_to_smallest_count(curr_nib) {
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
        testing_utils::{common_setup, generate_n_random_trie_entries},
    };

    const TRIE_SIZE: usize = 100000;

    #[test]
    fn get_works() {
        common_setup();

        let random_entries: Vec<_> = generate_n_random_trie_entries(TRIE_SIZE, 9001).collect();
        let t = PartialTrie::construct_trie_from_inserts(random_entries.iter().cloned());

        for e in random_entries.iter() {
            debug!("Attempting to retrieve {:?}...", e);
            let res = t.get(e.nibbles.into());

            assert_eq!(res, Some(e.v.as_slice()));
        }
    }
}
