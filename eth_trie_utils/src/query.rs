use log::trace;

use crate::{
    partial_trie::{Nibbles, PartialTrie},
};

impl PartialTrie {
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
            PartialTrie::Branch { children, .. } => {
                let nib = curr_nibbles.pop_next_nibble();
                trace!(
                    "Get traversed Branch (nibble: {:x})", nib
                );
                // println!("Our trie num non empty children: {}", children.iter().filter(|c| !matches!(***c, PartialTrie::Empty)).count());
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
                // println!("Curr nib: {:#?}", curr_nibbles);
                // println!("Value: {:?}", value);
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
        testing_utils::{common_setup, generate_n_random_fixed_trie_entries},
    };

    const TRIE_SIZE: usize = 100000;

    #[test]
    fn get_works() {
        common_setup();

        let random_entries: Vec<_> =
            generate_n_random_fixed_trie_entries(TRIE_SIZE, 9001).collect();
        let t = PartialTrie::construct_trie_from_inserts(random_entries.iter().cloned());

        for e in random_entries.iter() {
            debug!("Attempting to retrieve {:?}...", e);
            let res = t.get(e.nibbles);

            assert_eq!(res, Some(e.v.as_slice()));
        }
    }
}
