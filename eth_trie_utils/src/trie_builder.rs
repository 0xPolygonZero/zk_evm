use std::fmt::Display;

use ethereum_types::U256;
use log::trace;

use crate::{
    partial_trie::{Nibbles, PartialTrie},
    utils::nibbles,
};

#[derive(Debug)]
/// Simplified trie node type to make logging cleaner.
enum TrieNodeType {
    Empty,
    Hash,
    Branch,
    Extension,
    Leaf,
}

impl From<&PartialTrie> for TrieNodeType {
    fn from(node: &PartialTrie) -> Self {
        match node {
            PartialTrie::Empty => Self::Empty,
            PartialTrie::Hash(_) => Self::Hash,
            PartialTrie::Branch { .. } => Self::Branch,
            PartialTrie::Extension { .. } => Self::Extension,
            PartialTrie::Leaf { .. } => Self::Leaf,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct InsertEntry {
    pub nibbles: Nibbles,
    pub v: Vec<u8>,
}

impl Display for InsertEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TrieEntry: (k: {}, v: {:?})", &self.nibbles, self.v)
    }
}

impl InsertEntry {
    pub(crate) fn truncate_n_nibbles(&mut self, n: usize) {
        self.nibbles = self.nibbles.truncate_n_nibbles(n);
    }

    pub fn from_trie_key_and_bytes(k: U256, v: Vec<u8>) -> Self {
        Self {
            nibbles: k.into(),
            v,
        }
    }
}

#[derive(Debug)]
struct ExistingAndNewNodePreAndPost {
    common_prefix: Nibbles,
    existing_postfix: Nibbles,
    new_postfix: Nibbles,
}

impl PartialTrie {
    pub fn construct_trie_from_inserts(
        nodes: impl Iterator<Item = InsertEntry>,
    ) -> Box<PartialTrie> {
        let mut root = Box::new(PartialTrie::Empty);

        for new_entry in nodes {
            if let Some(updated_root) = Self::insert_into_trie(&mut root, new_entry) {
                root = updated_root;
            }
        }

        root
    }

    pub fn insert_into_trie(
        root: &mut Box<PartialTrie>,
        new_entry: InsertEntry,
    ) -> Option<Box<PartialTrie>> {
        trace!("Inserting new leaf node {:?}...", new_entry);
        insert_into_trie_rec(root, new_entry)
    }
}

fn insert_into_trie_rec(
    node: &mut PartialTrie,
    mut new_node: InsertEntry,
) -> Option<Box<PartialTrie>> {
    match node {
        PartialTrie::Empty => {
            trace!("Insert traversed Empty");
            return Some(Box::new(PartialTrie::Leaf {
                nibbles: new_node.nibbles,
                value: new_node.v,
            }));
        }
        PartialTrie::Branch { children, value: _ } => {
            let nibble = new_node.nibbles.pop_next_nibble();
            trace!(
                "Insert traversed Branch (nibble: {})",
                nibbles(nibble as u64)
            );

            if let Some(updated_child) =
                insert_into_trie_rec(&mut children[nibble as usize], new_node)
            {
                children[nibble as usize] = updated_child;
            }
        }
        PartialTrie::Extension { nibbles, child } => {
            trace!("Insert traversed Extension (nibbles: {:?})", nibbles);

            // Note: Child is guaranteed to be a branch.
            assert!(matches!(**child, PartialTrie::Branch { .. }), "Extension node child should be guaranteed to be a branch, but wasn't! (Ext node: {:?})", node);

            let info = get_pre_and_postfixes_for_existing_and_new_nodes(nibbles, &new_node.nibbles);

            if nibbles.nibbles_are_identical_up_to_smallest_count(&new_node.nibbles) {
                new_node.truncate_n_nibbles(nibbles.count);
                if let Some(updated_node) = insert_into_trie_rec(child, new_node) {
                    *child = updated_node;
                }

                return None;
            }

            // Drop one since branch will cover one nibble.
            // Also note that the postfix is always >= 1.
            let existing_postfix_adjusted_for_branch = info.existing_postfix.truncate_n_nibbles(1);

            // If we split an extension node, we may need to place an extension node after
            // the branch.
            let updated_existing_node = match existing_postfix_adjusted_for_branch.count {
                0 => child.clone(),
                _ => Box::new(PartialTrie::Extension {
                    nibbles: existing_postfix_adjusted_for_branch,
                    child: child.clone(),
                }),
            };

            return Some(place_branch_and_potentially_ext_prefix(
                &info,
                updated_existing_node,
                new_node,
            ));
        }
        PartialTrie::Leaf { nibbles, value: _ } => {
            trace!("Insert traversed Leaf (nibbles: {:?})", nibbles);

            // Assume that the leaf and new entry key differ?
            assert!(*nibbles != new_node.nibbles, "Tried inserting a node that already existed in the trie! (new: {:?}, existing: {:?})", new_node, node);

            let info = get_pre_and_postfixes_for_existing_and_new_nodes(nibbles, &new_node.nibbles);

            // This existing leaf is going in a branch, so we need to truncate the first
            // nibble since it's going to be represented by the branch.
            *nibbles = nibbles.truncate_n_nibbles(info.common_prefix.count + 1);

            return Some(place_branch_and_potentially_ext_prefix(
                &info,
                Box::new(node.clone()),
                new_node,
            ));
        }
        PartialTrie::Hash(_) => {
            trace!("Insert traversed {:?}", node);
            unreachable!(
                "Found a `Hash` node during an insert in a `PartialTrie`! These should not be able to be traversed during an insert!"
            )
        }
    }

    None
}

fn get_pre_and_postfixes_for_existing_and_new_nodes(
    existing_node_nibbles: &Nibbles,
    new_node_nibbles: &Nibbles,
) -> ExistingAndNewNodePreAndPost {
    let nib_idx_of_difference = Nibbles::find_nibble_idx_that_differs_between_nibbles(
        existing_node_nibbles,
        &new_node_nibbles.get_nibble_range(0..existing_node_nibbles.count),
    );

    let (common_prefix, existing_postfix) =
        existing_node_nibbles.split_at_idx(nib_idx_of_difference);
    let new_postfix = new_node_nibbles.split_at_idx_postfix(nib_idx_of_difference);

    ExistingAndNewNodePreAndPost {
        common_prefix,
        existing_postfix,
        new_postfix,
    }
}

fn place_branch_and_potentially_ext_prefix(
    info: &ExistingAndNewNodePreAndPost,
    existing_node: Box<PartialTrie>,
    new_node: InsertEntry,
) -> Box<PartialTrie> {
    // `1` since the first nibble is being represented by the branch.
    let existing_first_nibble = info.existing_postfix.get_nibble(0);
    let new_first_nibble = info.new_postfix.get_nibble(0);

    let mut children = new_branch_child_arr();
    children[existing_first_nibble as usize] = existing_node;
    children[new_first_nibble as usize] = Box::new(PartialTrie::Leaf {
        nibbles: new_node
            .nibbles
            .truncate_n_nibbles(info.common_prefix.count + 1),
        value: new_node.v,
    });

    let branch = Box::new(PartialTrie::Branch {
        children,
        value: vec![],
    });

    match info.common_prefix.count {
        0 => branch,
        // TODO: Remove the redundant clone...
        _ => Box::new(PartialTrie::Extension {
            nibbles: info.common_prefix,
            child: branch,
        }),
    }
}

fn new_branch_child_arr() -> [Box<PartialTrie>; 16] {
    // Hahaha ok there actually is no better way to init this array unless I want to
    // use iterators and take a runtime hit...
    [
        Box::new(PartialTrie::Empty),
        Box::new(PartialTrie::Empty),
        Box::new(PartialTrie::Empty),
        Box::new(PartialTrie::Empty),
        Box::new(PartialTrie::Empty),
        Box::new(PartialTrie::Empty),
        Box::new(PartialTrie::Empty),
        Box::new(PartialTrie::Empty),
        Box::new(PartialTrie::Empty),
        Box::new(PartialTrie::Empty),
        Box::new(PartialTrie::Empty),
        Box::new(PartialTrie::Empty),
        Box::new(PartialTrie::Empty),
        Box::new(PartialTrie::Empty),
        Box::new(PartialTrie::Empty),
        Box::new(PartialTrie::Empty),
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use ethereum_types::U256;
    use log::info;

    use super::InsertEntry;
    use crate::{
        partial_trie::{Nibbles, PartialTrie},
        testing_utils::{common_setup, generate_n_random_trie_entries},
        types::Nibble,
        utils::create_mask_of_1s,
    };

    const NUM_RANDOM_INSERTS: usize = 100000;

    fn entry<K: Into<U256>>(k: K) -> InsertEntry {
        InsertEntry {
            nibbles: (k.into()).into(),
            v: Vec::new(),
        }
    }

    fn create_trie_from_inserts(ins: impl Iterator<Item = InsertEntry>) -> Box<PartialTrie> {
        PartialTrie::construct_trie_from_inserts(ins)
    }

    fn get_entries_in_trie(trie: &PartialTrie) -> HashSet<InsertEntry> {
        info!("Collecting all entries inserted into trie...");

        let mut seen_entries = HashSet::new();
        get_entries_in_trie_rec(
            trie,
            &mut seen_entries,
            Nibbles {
                count: 0,
                packed: U256::zero(),
            },
        );

        seen_entries
    }

    fn get_entries_in_trie_rec(
        trie: &PartialTrie,
        seen_entries: &mut HashSet<InsertEntry>,
        curr_k: Nibbles,
    ) {
        match trie {
            PartialTrie::Empty => (),
            PartialTrie::Hash(_) => unreachable!("Found a Hash node when collecting all entries in a trie! These should not exist for the Eth tests!"),
            PartialTrie::Branch { children, .. } => {
                for (branch_nib, child) in children.iter().enumerate() {
                    let new_k = append_nibble_to_nibbles(&curr_k, branch_nib as u8);
                    get_entries_in_trie_rec(child, seen_entries, new_k);
                }

                // Note: Currently ignoring the `Value` field...
            },
            PartialTrie::Extension { nibbles, child } => {
                let new_k = curr_k.merge(nibbles);
                get_entries_in_trie_rec(child, seen_entries, new_k);
            },
            PartialTrie::Leaf { nibbles, value } => {
                let final_key = curr_k.merge(nibbles);
                add_entry_to_seen_entries(InsertEntry { nibbles: final_key, v: value.clone() }, seen_entries);
            },
        }
    }

    fn add_entry_to_seen_entries(e: InsertEntry, seen_entries: &mut HashSet<InsertEntry>) {
        assert!(
            !seen_entries.contains(&e),
            "A duplicate entry exists in the trie! {:?}",
            e
        );

        seen_entries.insert(e);
    }

    fn append_nibble_to_nibbles(nibbles: &Nibbles, nibble: Nibble) -> Nibbles {
        assert!(nibble < 16);

        let packed = (nibbles.packed << 4) | nibble.into();
        Nibbles {
            count: nibbles.count + 1,
            packed,
        }
    }

    fn insert_entries_and_assert_all_exist_in_trie_with_no_extra(entries: &[InsertEntry]) {
        let trie = create_trie_from_inserts(entries.iter().cloned());
        let entries_in_trie = get_entries_in_trie(&trie);

        trie.get(U256::max_value());

        let all_entries_retrieved: Vec<_> = entries
            .iter()
            .filter(|e| !entries_in_trie.contains(e))
            .collect();

        // HashSet to avoid the linear search below.
        let entries_hashset: HashSet<InsertEntry> = HashSet::from_iter(entries.iter().cloned());
        let additional_entries_inserted: Vec<_> = entries_in_trie
            .iter()
            .filter(|e| !entries_hashset.contains(e))
            .collect();

        let all_entries_retrievable_from_trie = all_entries_retrieved.is_empty();
        let no_additional_entries_inserted = additional_entries_inserted.is_empty();

        if !all_entries_retrievable_from_trie || !no_additional_entries_inserted {
            println!(
                "Total retrieved/expected: {}/{}",
                entries_in_trie.len(),
                entries.len()
            );

            println!("Missing: {:#?}", all_entries_retrieved);
            println!("Unexpected retrieved: {:#?}", additional_entries_inserted);
        }

        assert!(all_entries_retrievable_from_trie);
        assert!(no_additional_entries_inserted);
    }

    #[test]
    fn single_insert() {
        common_setup();
        insert_entries_and_assert_all_exist_in_trie_with_no_extra(&[entry(0x1234)]);
    }

    #[test]
    fn two_disjoint_inserts_works() {
        common_setup();
        let entries = [entry(0x1234), entry(0x5678)];

        insert_entries_and_assert_all_exist_in_trie_with_no_extra(&entries);
    }

    #[test]
    fn two_inserts_that_share_one_nibble_works() {
        common_setup();
        let entries = [entry(0x1234), entry(0x1567)];

        insert_entries_and_assert_all_exist_in_trie_with_no_extra(&entries);
    }

    #[test]
    fn two_inserts_that_differ_on_last_nibble_works() {
        common_setup();
        let entries = [entry(0x1234), entry(0x1235)];

        insert_entries_and_assert_all_exist_in_trie_with_no_extra(&entries);
    }

    #[test]
    fn diagonal_inserts_to_base_of_trie_works() {
        common_setup();
        let entries: Vec<_> = (0..=3).map(|i| entry(create_mask_of_1s(i * 4))).collect();

        insert_entries_and_assert_all_exist_in_trie_with_no_extra(&entries);
    }

    #[test]
    fn mass_inserts_all_entries_are_retrievable() {
        common_setup();
        let entries: Vec<_> = generate_n_random_trie_entries(NUM_RANDOM_INSERTS, 0).collect();

        insert_entries_and_assert_all_exist_in_trie_with_no_extra(&entries);
    }

    #[test]
    fn equivalency_check_works() {
        assert_eq!(PartialTrie::Empty, PartialTrie::Empty);

        let entries = generate_n_random_trie_entries(NUM_RANDOM_INSERTS, 0);
        let big_trie_1 = create_trie_from_inserts(entries);
        assert_eq!(big_trie_1, big_trie_1);

        let entries = generate_n_random_trie_entries(NUM_RANDOM_INSERTS, 1);
        let big_trie_2 = create_trie_from_inserts(entries);

        assert_ne!(big_trie_1, big_trie_2)
    }
}
