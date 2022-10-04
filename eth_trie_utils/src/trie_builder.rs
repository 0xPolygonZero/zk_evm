use std::fmt::Display;

use log::trace;

use crate::{
    partial_trie::{Nibbles, PartialTrie},
    types::Nibble,
};

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
}

#[derive(Debug)]
struct ExistingAndNewNodePreAndPost {
    common_prefix: Nibbles,
    existing_postfix: Nibbles,
    new_postfix: Nibbles,
}

/// When splitting a leaf/extension node after an insert, there is a chance that
/// we may place one of the nodes right into the value node of the branch. This
/// enum just indicates whether or not a value needs to go into the branch node.
#[derive(Debug)]
enum ExistingOrNewBranchValuePlacement {
    BranchValue(Vec<u8>, (Nibble, Box<PartialTrie>)),
    BothBranchChildren((Nibble, Box<PartialTrie>), (Nibble, Box<PartialTrie>)),
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
        PartialTrie::Branch { children, value } => {
            if new_node.nibbles.count == 0 {
                trace!("Insert traversed branch and placed value in node");
                *value = new_node.v;
                return None;
            }

            let nibble = new_node.nibbles.pop_next_nibble();
            trace!("Insert traversed Branch (nibble: {:x})", nibble);

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
        PartialTrie::Leaf { nibbles, value } => {
            trace!("Insert traversed Leaf (nibbles: {:?})", nibbles);

            // Update existing node value if already present.
            if *nibbles == new_node.nibbles {
                *value = new_node.v;
                return Some(Box::new(node.clone()));
            }

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
    let nib_idx_of_difference =
        Nibbles::find_nibble_idx_that_differs_between_nibbles_different_lengths(
            existing_node_nibbles,
            new_node_nibbles,
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
    let mut children = new_branch_child_arr();
    let mut value = vec![];

    match check_if_existing_or_new_node_should_go_in_branch_value_field(
        info,
        existing_node,
        new_node,
    ) {
        ExistingOrNewBranchValuePlacement::BranchValue(branch_v, (nib, node)) => {
            children[nib as usize] = node;
            value = branch_v;
        }
        ExistingOrNewBranchValuePlacement::BothBranchChildren((nib_1, node_1), (nib_2, node_2)) => {
            children[nib_1 as usize] = node_1;
            children[nib_2 as usize] = node_2;
        }
    }

    let branch = Box::new(PartialTrie::Branch { children, value });

    match info.common_prefix.count {
        0 => branch,
        _ => Box::new(PartialTrie::Extension {
            nibbles: info.common_prefix,
            child: branch,
        }),
    }
}

/// Check if the new leaf or existing node (either leaf/extension) should go
/// into the value field of the new branch.
fn check_if_existing_or_new_node_should_go_in_branch_value_field(
    info: &ExistingAndNewNodePreAndPost,
    mut existing_node: Box<PartialTrie>,
    new_node_entry: InsertEntry,
) -> ExistingOrNewBranchValuePlacement {
    // Guaranteed that both postfixes are not equal at this point.
    match (
        info.existing_postfix.count,
        info.new_postfix.count,
        &mut *existing_node,
    ) {
        (0, _, PartialTrie::Leaf { value, .. }) => ExistingOrNewBranchValuePlacement::BranchValue(
            value.clone(),
            ins_entry_into_leaf_and_nibble(info, new_node_entry),
        ),
        (_, 0, _) => ExistingOrNewBranchValuePlacement::BranchValue(
            new_node_entry.v,
            (info.existing_postfix.get_nibble(0), existing_node),
        ),
        (_, _, _) => ExistingOrNewBranchValuePlacement::BothBranchChildren(
            (info.existing_postfix.get_nibble(0), existing_node),
            ins_entry_into_leaf_and_nibble(info, new_node_entry),
        ),
    }
}

fn ins_entry_into_leaf_and_nibble(
    info: &ExistingAndNewNodePreAndPost,
    entry: InsertEntry,
) -> (Nibble, Box<PartialTrie>) {
    let new_first_nibble = info.new_postfix.get_nibble(0);
    let new_node = Box::new(PartialTrie::Leaf {
        nibbles: entry
            .nibbles
            .truncate_n_nibbles(info.common_prefix.count + 1),
        value: entry.v,
    });

    (new_first_nibble, new_node)
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
        testing_utils::{
            common_setup, entry, generate_n_random_fixed_trie_entries,
            generate_n_random_variable_keys,
        },
        types::Nibble,
        utils::create_mask_of_1s,
    };

    const NUM_RANDOM_INSERTS: usize = 100000;

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
            PartialTrie::Branch { children, value } => {
                for (branch_nib, child) in children.iter().enumerate() {
                    let new_k = append_nibble_to_nibbles(&curr_k, branch_nib as u8);
                    get_entries_in_trie_rec(child, seen_entries, new_k);
                }

                if !value.is_empty() {
                    add_entry_to_seen_entries(InsertEntry { nibbles: curr_k, v: value.clone() }, seen_entries)
                }
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
        let entries: Vec<_> = (0..=64).map(|i| entry(create_mask_of_1s(i * 4))).collect();

        insert_entries_and_assert_all_exist_in_trie_with_no_extra(&entries);
    }

    #[test]
    fn updating_an_existing_node_works() {
        common_setup();
        let mut entries = [entry(0x1234), entry(0x1234)];
        entries[1].v = vec![100];

        let trie = PartialTrie::construct_trie_from_inserts(entries.into_iter());
        assert_eq!(trie.get(0x1234.into()), Some([100].as_slice()));
    }

    #[test]
    fn mass_inserts_fixed_sized_keys_all_entries_are_retrievable() {
        common_setup();
        let entries: Vec<_> = generate_n_random_fixed_trie_entries(NUM_RANDOM_INSERTS, 0).collect();

        insert_entries_and_assert_all_exist_in_trie_with_no_extra(&entries);
    }

    #[test]
    fn mass_inserts_variable_sized_keys_all_entries_are_retrievable() {
        common_setup();
        let entries: Vec<_> = generate_n_random_variable_keys(NUM_RANDOM_INSERTS, 0).collect();

        insert_entries_and_assert_all_exist_in_trie_with_no_extra(&entries);
    }

    #[test]
    fn equivalency_check_works() {
        common_setup();

        assert_eq!(PartialTrie::Empty, PartialTrie::Empty);

        let entries = generate_n_random_fixed_trie_entries(NUM_RANDOM_INSERTS, 0);
        let big_trie_1 = create_trie_from_inserts(entries);
        assert_eq!(big_trie_1, big_trie_1);

        let entries = generate_n_random_fixed_trie_entries(NUM_RANDOM_INSERTS, 1);
        let big_trie_2 = create_trie_from_inserts(entries);

        assert_ne!(big_trie_1, big_trie_2)
    }
}
