use std::fmt::Display;

use log::trace;

use crate::{
    partial_trie::{Nibbles, PartialTrie, WrappedNode},
    utils::Nibble,
};

/// A entry to be inserted into a `PartialTrie`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct InsertEntry {
    pub nibbles: Nibbles,
    pub v: Vec<u8>,
}

impl From<(Nibbles, Vec<u8>)> for InsertEntry {
    fn from((nibbles, v): (Nibbles, Vec<u8>)) -> Self {
        Self { nibbles, v }
    }
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

/// prefix/postfix info when comparing two `Nibbles`.
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
    BranchValue(Vec<u8>, (Nibble, WrappedNode)),
    BothBranchChildren((Nibble, WrappedNode), (Nibble, WrappedNode)),
}

impl PartialTrie {
    /// Inserts a node into the trie.
    pub fn insert(self, k: Nibbles, v: Vec<u8>) -> PartialTrie {
        let ins_entry = (k, v).into();
        trace!("Inserting new leaf node {:?}...", ins_entry);

        // Inserts are guaranteed to update the root node.
        *insert_into_trie_rec(&self.into(), ins_entry)
            .unwrap()
            .as_ref()
            .clone()
    }
}

impl FromIterator<(Nibbles, Vec<u8>)> for PartialTrie {
    fn from_iter<T: IntoIterator<Item = (Nibbles, Vec<u8>)>>(nodes: T) -> Self {
        let mut root = PartialTrie::Empty;

        for (k, v) in nodes {
            root = root.insert(k, v);
        }

        root
    }
}

fn insert_into_trie_rec(node: &WrappedNode, mut new_node: InsertEntry) -> Option<WrappedNode> {
    match node.as_ref().as_ref() {
        PartialTrie::Empty => {
            trace!("Insert traversed Empty");
            Some(
                PartialTrie::Leaf {
                    nibbles: new_node.nibbles,
                    value: new_node.v,
                }
                .into(),
            )
        }
        PartialTrie::Branch { children, value } => {
            if new_node.nibbles.count == 0 {
                trace!("Insert traversed branch and placed value in node");
                return Some(
                    PartialTrie::Branch {
                        children: children.clone(),
                        value: new_node.v,
                    }
                    .into(),
                );
            }

            let nibble = new_node.nibbles.pop_next_nibble();
            trace!("Insert traversed Branch (nibble: {:x})", nibble);

            insert_into_trie_rec(&children[nibble as usize], new_node).map(|updated_child| {
                let mut updated_children = children.clone();
                updated_children[nibble as usize] = updated_child;
                PartialTrie::Branch {
                    children: updated_children,
                    value: value.clone(),
                }
                .into()
            })
        }
        PartialTrie::Extension { nibbles, child } => {
            trace!("Insert traversed Extension (nibbles: {:?})", nibbles);

            // Note: Child is guaranteed to be a branch.
            assert!(matches!(***child, PartialTrie::Branch { .. }), "Extension node child should be guaranteed to be a branch, but wasn't! (Ext node: {:?})", node);

            let info = get_pre_and_postfixes_for_existing_and_new_nodes(nibbles, &new_node.nibbles);

            if nibbles.nibbles_are_identical_up_to_smallest_count(&new_node.nibbles) {
                new_node.truncate_n_nibbles(nibbles.count);

                return insert_into_trie_rec(child, new_node).map(|updated_child| {
                    PartialTrie::Extension {
                        nibbles: *nibbles,
                        child: updated_child,
                    }
                    .into()
                });
            }

            // Drop one since branch will cover one nibble.
            // Also note that the postfix is always >= 1.
            let existing_postfix_adjusted_for_branch = info.existing_postfix.truncate_n_nibbles(1);

            // If we split an extension node, we may need to place an extension node after
            // the branch.
            let updated_existing_node = match existing_postfix_adjusted_for_branch.count {
                0 => child.clone(),
                _ => PartialTrie::Extension {
                    nibbles: existing_postfix_adjusted_for_branch,
                    child: child.clone(),
                }
                .into(),
            };

            Some(place_branch_and_potentially_ext_prefix(
                &info,
                updated_existing_node,
                new_node,
            ))
        }
        PartialTrie::Leaf { nibbles, value } => {
            trace!("Insert traversed Leaf (nibbles: {:?})", nibbles);

            // Update existing node value if already present.
            if *nibbles == new_node.nibbles {
                return Some(
                    PartialTrie::Leaf {
                        nibbles: *nibbles,
                        value: new_node.v,
                    }
                    .into(),
                );
            }

            let info = get_pre_and_postfixes_for_existing_and_new_nodes(nibbles, &new_node.nibbles);

            // This existing leaf is going in a branch, so we need to truncate the first
            // nibble since it's going to be represented by the branch.
            let existing_node_truncated = PartialTrie::Leaf {
                nibbles: nibbles.truncate_n_nibbles(info.common_prefix.count + 1),
                value: value.clone(),
            }
            .into();

            Some(place_branch_and_potentially_ext_prefix(
                &info,
                existing_node_truncated,
                new_node,
            ))
        }
        PartialTrie::Hash(_) => {
            trace!("Insert traversed {:?}", node);
            unreachable!(
                "Found a `Hash` node during an insert in a `PartialTrie`! These should not be able to be traversed during an insert!"
            )
        }
    }
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
    existing_node: WrappedNode,
    new_node: InsertEntry,
) -> WrappedNode {
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

    let branch = PartialTrie::Branch { children, value }.into();

    match info.common_prefix.count {
        0 => branch,
        _ => PartialTrie::Extension {
            nibbles: info.common_prefix,
            child: branch,
        }
        .into(),
    }
}

/// Check if the new leaf or existing node (either leaf/extension) should go
/// into the value field of the new branch.
fn check_if_existing_or_new_node_should_go_in_branch_value_field(
    info: &ExistingAndNewNodePreAndPost,
    existing_node: WrappedNode,
    new_node_entry: InsertEntry,
) -> ExistingOrNewBranchValuePlacement {
    // Guaranteed that both postfixes are not equal at this point.
    match (
        info.existing_postfix.count,
        info.new_postfix.count,
        existing_node.as_ref().as_ref(),
    ) {
        (0, _, PartialTrie::Leaf { value, .. }) => ExistingOrNewBranchValuePlacement::BranchValue(
            value.clone(),
            ins_entry_into_leaf_and_nibble(info, new_node_entry),
        ),
        (_, 0, _) => ExistingOrNewBranchValuePlacement::BranchValue(
            new_node_entry.v,
            (info.existing_postfix.get_nibble(0), existing_node.clone()),
        ),
        (_, _, _) => ExistingOrNewBranchValuePlacement::BothBranchChildren(
            (info.existing_postfix.get_nibble(0), existing_node.clone()),
            ins_entry_into_leaf_and_nibble(info, new_node_entry),
        ),
    }
}

fn ins_entry_into_leaf_and_nibble(
    info: &ExistingAndNewNodePreAndPost,
    entry: InsertEntry,
) -> (Nibble, WrappedNode) {
    let new_first_nibble = info.new_postfix.get_nibble(0);
    let new_node = PartialTrie::Leaf {
        nibbles: entry
            .nibbles
            .truncate_n_nibbles(info.common_prefix.count + 1),
        value: entry.v,
    }
    .into();

    (new_first_nibble, new_node)
}

fn new_branch_child_arr() -> [WrappedNode; 16] {
    // Hahaha ok there actually is no better way to init this array unless I want to
    // use iterators and take a runtime hit...
    [
        PartialTrie::Empty.into(),
        PartialTrie::Empty.into(),
        PartialTrie::Empty.into(),
        PartialTrie::Empty.into(),
        PartialTrie::Empty.into(),
        PartialTrie::Empty.into(),
        PartialTrie::Empty.into(),
        PartialTrie::Empty.into(),
        PartialTrie::Empty.into(),
        PartialTrie::Empty.into(),
        PartialTrie::Empty.into(),
        PartialTrie::Empty.into(),
        PartialTrie::Empty.into(),
        PartialTrie::Empty.into(),
        PartialTrie::Empty.into(),
        PartialTrie::Empty.into(),
    ]
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::{
        partial_trie::PartialTrie,
        testing_utils::{
            common_setup, entry, generate_n_random_fixed_trie_entries,
            generate_n_random_variable_keys, get_entries_in_trie, TestInsertEntry,
        },
        utils::create_mask_of_1s,
    };

    const NUM_RANDOM_INSERTS: usize = 100000;

    fn insert_entries_and_assert_all_exist_in_trie_with_no_extra(entries: &[TestInsertEntry]) {
        let trie = PartialTrie::from_iter(entries.iter().cloned());
        let entries_in_trie = get_entries_in_trie(&trie);

        let all_entries_retrieved: Vec<_> = entries
            .iter()
            .filter(|e| !entries_in_trie.contains(e))
            .collect();

        // HashSet to avoid the linear search below.
        let entries_hashset: HashSet<TestInsertEntry> = HashSet::from_iter(entries.iter().cloned());
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
        entries[1].1 = vec![100];

        let trie = PartialTrie::from_iter(entries.into_iter());
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
        let big_trie_1 = PartialTrie::from_iter(entries);
        assert_eq!(big_trie_1, big_trie_1);

        let entries = generate_n_random_fixed_trie_entries(NUM_RANDOM_INSERTS, 1);
        let big_trie_2 = PartialTrie::from_iter(entries);

        assert_ne!(big_trie_1, big_trie_2)
    }
}
