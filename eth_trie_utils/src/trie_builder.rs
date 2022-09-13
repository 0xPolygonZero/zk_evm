use std::fmt::Display;

use ethereum_types::U256;
use itertools::Itertools;
use log::trace;

use crate::{
    partial_trie::{Nibbles, PartialTrie},
    types::EthAddress,
};

// Use a whole byte for a Nibble just for convenience
pub(crate) type Nibble = u8;

#[derive(Debug)]
/// Simplified trie node type to make logging cleaner.
enum TrieNodeType {
    Empty,
    Branch,
    Extension,
    Leaf,
}

impl From<&PartialTrie> for TrieNodeType {
    fn from(node: &PartialTrie) -> Self {
        match node {
            PartialTrie::Empty => Self::Empty,
            PartialTrie::Hash(_) => unreachable!(
                "Hit a Hash node when converting a node type to a debug representation!"
            ),
            PartialTrie::Branch { .. } => Self::Branch,
            PartialTrie::Extension { .. } => Self::Extension,
            PartialTrie::Leaf { .. } => Self::Leaf,
        }
    }
}

#[derive(Debug)]
struct NibblesBuilder {
    nibbles: [Nibble; 64],
    count: usize,
}

impl Default for NibblesBuilder {
    fn default() -> Self {
        Self {
            nibbles: [0; 64],
            count: Default::default(),
        }
    }
}

impl From<NibblesBuilder> for Nibbles {
    fn from(b: NibblesBuilder) -> Self {
        // TODO: Not the nicest impl... Make nicer later?
        let mut nibble_bytes: [u8; 32] = [0; 32];
        let mut nibble_u64s = [0; 4];

        for (i, byte) in NibblesBuilder::nibbles_to_bytes(b.nibbles.into_iter()).enumerate() {
            nibble_bytes[i] = byte;
        }

        nibble_u64s[0] = u64::from_be_bytes(b.nibbles[0..8].try_into().unwrap());
        nibble_u64s[1] = u64::from_be_bytes(b.nibbles[8..16].try_into().unwrap());
        nibble_u64s[2] = u64::from_be_bytes(b.nibbles[16..24].try_into().unwrap());
        nibble_u64s[3] = u64::from_be_bytes(b.nibbles[24..32].try_into().unwrap());

        Self {
            count: b.count,
            packed: U256(nibble_u64s),
        }
    }
}

impl NibblesBuilder {
    pub(crate) fn append_nibble(&mut self, nibble: Nibble) {
        debug_assert!(nibble < 16, "Got a nibble that was more than 4 bits!");

        self.nibbles[self.count] = nibble;
        self.count += 1;
    }

    fn nibbles_to_bytes(nibbles: impl Iterator<Item = Nibble>) -> impl Iterator<Item = u8> {
        nibbles.tuples().map(|(a, b)| a | (b << 4))
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct TrieEntry {
    pub nibbles: Nibbles,
    pub v: Vec<u8>,
}

impl Display for TrieEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TrieEntry: (k: {}, v: {:?})", &self.nibbles, self.v)
    }
}

impl TrieEntry {
    pub(crate) fn truncate_n_nibbles(&mut self, n: usize) {
        self.nibbles = self.nibbles.truncate_n_nibbles(n);
    }
}

pub(crate) fn insert_into_trie(
    trie: &mut Box<PartialTrie>,
    new_entry: TrieEntry,
) -> Option<Box<PartialTrie>> {
    trace!("Inserting {}...", new_entry);
    insert_into_trie_rec(trie, new_entry)
}

pub(crate) fn construct_trie_from_inserts(
    nodes: impl Iterator<Item = TrieEntry>,
) -> Box<PartialTrie> {
    let mut root = Box::new(PartialTrie::Empty);

    for new_entry in nodes {
        if let Some(updated_root) = insert_into_trie(&mut root, new_entry) {
            root = updated_root;
        }
    }

    root
}

fn insert_into_trie_rec(
    node: &mut PartialTrie,
    mut new_node: TrieEntry,
) -> Option<Box<PartialTrie>> {
    trace!("Insert: Traversed {:?}", TrieNodeType::from(&*node));

    match node {
        PartialTrie::Empty => {
            return Some(Box::new(PartialTrie::Leaf {
                nibbles: new_node.nibbles,
                value: new_node.v,
            }));
        }
        PartialTrie::Branch { children, value: _ } => {
            let nibble = new_node.nibbles.get_nibble(0);
            new_node.truncate_n_nibbles(1);

            if let Some(updated_child) =
                insert_into_trie_rec(&mut children[nibble as usize], new_node)
            {
                children[nibble as usize] = updated_child;
            }
        }
        PartialTrie::Extension { nibbles, child } => {
            // Note: Child is guaranteed to be a branch.
            assert!(matches!(**child, PartialTrie::Branch { .. }), "Extension node child should be guaranteed to be a branch, but wasn't! (Ext node: {:?})", node);

            let new_node_nibbles_at_position = new_node.nibbles.get_nibble_range(0..nibbles.count);

            // If the nibbles match, then there is no need to split the extension node.
            match *nibbles == new_node_nibbles_at_position {
                false => {
                    return Some(split_extension_node(
                        child.clone(),
                        new_node,
                        nibbles,
                        &new_node_nibbles_at_position,
                    ));
                }
                true => {
                    // No change. Keep traversing.
                    let num_ext_nibbles = nibbles.count;
                    new_node.truncate_n_nibbles(num_ext_nibbles);

                    if let Some(updated_node) = insert_into_trie_rec(child, new_node) {
                        *child = updated_node;
                    }
                }
            }
        }
        PartialTrie::Leaf { nibbles, value } => {
            // // Assume that the leaf and new entry key differ?
            // let new_node_nibbles_at_depth =
            //     Nibbles::get_nibble_range_from_eth_addr(&new_node.nibbles, depth..(depth
            // + nibbles.count));

            assert!(*nibbles != new_node.nibbles, "Tried inserting a node that already existed in the trie! (new: {:?}, existing: {:?})", new_node, node);
            let existing_leaf_nibbles = *nibbles;

            return Some(split_leaf_node(
                value.clone(),
                new_node,
                &existing_leaf_nibbles,
            ));
        }
        PartialTrie::Hash(_) => unreachable!(
            "Found a `Hash` node in a partial trie! These should not exist for the Eth tests!"
        ),
    }

    None
}

fn split_extension_node(
    existing_ext_child: Box<PartialTrie>,
    new_node: TrieEntry,
    existing_ext_nibbles: &Nibbles,
    _new_node_nibbles_at_depth: &Nibbles,
) -> Box<PartialTrie> {
    let (pre, post) =
        new_node
            .nibbles
            .split_at_idx(Nibbles::find_nibble_idx_that_differs_between_nibbles(
                &new_node.nibbles,
                existing_ext_nibbles,
            ));
    let lower_extension_nibbles = post.truncate_n_nibbles(1);

    let node_that_goes_into_new_branch = match lower_extension_nibbles.count > 0 {
        false => {
            // The new branch we insert will cover the one nibble that we would
            // otherwise have an extension node for.
            existing_ext_child
        }
        true => {
            trace!("CREATING EXT NODE!");

            // We need to create another extension node after the branch to cover
            // the repeated nibbles.
            Box::new(PartialTrie::Extension {
                nibbles: lower_extension_nibbles,
                child: existing_ext_child,
            })
        }
    };

    split_common(node_that_goes_into_new_branch, new_node, pre, post)
}

fn split_leaf_node(
    existing_leaf_data: Vec<u8>,
    new_node: TrieEntry,
    existing_leaf_nibbles: &Nibbles,
) -> Box<PartialTrie> {
    let nib_idx_of_difference = Nibbles::find_nibble_idx_that_differs_between_nibbles(
        existing_leaf_nibbles,
        &new_node.nibbles,
    );

    let common_prefix = existing_leaf_nibbles.split_at_idx_prefix(nib_idx_of_difference);
    let existing_leaf_postfix = existing_leaf_nibbles.split_at_idx_postfix(nib_idx_of_difference);
    let _new_node_postfix = new_node.nibbles.split_at_idx_postfix(nib_idx_of_difference);

    trace!(
        "EXISTING LEAF POSTFIX: {}",
        nibbles_to_human_readable_string(&existing_leaf_postfix)
    );

    // Remove one nibble since the new branch is going to contain one nibble of the
    // leaf.
    let updated_leaf_nibbles = existing_leaf_postfix.truncate_n_nibbles(1);

    let updated_existing_leaf = Box::new(PartialTrie::Leaf {
        nibbles: updated_leaf_nibbles,
        value: existing_leaf_data,
    });

    trace!(
        "Updated existing leaf: {}",
        node_to_human_readable_string(&updated_existing_leaf)
    );

    split_common(
        updated_existing_leaf,
        new_node,
        common_prefix,
        existing_leaf_postfix,
    )
}

fn split_common(
    updated_existing_node_that_goes_into_new_branch: Box<PartialTrie>,
    new_node: TrieEntry,
    pre: Nibbles,
    post: Nibbles,
) -> Box<PartialTrie> {
    // Where they differ, insert a branch node.
    let mut branch_children = new_branch_child_arr();
    let first_nibble_of_post = post.get_nibble(0);
    branch_children[first_nibble_of_post as usize] =
        updated_existing_node_that_goes_into_new_branch;

    let first_nibble_of_ins_node = new_node.nibbles.get_nibble(0);

    // Guaranteed to not collide with other node, so we can also insert directly.
    assert!(matches!(
        &*branch_children[first_nibble_of_ins_node as usize],
        &PartialTrie::Empty
    ));

    branch_children[first_nibble_of_ins_node as usize] = Box::new(PartialTrie::Leaf {
        nibbles: new_node.nibbles.truncate_n_nibbles(1),
        value: new_node.v,
    });

    let branch = Box::new(PartialTrie::Branch {
        children: branch_children,
        value: None,
    });

    let new_first_node = match pre.count > 0 {
        false => {
            // Replace ext node with a branch.
            branch
        }
        true => {
            // Keep ext node, but shorten it and insert a branch at the diverge
            // point.
            Box::new(PartialTrie::Extension {
                nibbles: pre,
                child: branch,
            })
        }
    };

    trace!(
        "Split into a:\n{}",
        node_to_human_readable_string(&new_first_node)
    );

    // The redundant let binding I think helps with readability here.
    #[allow(clippy::let_and_return)]
    new_first_node
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

fn shift_nibbles_out(n: &mut Nibbles, amt: usize) {
    n.packed >>= 4 * amt;
    n.count -= 1;
}

fn eth_addr_to_nibbles(addr: EthAddress) -> Nibbles {
    // Note: `bits()` is always >= 1.
    Nibbles {
        count: (addr.bits() + 3) / 4,
        packed: addr,
    }
}

fn node_to_human_readable_string(node: &PartialTrie) -> String {
    let mut string = String::new();
    node_to_human_readable_string_rec(node, &mut string);

    string
}

// Inefficient, but that's ok.
fn node_to_human_readable_string_rec(node: &PartialTrie, string: &mut String) {
    string.push_str(&format!(" {:?}\n", node));

    match node {
        PartialTrie::Branch { children, .. } => {
            for child in children {
                node_to_human_readable_string_rec(child, string);
            }
        }
        PartialTrie::Extension { nibbles, child } => {
            string.push_str(&nibbles_to_human_readable_string(nibbles));
            node_to_human_readable_string_rec(child, string);
        }
        PartialTrie::Leaf { nibbles, .. } => {
            string.push_str(&nibbles_to_human_readable_string(nibbles));
        }
        _ => (),
    }
}

fn nibbles_to_human_readable_string(n: &Nibbles) -> String {
    u256_to_human_readable_string(&n.packed)
}

fn u256_to_human_readable_string(v: &U256) -> String {
    let mut byte_buf = [0; 32];
    v.to_big_endian(&mut byte_buf);
    let hex_string = hex::encode(byte_buf);

    format!("nibbles_hex: 0x{}", hex_string)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use log::{info, trace};

    use super::{construct_trie_from_inserts, Nibble, TrieEntry};
    use crate::{
        partial_trie::{Nibbles, PartialTrie},
        trie_builder::{nibbles_to_human_readable_string, TrieNodeType},
        types::EthAddress,
    };

    fn entry(k: u64) -> TrieEntry {
        TrieEntry {
            nibbles: EthAddress::from(k).into(),
            v: Vec::new(),
        }
    }

    fn create_trie_from_inserts(ins: &[TrieEntry]) -> Box<PartialTrie> {
        construct_trie_from_inserts(ins.iter().cloned())
    }

    fn common_setup() {
        // Try init since multiple tests calling `init` will cause an error.
        let _ = pretty_env_logger::try_init();
    }

    fn get_entries_in_trie(trie: &PartialTrie) -> HashSet<TrieEntry> {
        info!("Collecting all entries inserted into trie...");

        let mut seen_entries = HashSet::new();
        get_entries_in_trie_rec(
            trie,
            &mut seen_entries,
            Nibbles {
                count: 0,
                packed: EthAddress::zero(),
            },
        );

        seen_entries
    }

    fn get_entries_in_trie_rec(
        trie: &PartialTrie,
        seen_entries: &mut HashSet<TrieEntry>,
        curr_k: Nibbles,
    ) {
        trace!(
            "Entry collection traversed node type: {:?}",
            TrieNodeType::from(trie)
        );

        match trie {
            PartialTrie::Empty => (),
            PartialTrie::Hash(_) => unreachable!("Found a Hash node when collecting all entries in a trie! These should not exist for the Eth tests!"),
            PartialTrie::Branch { children, .. } => {
                trace!("Branch loop start");
                for (branch_nib, child) in children.iter().enumerate() {
                    let new_k = append_nibble_to_nibbles(&curr_k, branch_nib as u8);
                    // let new_k = create_nibbles_by_shifting_out(&curr_k.packed, 1);
                    trace!("New nibble after branch: {}", nibbles_to_human_readable_string(&new_k));
                    get_entries_in_trie_rec(child, seen_entries, new_k);
                }
                trace!("Branch loop end");

                // Note: Currently ignoring the `Value` field...
            },
            PartialTrie::Extension { nibbles, child } => {
                let new_k = curr_k.merge(nibbles);
                get_entries_in_trie_rec(child, seen_entries, new_k);
            },
            PartialTrie::Leaf { nibbles, value } => {
                let final_key = curr_k.merge(nibbles);
                add_entry_to_seen_entries(TrieEntry { nibbles: final_key, v: value.clone() }, seen_entries);
            },
        }
    }

    fn add_entry_to_seen_entries(e: TrieEntry, seen_entries: &mut HashSet<TrieEntry>) {
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

    fn insert_entries_and_assert_all_exist_in_trie_with_no_extra(entries: &[TrieEntry]) {
        let trie = create_trie_from_inserts(entries);
        let entries_in_trie = get_entries_in_trie(&trie);

        println!("{:#?}", entries_in_trie);

        let all_entries_retrievable_from_trie = entries.iter().all(|e| entries_in_trie.contains(e));
        let no_additional_entries_inserted = entries.iter().all(|e| entries.contains(e));

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

        insert_entries_and_assert_all_exist_in_trie_with_no_extra(&entries)
    }

    #[test]
    fn two_inserts_that_share_one_nibble_works() {
        common_setup();
        let entries = [entry(0x1234), entry(0x1567)];

        insert_entries_and_assert_all_exist_in_trie_with_no_extra(&entries)
    }

    #[test]
    fn two_inserts_that_differ_on_last_nibble_works() {
        todo!()
    }

    #[test]
    fn mass_inserts_all_entries_are_retrievable() {
        todo!()
    }
}
