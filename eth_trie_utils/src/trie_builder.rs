use std::fmt::Display;

use ethereum_types::U256;
use itertools::Itertools;
use log::trace;

use crate::partial_trie::{Nibbles, PartialTrie};

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

            let info = get_pre_and_postfixes_for_existing_and_new_nodes(nibbles, &new_node.nibbles);

            let updated_existing_node = match info.new_postfix.count {
                0 => child.clone(),
                _ => Box::new(PartialTrie::Extension {
                    nibbles: info.new_postfix,
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
        PartialTrie::Hash(_) => unreachable!(
            "Found a `Hash` node in a partial trie! These should not exist for the Eth tests!"
        ),
    }

    None
}

fn get_pre_and_postfixes_for_existing_and_new_nodes(
    existing_node_nibbles: &Nibbles,
    new_node_nibbles: &Nibbles,
) -> ExistingAndNewNodePreAndPost {
    let nib_idx_of_difference = Nibbles::find_nibble_idx_that_differs_between_nibbles(
        existing_node_nibbles,
        new_node_nibbles,
    );

    let (common_prefix, existing_postfix) =
        existing_node_nibbles.split_at_idx(nib_idx_of_difference);
    let new_postfix = new_node_nibbles.split_at_idx_postfix(nib_idx_of_difference);

    trace!("IDX OF DIFF: {}", nib_idx_of_difference);
    trace!("COMMON: {}", common_prefix);

    ExistingAndNewNodePreAndPost {
        common_prefix,
        existing_postfix,
        new_postfix,
    }
}

struct ExistingAndNewNodePreAndPost {
    common_prefix: Nibbles,
    existing_postfix: Nibbles,
    new_postfix: Nibbles,
}

fn place_branch_and_potentially_ext_prefix(
    info: &ExistingAndNewNodePreAndPost,
    existing_node: Box<PartialTrie>,
    new_node: TrieEntry,
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
        value: None,
    });

    trace!("COMMON PREFIX: {}", info.common_prefix);
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
        trace!("Entry collection traversed node: {:?}", trie);

        match trie {
            PartialTrie::Empty => (),
            PartialTrie::Hash(_) => unreachable!("Found a Hash node when collecting all entries in a trie! These should not exist for the Eth tests!"),
            PartialTrie::Branch { children, .. } => {
                trace!("Branch loop start");
                for (branch_nib, child) in children.iter().enumerate() {
                    let new_k = append_nibble_to_nibbles(&curr_k, branch_nib as u8);
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
    fn mass_inserts_all_entries_are_retrievable() {
        todo!()
    }
}
