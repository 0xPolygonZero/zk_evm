//! Specialized queries that users of the library may need that require
//! knowledge of the private internal trie state.

use crate::{
    nibbles::Nibbles,
    partial_trie::{Node, PartialTrie, WrappedNode},
    utils::TrieSegment,
};

/// An iterator for a trie query. Note that this iterator is lazy.
#[derive(Debug)]
pub struct TriePathIter<N: PartialTrie> {
    /// The next node in the trie to query with the remaining key.
    curr_node: WrappedNode<N>,

    /// The remaining part of the key as we traverse down the trie.
    curr_key: Nibbles,

    // Although wrapping `curr_node` in an option might be more "Rust like", the logic is a lot
    // cleaner with a bool.
    terminated: bool,
}

impl<T: PartialTrie> Iterator for TriePathIter<T> {
    type Item = TrieSegment;

    fn next(&mut self) -> Option<Self::Item> {
        if self.terminated {
            return None;
        }

        match self.curr_node.as_ref() {
            Node::Empty => {
                self.terminated = true;
                Some(TrieSegment::Empty)
            }
            Node::Hash(_) => {
                self.terminated = true;
                Some(TrieSegment::Hash)
            }
            Node::Branch { children, .. } => {
                // Our query key has ended. Stop here.
                if self.curr_key.is_empty() {
                    self.terminated = true;
                    return None;
                }

                let nib = self.curr_key.pop_next_nibble_front();
                self.curr_node = children[nib as usize].clone();

                Some(TrieSegment::Branch(nib))
            }
            Node::Extension { nibbles, child } => {
                match self
                    .curr_key
                    .nibbles_are_identical_up_to_smallest_count(nibbles)
                {
                    false => {
                        // Only a partial match. Stop.
                        self.terminated = true;
                        None
                    }
                    true => {
                        pop_nibbles_clamped(&mut self.curr_key, nibbles.count);
                        let res = Some(TrieSegment::Extension(*nibbles));
                        self.curr_node = child.clone();

                        res
                    }
                }
            }
            Node::Leaf { nibbles, .. } => {
                self.terminated = true;

                match self.curr_key == *nibbles {
                    false => None,
                    true => Some(TrieSegment::Leaf(*nibbles)),
                }
            }
        }
    }
}

/// Attempt to pop `n` nibbles from the given [`Nibbles`] and "clamp" the
/// nibbles popped by not popping more nibbles than exist.
fn pop_nibbles_clamped(nibbles: &mut Nibbles, n: usize) -> Nibbles {
    let n_nibs_to_pop = nibbles.count.min(n);
    nibbles.pop_nibbles_front(n_nibs_to_pop)
}

/// Returns all nodes in the trie that are traversed given a query (key).
///
/// Note that if the key does not match the entire key of a node (eg. the
/// remaining key is `0x34` but the next key is a leaf with the key `0x3456`),
/// then the leaf will not appear in the query output.
pub fn path_for_query<K, T: PartialTrie>(trie: &Node<T>, k: K) -> TriePathIter<T>
where
    K: Into<Nibbles>,
{
    TriePathIter {
        curr_node: trie.clone().into(),
        curr_key: k.into(),
        terminated: false,
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::path_for_query;
    use crate::{nibbles::Nibbles, testing_utils::handmade_trie_1, utils::TrieSegment};

    #[test]
    fn query_iter_works() {
        let (trie, ks) = handmade_trie_1();

        // ks --> vec![0x1234, 0x1324, 0x132400005_u64, 0x2001, 0x2002];
        let res = vec![
            vec![
                TrieSegment::Branch(1),
                TrieSegment::Branch(2),
                TrieSegment::Leaf(0x34.into()),
            ],
            vec![
                TrieSegment::Branch(1),
                TrieSegment::Branch(3),
                TrieSegment::Extension(0x24.into()),
            ],
            vec![
                TrieSegment::Branch(1),
                TrieSegment::Branch(3),
                TrieSegment::Extension(0x24.into()),
                TrieSegment::Branch(0),
                TrieSegment::Leaf(Nibbles::from_str("0x0005").unwrap()),
            ],
            vec![
                TrieSegment::Branch(2),
                TrieSegment::Extension(Nibbles::from_str("0x00").unwrap()),
                TrieSegment::Branch(0x1),
                TrieSegment::Leaf(Nibbles::default()),
            ],
            vec![
                TrieSegment::Branch(2),
                TrieSegment::Extension(Nibbles::from_str("0x00").unwrap()),
                TrieSegment::Branch(0x2),
                TrieSegment::Leaf(Nibbles::default()),
            ],
        ];

        for (q, expected) in ks.into_iter().zip(res.into_iter()) {
            let res: Vec<_> = path_for_query(&trie.node, q).collect();
            assert_eq!(res, expected)
        }
    }
}
