use std::collections::BTreeMap;

use ethereum_types::U256;
use serde::{Deserialize, Serialize};

use crate::memory::segments::Segment;

pub const ACCOUNTS_LINKED_LIST_NODE_SIZE: usize = 4;
pub const STORAGE_LINKED_LIST_NODE_SIZE: usize = 5;

pub const DUMMYHEAD: (U256, U256) = (U256::MAX, U256::zero());

// Provides quick access to pointers that reference the memory location
// of a storage or accounts linked list node, containing a specific key.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct LinkedListsPtrs {
    /// Each entry contains the pair (key, ptr) where key is the (hashed) key
    /// of an account in the accounts linked list, and ptr is the respective
    /// node address in memory.
    pub(crate) accounts: BTreeMap<U256, usize>,
    /// Each entry contains the pair ((account_key, slot_key), ptr) where
    /// account_key is the (hashed) key of an account, slot_key is the slot
    /// key, and ptr is the respective node address in memory.
    pub(crate) storage: BTreeMap<(U256, U256), usize>,
}

pub(crate) fn empty_list_mem<const N: usize>(segment: Segment) -> [Option<U256>; N] {
    std::array::from_fn(|i| {
        if i == 0 {
            Some(U256::MAX)
        } else if i == N - 1 {
            Some((segment as usize).into())
        } else {
            Some(U256::zero())
        }
    })
}

#[cfg(test)]
pub(crate) mod testing {
    use std::fmt;
    use std::marker::PhantomData;

    use anyhow::Result;

    use super::*;
    use crate::util::u256_to_usize;
    use crate::witness::errors::ProgramError;
    use crate::witness::errors::ProverInputError::InvalidInput;

    pub const ADDRESSES_ACCESS_LIST_LEN: usize = 2;
    pub(crate) trait LinkedListType {}
    #[derive(Clone)]
    /// A linked list that starts from the first node after the special node and
    /// iterates forever.
    pub(crate) struct Cyclic;
    #[derive(Clone)]
    /// A linked list that starts from the special node and iterates until the
    /// last node.
    pub(crate) struct Bounded;
    impl LinkedListType for Cyclic {}
    impl LinkedListType for Bounded {}

    // A linked list implemented using a vector `access_list_mem`.
    // In this representation, the values of nodes are stored in the range
    // `access_list_mem[i..i + node_size - 1]`, and `access_list_mem[i + node_size -
    // 1]` holds the address of the next node, where i = node_size * j.
    #[derive(Clone)]
    pub(crate) struct LinkedList<'a, const N: usize, T = Cyclic>
    where
        T: LinkedListType,
    {
        mem: &'a [Option<U256>],
        offset: usize,
        pos: usize,
        _marker: PhantomData<T>,
    }

    impl<'a, const N: usize, T: LinkedListType> LinkedList<'a, N, T> {
        pub fn from_mem_and_segment(
            mem: &'a [Option<U256>],
            segment: Segment,
        ) -> Result<Self, ProgramError> {
            Self::from_mem_len_and_segment(mem, segment)
        }

        pub fn from_mem_len_and_segment(
            mem: &'a [Option<U256>],
            segment: Segment,
        ) -> Result<Self, ProgramError> {
            if mem.len() % N != 0 {
                return Err(ProgramError::ProverInputError(InvalidInput));
            }
            Ok(Self {
                mem,
                offset: segment as usize,
                pos: 0,
                _marker: PhantomData,
            })
        }
    }

    impl<'a, const N: usize> fmt::Debug for LinkedList<'a, N> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            writeln!(f, "Linked List {{")?;
            let cloned_list = self.clone();
            for (i, node) in cloned_list.enumerate() {
                if i > 0 && node[0] == U256::MAX {
                    break;
                }
                writeln!(f, "{:?} ->", node)?;
            }
            write!(f, "}}")
        }
    }

    impl<'a, const N: usize> fmt::Debug for LinkedList<'a, N, Bounded> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            writeln!(f, "Linked List {{")?;
            let cloned_list = self.clone();
            for node in cloned_list {
                writeln!(f, "{:?} ->", node)?;
            }
            write!(f, "}}")
        }
    }

    impl<'a, const N: usize> Iterator for LinkedList<'a, N> {
        type Item = [U256; N];

        fn next(&mut self) -> Option<Self::Item> {
            let node = Some(std::array::from_fn(|i| {
                self.mem[self.pos + i].unwrap_or_default()
            }));
            if let Ok(new_pos) = u256_to_usize(self.mem[self.pos + N - 1].unwrap_or_default()) {
                self.pos = new_pos - self.offset;
                node
            } else {
                None
            }
        }
    }

    impl<'a, const N: usize> Iterator for LinkedList<'a, N, Bounded> {
        type Item = [U256; N];

        fn next(&mut self) -> Option<Self::Item> {
            if self.mem[self.pos] != Some(U256::MAX) {
                let node = Some(std::array::from_fn(|i| {
                    self.mem[self.pos + i].unwrap_or_default()
                }));
                if let Ok(new_pos) = u256_to_usize(self.mem[self.pos + N - 1].unwrap_or_default()) {
                    self.pos = new_pos - self.offset;
                    node
                } else {
                    None
                }
            } else {
                None
            }
        }
    }
}
