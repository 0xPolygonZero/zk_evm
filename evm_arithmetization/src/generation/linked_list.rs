use std::collections::HashSet;

use anyhow::Result;
use env_logger::try_init_from_env;
use env_logger::Env;
use env_logger::DEFAULT_FILTER_ENV;
use ethereum_types::{Address, H160, U256};
use itertools::Itertools;
use num::traits::ToBytes;
use plonky2::field::goldilocks_field::GoldilocksField as F;
use plonky2_maybe_rayon::rayon::iter;
use rand::{thread_rng, Rng};

use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::cpu::kernel::interpreter::Interpreter;
use crate::memory::segments::Segment::{self, AccessedAddresses, AccessedStorageKeys};
use crate::util::u256_to_usize;
use crate::witness::errors::ProgramError;
use crate::witness::errors::ProverInputError;
use crate::witness::errors::ProverInputError::InvalidInput;
use crate::witness::memory::MemoryAddress;

// A linked list implemented using a vector `access_list_mem`.
// In this representation, the values of nodes are stored in the range
// `access_list_mem[i..i + node_size - 1]`, and `access_list_mem[i + node_size -
// 1]` holds the address of the next node, where i = node_size * j.
pub(crate) struct LinkedList<'a, const N: usize> {
    mem: &'a [Option<U256>],
    mem_len: usize,
    offset: usize,
    pos: usize,
}

impl<'a, const N: usize> LinkedList<'a, N> {
    pub fn from_mem_and_segment(
        mem: &'a [Option<U256>],
        segment: Segment,
    ) -> Result<Self, ProgramError> {
        Self::from_mem_len_and_segment(mem, mem.len(), segment)
    }

    pub fn from_mem_len_and_segment(
        mem: &'a [Option<U256>],
        mem_len: usize,
        segment: Segment,
    ) -> Result<Self, ProgramError> {
        if mem.is_empty() {
            return Err(ProgramError::ProverInputError(InvalidInput));
        }
        let mem_len = mem.len();
        Ok(Self {
            mem,
            mem_len,
            offset: segment as usize,
            pos: 0,
        })
    }

    /// Returns the index of the smallest node such that its sucessor satisfy
    /// `predicate`
    pub fn predecessor<F>(self, predicate: F) -> Option<usize>
    where
        F: Fn(&[U256; N]) -> bool,
    {
        for (prev_ptr, node) in self {
            if predicate(&node) {
                return Some(prev_ptr);
            }
        }
        None
    }

    // fn insert(&mut self, new_node: &[Option<U256>; N]) -> Result<(),
    // ProgramError> {     if let Some((ptr, node)) =
    //         self.find(|(prev_ptr, other_node)| other_node[0] >
    // new_node[0].unwrap_or_default())     {
    //         let scaled_new_ptr = self.offset + self.mem.len();
    //         // TODO: We don't want to use the next pointer in new_node. Ideally,
    // we would         // like to define new_node as &[Option<U256>; N - 1].
    // However that         // would require const_generic_expr.
    //         self.mem[self.mem_len..self.mem_len + N -
    // 1].clone_from_slice(&new_node[0..N - 1]);         let prev_node = &mut
    // self.mem[ptr..ptr + N];         let scaled_prev_next_ptr = prev_node[N -
    // 1];         prev_node[N - 1] = Some(scaled_new_ptr.into());
    //         self.mem[self.mem_len + N - 1] = scaled_prev_next_ptr;
    //         Ok(())
    //     } else {
    //         // TODO: Is this the right error?
    //         Err(ProgramError::ProverInputError(
    //             ProverInputError::InvalidInput,
    //         ))
    //     }
    // }
}

impl<'a, const N: usize> Iterator for LinkedList<'a, N> {
    type Item = (usize, [U256; N]);

    fn next(&mut self) -> Option<Self::Item> {
        if let Ok(new_pos) = u256_to_usize(self.mem[self.pos + N - 1].unwrap_or_default()) {
            let old_pos = self.pos;
            self.pos = new_pos - self.offset;
            Some((
                old_pos,
                std::array::from_fn(|i| self.mem[self.pos + i].unwrap_or_default()),
            ))
        } else {
            None
        }
    }
}
