use core::mem::transmute;
use core::ops::Neg;
use std::collections::{BTreeSet, HashMap};
use std::str::FromStr;

use anyhow::{bail, Error, Result};
use ethereum_types::{BigEndianHash, H256, U256, U512};
use itertools::Itertools;
use keccak_hash::keccak;
use num_bigint::BigUint;
use plonky2::hash::hash_types::RichField;
use serde::{Deserialize, Serialize};

use super::jumpdest::{JumpDestTableProcessed, JumpDestTableWitness};
#[cfg(test)]
use super::linked_list::testing::{LinkedList, ADDRESSES_ACCESS_LIST_LEN};
use super::linked_list::{
    LinkedListsPtrs, ACCOUNTS_LINKED_LIST_NODE_SIZE, DUMMYHEAD, STORAGE_LINKED_LIST_NODE_SIZE,
};
use super::mpt::load_state_mpt;
use crate::cpu::kernel::cancun_constants::KZG_VERSIONED_HASH;
use crate::cpu::kernel::constants::cancun_constants::{
    BLOB_BASE_FEE_UPDATE_FRACTION, G2_TRUSTED_SETUP_POINT, MIN_BASE_FEE_PER_BLOB_GAS,
    POINT_EVALUATION_PRECOMPILE_RETURN_VALUE,
};
use crate::cpu::kernel::constants::context_metadata::ContextMetadata;
use crate::cpu::kernel::interpreter::{
    get_jumpdest_analysis_inputs_rpc, simulate_cpu_and_get_user_jumps,
};
use crate::curve_pairings::{bls381, CurveAff, CyclicGroup};
use crate::extension_tower::{FieldExt, Fp12, Fp2, BLS381, BLS_BASE, BLS_SCALAR, BN254, BN_BASE};
use crate::generation::prover_input::EvmField::{
    Bls381Base, Bls381Scalar, Bn254Base, Bn254Scalar, Secp256k1Base, Secp256k1Scalar,
};
use crate::generation::prover_input::FieldOp::{Inverse, Sqrt};
use crate::generation::state::GenerationState;
use crate::generation::GlobalMetadata;
use crate::memory::segments::Segment;
use crate::memory::segments::Segment::BnPairing;
use crate::util::{biguint_to_mem_vec, mem_vec_to_biguint, sha2, u256_to_u8, u256_to_usize};
use crate::witness::errors::ProverInputError::*;
use crate::witness::errors::{ProgramError, ProverInputError};
use crate::witness::memory::MemoryAddress;
use crate::witness::operation::CONTEXT_SCALING_FACTOR;
use crate::witness::util::{current_context_peek, stack_peek};

/// A set to hold contract code as a byte vectors.
pub type CodeDb = BTreeSet<Vec<u8>>;

/// Prover input function represented as a scoped function name.
/// Example: `PROVER_INPUT(ff::bn254_base::inverse)` is represented as
/// `ProverInputFn([ff, bn254_base, inverse])`.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct ProverInputFn(Vec<String>);

impl From<Vec<String>> for ProverInputFn {
    fn from(v: Vec<String>) -> Self {
        Self(v)
    }
}

impl<F: RichField> GenerationState<F> {
    pub(crate) fn prover_input(&mut self, input_fn: &ProverInputFn) -> Result<U256, ProgramError> {
        match input_fn.0[0].as_str() {
            "end_of_txns" => self.run_end_of_txns(),
            "trie_ptr" => self.run_trie_ptr(input_fn),
            "ff" => self.run_ff(input_fn),
            "sf" => self.run_sf(input_fn),
            "ffe" => self.run_ffe(input_fn),
            "rlp" => self.run_rlp(),
            "blobbasefee" => self.run_blobbasefee(),
            "current_hash" => self.run_current_hash(),
            "account_code" => self.run_account_code(),
            "bignum_modmul" => self.run_bignum_modmul(),
            "withdrawal" => self.run_withdrawal(),
            "num_bits" => self.run_num_bits(),
            "jumpdest_table" => self.run_jumpdest_table(input_fn),
            "access_lists" => self.run_access_lists(input_fn),
            "linked_list" => self.run_linked_list(input_fn),
            "ger" => self.run_global_exit_root(),
            "kzg_point_eval" => self.run_kzg_point_eval(),
            "kzg_point_eval_2" => self.run_kzg_point_eval_2(),
            _ => Err(ProgramError::ProverInputError(InvalidFunction)),
        }
    }

    fn run_end_of_txns(&mut self) -> Result<U256, ProgramError> {
        // Reset the jumpdest table before the next transaction.
        // self.jumpdest_table = None;
        let end = self.next_txn_index == self.inputs.txn_hashes.len();
        if end {
            Ok(U256::one())
        } else {
            self.next_txn_index += 1;
            Ok(U256::zero())
        }
    }

    fn run_trie_ptr(&mut self, input_fn: &ProverInputFn) -> Result<U256, ProgramError> {
        let trie = input_fn.0[1].as_str();
        match trie {
            "initial_state" => self
                .trie_root_ptrs
                .state_root_ptr
                .map_or_else(
                    || {
                        let mut new_content = self.memory.get_preinit_memory(Segment::TrieData);

                        let n = load_state_mpt(&self.inputs.trimmed_tries, &mut new_content)?;

                        self.memory.insert_preinitialized_segment(
                            Segment::TrieData,
                            crate::witness::memory::MemorySegmentState {
                                content: new_content,
                            },
                        );
                        Ok(n)
                    },
                    Ok,
                )
                .map(U256::from),
            "txn" => Ok(U256::from(self.trie_root_ptrs.txn_root_ptr)),
            "receipt" => Ok(U256::from(self.trie_root_ptrs.receipt_root_ptr)),
            "trie_data_size" => Ok(self
                .memory
                .preinitialized_segments
                .get(&Segment::TrieData)
                .unwrap_or(&crate::witness::memory::MemorySegmentState { content: vec![] })
                .content
                .len()
                .max(
                    self.memory.contexts[0].segments[Segment::TrieData.unscale()]
                        .content
                        .len(),
                )
                .into()),

            _ => Err(ProgramError::ProverInputError(InvalidInput)),
        }
    }

    /// Finite field operations.
    fn run_ff(&self, input_fn: &ProverInputFn) -> Result<U256, ProgramError> {
        let field = EvmField::from_str(input_fn.0[1].as_str())
            .map_err(|_| ProgramError::ProverInputError(InvalidFunction))?;
        let op = FieldOp::from_str(input_fn.0[2].as_str())
            .map_err(|_| ProgramError::ProverInputError(InvalidFunction))?;
        let x = stack_peek(self, 0)?;
        field.op(op, x)
    }

    /// Special finite field operations.
    fn run_sf(&self, input_fn: &ProverInputFn) -> Result<U256, ProgramError> {
        let field = EvmField::from_str(input_fn.0[1].as_str())
            .map_err(|_| ProgramError::ProverInputError(InvalidFunction))?;
        let inputs: [U256; 4] = match field {
            Bls381Base => (0..4)
                .map(|i| stack_peek(self, i))
                .collect::<Result<Vec<U256>, _>>()?
                .try_into()
                .unwrap(),
            _ => todo!(),
        };
        let res = match input_fn.0[2].as_str() {
            "add_lo" => field.add_lo(inputs),
            "add_hi" => field.add_hi(inputs),
            "mul_lo" => field.mul_lo(inputs),
            "mul_hi" => field.mul_hi(inputs),
            "sub_lo" => field.sub_lo(inputs),
            "sub_hi" => field.sub_hi(inputs),
            _ => return Err(ProgramError::ProverInputError(InvalidFunction)),
        };

        Ok(res)
    }

    /// Finite field extension operations.
    fn run_ffe(&self, input_fn: &ProverInputFn) -> Result<U256, ProgramError> {
        let field = EvmField::from_str(input_fn.0[1].as_str())
            .map_err(|_| ProgramError::ProverInputError(InvalidFunction))?;
        let n = input_fn.0[2]
            .as_str()
            .split('_')
            .nth(1)
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let ptr = stack_peek(self, 11 - n).map(u256_to_usize)??;

        let f: [U256; 12] = match field {
            Bn254Base => std::array::from_fn(|i| current_context_peek(self, BnPairing, ptr + i)),
            _ => todo!(),
        };
        Ok(field.field_extension_inverse(n, f))
    }

    /// RLP data.
    fn run_rlp(&mut self) -> Result<U256, ProgramError> {
        self.rlp_prover_inputs
            .pop()
            .ok_or(ProgramError::ProverInputError(OutOfRlpData))
    }

    fn run_blobbasefee(&mut self) -> Result<U256, ProgramError> {
        let excess_blob_gas = self.inputs.block_metadata.block_excess_blob_gas;
        Ok(fake_exponential(
            MIN_BASE_FEE_PER_BLOB_GAS,
            excess_blob_gas,
            BLOB_BASE_FEE_UPDATE_FRACTION,
        ))
    }

    fn run_current_hash(&mut self) -> Result<U256, ProgramError> {
        Ok(U256::from_big_endian(&self.inputs.block_hashes.cur_hash.0))
    }

    /// Account code loading.
    /// Initializes the code segment of the given context with the code
    /// corresponding to the provided hash.
    /// Returns the length of the code.
    fn run_account_code(&mut self) -> Result<U256, ProgramError> {
        // stack: codehash, ctx, ...
        let codehash = stack_peek(self, 0)?;
        let context = stack_peek(self, 1)? >> CONTEXT_SCALING_FACTOR;
        let context = u256_to_usize(context)?;
        let mut address = MemoryAddress::new(context, Segment::Code, 0);
        let code = self
            .inputs
            .contract_code
            .get(&H256::from_uint(&codehash))
            .ok_or(ProgramError::ProverInputError(CodeHashNotFound))?;
        for &byte in code {
            self.memory.set(address, byte.into());
            address.increment();
        }
        Ok(code.len().into())
    }

    // Bignum modular multiplication.
    // On the first call, calculates the remainder and quotient of the given inputs.
    // These are stored, as limbs, in self.bignum_modmul_result_limbs.
    // Subsequent calls return one limb at a time, in order (first remainder and
    // then quotient).
    fn run_bignum_modmul(&mut self) -> Result<U256, ProgramError> {
        if self.bignum_modmul_result_limbs.is_empty() {
            let len = stack_peek(self, 2).map(u256_to_usize)??;
            let a_start_loc = stack_peek(self, 3).map(u256_to_usize)??;
            let b_start_loc = stack_peek(self, 4).map(u256_to_usize)??;
            let m_start_loc = stack_peek(self, 5).map(u256_to_usize)??;

            let (remainder, quotient) =
                self.bignum_modmul(len, a_start_loc, b_start_loc, m_start_loc);

            self.bignum_modmul_result_limbs = remainder
                .iter()
                .cloned()
                .pad_using(len, |_| 0.into())
                .chain(quotient.iter().cloned().pad_using(2 * len, |_| 0.into()))
                .collect();
            self.bignum_modmul_result_limbs.reverse();
        }

        self.bignum_modmul_result_limbs
            .pop()
            .ok_or(ProgramError::ProverInputError(InvalidInput))
    }

    fn bignum_modmul(
        &mut self,
        len: usize,
        a_start_loc: usize,
        b_start_loc: usize,
        m_start_loc: usize,
    ) -> (Vec<U256>, Vec<U256>) {
        let n = self.memory.contexts.len();
        let a = &self.memory.contexts[n - 1].segments[Segment::KernelGeneral.unscale()].content()
            [a_start_loc..a_start_loc + len];
        let b = &self.memory.contexts[n - 1].segments[Segment::KernelGeneral.unscale()].content()
            [b_start_loc..b_start_loc + len];
        let m = &self.memory.contexts[n - 1].segments[Segment::KernelGeneral.unscale()].content()
            [m_start_loc..m_start_loc + len];

        let a_biguint = mem_vec_to_biguint(a);
        let b_biguint = mem_vec_to_biguint(b);
        let m_biguint = mem_vec_to_biguint(m);

        let prod = a_biguint * b_biguint;
        let quo = if m_biguint == BigUint::default() {
            BigUint::default()
        } else {
            &prod / &m_biguint
        };
        let rem = prod - m_biguint * &quo;

        (biguint_to_mem_vec(rem), biguint_to_mem_vec(quo))
    }

    /// Withdrawal data.
    fn run_withdrawal(&mut self) -> Result<U256, ProgramError> {
        self.withdrawal_prover_inputs
            .pop()
            .ok_or(ProgramError::ProverInputError(OutOfWithdrawalData))
    }

    /// Return the number of bits of the top of the stack or an error if
    /// the top of the stack is zero or empty.
    fn run_num_bits(&mut self) -> Result<U256, ProgramError> {
        let value = stack_peek(self, 0)?;
        if value.is_zero() {
            Err(ProgramError::ProverInputError(NumBitsError))
        } else {
            let num_bits = value.bits();
            Ok(num_bits.into())
        }
    }

    /// Generate either the next used jump address, the proof for the last
    /// jump address, or a non-jumpdest proof.
    fn run_jumpdest_table(&mut self, input_fn: &ProverInputFn) -> Result<U256, ProgramError> {
        match input_fn.0[1].as_str() {
            "next_address" => self.run_next_jumpdest_table_address(),
            "next_proof" => self.run_next_jumpdest_table_proof(),
            "non_jumpdest_proof" => self.run_next_non_jumpdest_proof(),
            _ => Err(ProgramError::ProverInputError(InvalidInput)),
        }
    }

    /// Generates either the next used jump address or the proof for the last
    /// jump address.
    fn run_access_lists(&mut self, input_fn: &ProverInputFn) -> Result<U256, ProgramError> {
        match input_fn.0[1].as_str() {
            "address_insert" => self.run_next_addresses_insert(),
            "storage_insert" => self.run_next_storage_insert(),
            "address_remove" => self.run_next_addresses_remove(),
            "storage_remove" => self.run_next_storage_remove(),
            "reset" => self.run_reset(),
            _ => Err(ProgramError::ProverInputError(InvalidInput)),
        }
    }

    /// Generates either the next used jump address or the proof for the last
    /// jump address.
    fn run_linked_list(&mut self, input_fn: &ProverInputFn) -> Result<U256, ProgramError> {
        match input_fn.0[1].as_str() {
            "insert_account" | "search_account" => self.run_next_insert_account(input_fn),
            "remove_account" => self.run_next_remove_account(),
            "insert_slot" | "search_slot" => self.run_next_insert_slot(input_fn),
            "remove_slot" => self.run_next_remove_slot(),
            "remove_address_slots" => self.run_next_remove_address_slots(),
            _ => Err(ProgramError::ProverInputError(InvalidInput)),
        }
    }

    fn run_global_exit_root(&mut self) -> Result<U256, ProgramError> {
        self.ger_prover_inputs
            .pop()
            .ok_or(ProgramError::ProverInputError(OutOfGerData))
    }

    /// Returns the next used jumpdest address.
    fn run_next_jumpdest_table_address(&mut self) -> Result<U256, ProgramError> {
        let batch_context = u256_to_usize(stack_peek(self, 0)? >> CONTEXT_SCALING_FACTOR)?;

        log::info!(
            "Current ctx {}  current tx {}",
            batch_context,
            self.next_txn_index - 1
        );

        if self.jumpdest_table.is_none() {
            self.generate_jumpdest_table()?;
        }

        let Some(jumpdest_table) = &mut self.jumpdest_table else {
            return Err(ProgramError::ProverInputError(
                ProverInputError::InvalidJumpdestSimulation,
            ));
        };

        if let Some(ctx_jumpdest_table) = jumpdest_table.try_get_ctx_mut(&batch_context)
            && let Some(next_jumpdest_address) = ctx_jumpdest_table.pop()
        {
            log::info!(
                "run_next_jumpdest_table_address,     ctx {:>5}, address {:>5}",
                batch_context,
                next_jumpdest_address + 1
            );
            Ok((next_jumpdest_address + 1).into())
        } else {
            log::info!(
                "run_next_jumpdest_table_address,     ctx {:>5}, address {:>5}",
                batch_context,
                0
            );
            jumpdest_table.remove_ctx(&batch_context);
            Ok(U256::zero())
        }
    }

    /// Returns the proof for the last jump address.
    fn run_next_jumpdest_table_proof(&mut self) -> Result<U256, ProgramError> {
        let context = u256_to_usize(stack_peek(self, 1)? >> CONTEXT_SCALING_FACTOR)?;
        let Some(jumpdest_table) = &mut self.jumpdest_table else {
            return Err(ProgramError::ProverInputError(
                ProverInputError::InvalidJumpdestSimulation,
            ));
        };

        if let Some(ctx_jumpdest_table) = jumpdest_table.try_get_ctx_mut(&context)
            && let Some(next_jumpdest_proof) = ctx_jumpdest_table.pop()
        {
            log::info!(
                "run_next_jumpdest_table_proof,       ctx {:>5},   proof {:>5}",
                context,
                next_jumpdest_proof
            );
            Ok(next_jumpdest_proof.into())
        } else {
            Err(ProgramError::ProverInputError(
                ProverInputError::InvalidJumpdestSimulation,
            ))
        }
    }

    /// Returns a non-jumpdest proof for the address on the top of the stack. A
    /// non-jumpdest proof is the closest address to the address on the top of
    /// the stack, if the closest address is >= 32, or zero otherwise.
    fn run_next_non_jumpdest_proof(&self) -> Result<U256, ProgramError> {
        let code = self.get_current_code()?;
        let address = u256_to_usize(stack_peek(self, 0)?)?;
        let closest_opcode_addr = get_closest_opcode_address(&code, address);
        Ok(if closest_opcode_addr < 32 {
            log::info!(
                "run_next_non_jumpdest_proof address {:>5}, closest_opcode_addr {:>5}, returns 0",
                address,
                closest_opcode_addr,
            );
            U256::zero()
        } else {
            log::info!(
                "run_next_non_jumpdest_proof address,        {:>5}, closest_opcode_addr {:>5}",
                address,
                closest_opcode_addr,
            );
            closest_opcode_addr.into()
        })
    }

    /// Returns a pointer to an element in the list whose value is such that
    /// `value <= addr < next_value` and `addr` is the top of the stack.
    fn run_next_addresses_insert(&mut self) -> Result<U256, ProgramError> {
        let addr = stack_peek(self, 0)?;

        let (&pred_addr, &ptr) = self
            .access_lists_ptrs
            .accounts
            .range(..=addr)
            .next_back()
            .unwrap_or((&U256::MAX, &(Segment::AccessedAddresses as usize)));

        if pred_addr != addr {
            self.access_lists_ptrs.accounts.insert(
                addr,
                u256_to_usize(
                    self.memory
                        .read_global_metadata(GlobalMetadata::AccessedAddressesLen),
                )?,
            );
        }
        Ok(U256::from(ptr / 2))
    }

    /// Returns a pointer to an element in the list whose value is such that
    /// `value < addr == next_value` and addr is the top of the stack.
    /// If the element is not in the list, it loops forever
    fn run_next_addresses_remove(&mut self) -> Result<U256, ProgramError> {
        let addr = stack_peek(self, 0)?;

        let (_, &ptr) = self
            .access_lists_ptrs
            .accounts
            .range(..addr)
            .next_back()
            .unwrap_or((&U256::MAX, &(Segment::AccessedAddresses as usize)));
        self.access_lists_ptrs
            .accounts
            .remove(&addr)
            .ok_or(ProgramError::ProverInputError(InvalidInput))?;

        Ok(U256::from(ptr / 2))
    }

    /// Returns a pointer to the predecessor of the top of the stack in the
    /// accessed storage keys list.
    fn run_next_storage_insert(&mut self) -> Result<U256, ProgramError> {
        let addr = stack_peek(self, 0)?;
        let key = stack_peek(self, 1)?;

        let (&(pred_addr, pred_slot_key), &ptr) = self
            .access_lists_ptrs
            .storage
            .range(..=(addr, key))
            .next_back()
            .unwrap_or((&DUMMYHEAD, &(Segment::AccessedStorageKeys as usize)));
        if pred_addr != addr || pred_slot_key != key {
            self.access_lists_ptrs.storage.insert(
                (addr, key),
                u256_to_usize(
                    self.memory
                        .read_global_metadata(GlobalMetadata::AccessedStorageKeysLen),
                )?,
            );
        }
        Ok(U256::from(ptr / 4))
    }

    /// Returns a pointer to the predecessor of the top of the stack in the
    /// accessed storage keys list.
    fn run_next_storage_remove(&mut self) -> Result<U256, ProgramError> {
        let addr = stack_peek(self, 0)?;
        let key = stack_peek(self, 1)?;

        let (_, &ptr) = self
            .access_lists_ptrs
            .storage
            .range(..(addr, key))
            .next_back()
            .unwrap_or((&DUMMYHEAD, &(Segment::AccessedStorageKeys as usize)));
        self.access_lists_ptrs
            .storage
            .remove(&(addr, key))
            .ok_or(ProgramError::ProverInputError(InvalidInput))?;

        Ok(U256::from(ptr / 4))
    }

    fn run_reset(&mut self) -> Result<U256, ProgramError> {
        self.access_lists_ptrs = LinkedListsPtrs::default();
        Ok(U256::zero())
    }

    /// Returns a pointer to a node in the list such that
    /// `node[0] <= addr < next_node[0]` and `addr` is the top of the stack.
    fn run_next_insert_account(&mut self, input_fn: &ProverInputFn) -> Result<U256, ProgramError> {
        let addr = stack_peek(self, 0)?;

        let (&pred_addr, &pred_ptr) = self
            .state_ptrs
            .accounts
            .range(..=addr)
            .next_back()
            .unwrap_or((&U256::MAX, &(Segment::AccountsLinkedList as usize)));

        if pred_addr != addr && input_fn.0[1].as_str() == "insert_account" {
            self.state_ptrs.accounts.insert(
                addr,
                u256_to_usize(
                    self.memory
                        .read_global_metadata(GlobalMetadata::AccountsLinkedListNextAvailable),
                )?,
            );
        }

        Ok(U256::from(pred_ptr / ACCOUNTS_LINKED_LIST_NODE_SIZE))
    }

    /// Returns an unscaled pointer to a node in the list such that
    /// `node[0] <= addr < next_node[0]`, or  node[0] == addr and `node[1] <=
    /// key < next_node[1]`, where `addr` and `key` are the elements at the top
    /// of the stack.
    fn run_next_insert_slot(&mut self, input_fn: &ProverInputFn) -> Result<U256, ProgramError> {
        let addr = stack_peek(self, 0)?;
        let key = stack_peek(self, 1)?;

        let (&(pred_addr, pred_slot_key), &pred_ptr) = self
            .state_ptrs
            .storage
            .range(..=(addr, key))
            .next_back()
            .unwrap_or((&DUMMYHEAD, &(Segment::StorageLinkedList as usize)));
        if (pred_addr != addr || pred_slot_key != key) && input_fn.0[1] == "insert_slot" {
            self.state_ptrs.storage.insert(
                (addr, key),
                u256_to_usize(
                    self.memory
                        .read_global_metadata(GlobalMetadata::StorageLinkedListNextAvailable),
                )?,
            );
        }
        Ok(U256::from(
            (pred_ptr - Segment::StorageLinkedList as usize) / STORAGE_LINKED_LIST_NODE_SIZE,
        ))
    }

    /// Returns a pointer `ptr` to a node of the form [..] -> [next_addr, ..]
    /// list such that `next_addr = addr` and `addr` is the top of the stack.
    /// If the element is not in the list, loops forever.
    fn run_next_remove_account(&mut self) -> Result<U256, ProgramError> {
        let addr = stack_peek(self, 0)?;

        let (_, &ptr) = self
            .state_ptrs
            .accounts
            .range(..addr)
            .next_back()
            .unwrap_or((&U256::MAX, &(Segment::AccountsLinkedList as usize)));
        self.state_ptrs
            .accounts
            .remove(&addr)
            .ok_or(ProgramError::ProverInputError(InvalidInput))?;

        Ok(U256::from(ptr / ACCOUNTS_LINKED_LIST_NODE_SIZE))
    }

    /// Returns a pointer `ptr` to a node = `[next_addr, next_key]` in the list
    /// such that `next_addr == addr` and `next_key == key`,
    /// and `addr, key` are the elements at the top of the stack.
    /// If the element is not in the list, loops forever.
    fn run_next_remove_slot(&mut self) -> Result<U256, ProgramError> {
        let addr = stack_peek(self, 0)?;
        let key = stack_peek(self, 1)?;

        let (_, &ptr) = self
            .state_ptrs
            .storage
            .range(..(addr, key))
            .next_back()
            .unwrap_or((&DUMMYHEAD, &(Segment::StorageLinkedList as usize)));
        self.state_ptrs
            .storage
            .remove(&(addr, key))
            .ok_or(ProgramError::ProverInputError(InvalidInput))?;

        Ok(U256::from(ptr - Segment::StorageLinkedList as usize) / STORAGE_LINKED_LIST_NODE_SIZE)
    }

    /// Returns a pointer `ptr` to a storage node in the storage linked list.
    /// The node's next element = `[next_addr, next_key]` is such that
    /// `next_addr = addr`, if such an element exists, or such that
    /// `next_addr = @U256_MAX`. This is used to determine the first storage
    /// node for the account at `addr`. `addr` is the element at the top of the
    /// stack.
    fn run_next_remove_address_slots(&mut self) -> Result<U256, ProgramError> {
        let addr = stack_peek(self, 0)?;

        let (_, &pred_ptr) = self
            .state_ptrs
            .storage
            .range(..(addr, U256::zero()))
            .next_back()
            .unwrap_or((&DUMMYHEAD, &(Segment::StorageLinkedList as usize)));

        Ok(U256::from(
            (pred_ptr - Segment::StorageLinkedList as usize) / STORAGE_LINKED_LIST_NODE_SIZE,
        ))
    }

    #[cfg(test)]
    pub(crate) fn get_addresses_access_list(
        &self,
    ) -> Result<LinkedList<ADDRESSES_ACCESS_LIST_LEN>, ProgramError> {
        // `GlobalMetadata::AccessedAddressesLen` stores the value of the next available
        // virtual address in the segment. In order to get the length we need
        // to substract `Segment::AccessedAddresses` as usize.
        LinkedList::from_mem_and_segment(
            &self.memory.contexts[0].segments[Segment::AccessedAddresses.unscale()].content,
            Segment::AccessedAddresses,
        )
    }

    /// Returns the first part of the KZG precompile output.
    fn run_kzg_point_eval(&mut self) -> Result<U256, ProgramError> {
        let versioned_hash = stack_peek(self, 0)?;
        let z = stack_peek(self, 1)?;
        let y = stack_peek(self, 2)?;
        let comm_hi = stack_peek(self, 3)?;
        let comm_lo = stack_peek(self, 4)?;
        let proof_hi = stack_peek(self, 5)?;
        let proof_lo = stack_peek(self, 6)?;

        // Validate scalars
        if z > BLS_SCALAR || y > BLS_SCALAR {
            return Ok(U256::zero());
        }

        let mut comm_bytes = [0u8; 48];
        comm_lo.to_big_endian(&mut comm_bytes[16..48]); // only actually 16 bytes
        if comm_bytes[16..32] != [0; 16] {
            // Commitments must fit in 48 bytes.
            return Ok(U256::zero());
        }
        comm_hi.to_big_endian(&mut comm_bytes[0..32]);

        let mut proof_bytes = [0u8; 48];
        proof_lo.to_big_endian(&mut proof_bytes[16..48]); // only actually 16 bytes
        if proof_bytes[16..32] != [0; 16] {
            // Proofs must fit in 48 bytes.
            return Ok(U256::zero());
        }
        proof_hi.to_big_endian(&mut proof_bytes[0..32]);

        let mut expected_versioned_hash = sha2(comm_bytes.to_vec());

        const KZG_HASH_MASK: U256 = U256([
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0x00ffffffffffffff,
        ]);
        expected_versioned_hash &= KZG_HASH_MASK; // erase most significant byte
        expected_versioned_hash |= U256::from(KZG_VERSIONED_HASH) << 248; // append 1

        if versioned_hash != expected_versioned_hash {
            return Ok(U256::zero());
        }

        self.verify_kzg_proof(&comm_bytes, z, y, &proof_bytes)
    }

    /// Returns the second part of the KZG precompile output.
    ///
    /// The POINT_EVALUATION_PRECOMPILE returns a 64-byte value.
    /// Because EVM words only fit in 32 bytes, we need to push
    /// the following word separately.
    fn run_kzg_point_eval_2(&mut self) -> Result<U256, ProgramError> {
        let prev_value = stack_peek(self, 0)?;

        // `run_kzg_point_eval_1` should return 0 upon failure, which should be caught
        // in the Kernel. Ending up here should hence not happen.
        if prev_value != U256::from_big_endian(&POINT_EVALUATION_PRECOMPILE_RETURN_VALUE[1]) {
            return Err(ProgramError::ProverInputError(
                ProverInputError::KzgEvalFailure(
                    "run_kzg_point_eval_1 should have output the expected return value at this point"
                        .to_string(),
                ),
            ));
        }

        Ok(U256::from_big_endian(
            &POINT_EVALUATION_PRECOMPILE_RETURN_VALUE[0],
        ))
    }

    /// Verifies a KZG proof, i.e. that the commitment opens to y at z.
    ///
    /// Returns `0` upon failure of one of the checks, or `BLS_MODULUS` upon
    /// success.
    fn verify_kzg_proof(
        &self,
        comm_bytes: &[u8; 48],
        z: U256,
        y: U256,
        proof_bytes: &[u8; 48],
    ) -> Result<U256, ProgramError> {
        let comm = if let Ok(c) = bls381::g1_from_bytes(comm_bytes) {
            c
        } else {
            return Ok(U256::zero());
        };

        let proof = if let Ok(p) = bls381::g1_from_bytes(proof_bytes) {
            p
        } else {
            return Ok(U256::zero());
        };

        // TODO: use some WNAF method if performance becomes critical
        let mut z_bytes = [0u8; 32];
        z.to_big_endian(&mut z_bytes);
        let mut acc = CurveAff::<Fp2<BLS381>>::unit();
        for byte in z_bytes.into_iter() {
            acc = acc * 256_i32;
            acc = acc + (CurveAff::<Fp2<BLS381>>::GENERATOR * byte as i32);
        }
        let minus_z_g2 = -acc;

        let mut y_bytes = [0u8; 32];
        y.to_big_endian(&mut y_bytes);
        let mut acc = CurveAff::<BLS381>::unit();
        for byte in y_bytes {
            acc = acc * 256_i32;
            acc = acc + (CurveAff::<BLS381>::GENERATOR * byte as i32);
        }
        let comm_minus_y = comm + (acc.neg());

        let x = CurveAff::<Fp2<BLS381>> {
            x: Fp2::<BLS381> {
                re: BLS381 {
                    val: U512::from_big_endian(&G2_TRUSTED_SETUP_POINT[0]),
                },
                im: BLS381 {
                    val: U512::from_big_endian(&G2_TRUSTED_SETUP_POINT[1]),
                },
            },
            y: Fp2::<BLS381> {
                re: BLS381 {
                    val: U512::from_big_endian(&G2_TRUSTED_SETUP_POINT[2]),
                },
                im: BLS381 {
                    val: U512::from_big_endian(&G2_TRUSTED_SETUP_POINT[3]),
                },
            },
        };
        let x_minus_z = x + minus_z_g2;

        // TODO: If this ends up being implemented in the Kernel directly, we should
        // really not have to go through the final exponentiation twice.
        if bls381::ate_optim(comm_minus_y, -CurveAff::<Fp2<BLS381>>::GENERATOR)
            * bls381::ate_optim(proof, x_minus_z)
            != Fp12::<BLS381>::UNIT
        {
            Ok(U256::zero())
        } else {
            Ok(U256::from_big_endian(
                &POINT_EVALUATION_PRECOMPILE_RETURN_VALUE[1],
            ))
        }
    }
}

impl<F: RichField> GenerationState<F> {
    /// Simulate the user's code and store all the jump addresses with their
    /// respective contexts.
    fn generate_jumpdest_table(&mut self) -> Result<(), ProgramError> {
        let tx_in_batch_idx = self.next_txn_index - 1;
        let prev_max_wctx: usize = self
            .inputs
            .jumpdest_table
            .get(tx_in_batch_idx - 1)
            .map(|x| x.as_ref())
            .flatten()
            .map(|jdt| {
                jdt.iter()
                    .map(|(_h, jdt)| jdt.keys().max().copied().unwrap_or(0))
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0)
            + 0;
        log::info!("Maximum CTX in previous tx: {}", prev_max_wctx);
        log::info!("TXIDX: {}", tx_in_batch_idx);
        log::info!("BATCH LEN: {}", self.inputs.txn_hashes.len());
        log::info!("TXN_NUM_BEFORE: {}", self.inputs.txn_number_before);
        let rpcw = self.inputs.jumpdest_table[tx_in_batch_idx].clone();
        let rpcp: Option<JumpDestTableProcessed> = rpcw.as_ref().map(|jdt| {
            get_jumpdest_analysis_inputs_rpc(jdt, &self.inputs.contract_code, prev_max_wctx)
        });
        log::info!("RPCW {:#?}", &rpcw);
        log::info!("RPCP {:#?}", &rpcp);
        // if rpcp.is_some() {
        //     self.jumpdest_table = rpcp;
        //     return Ok(());
        // }
        // Simulate the user's code and (unnecessarily) part of the kernel code,
        // skipping the validate table call
        self.jumpdest_table = None;
        let (simp, simw) = simulate_cpu_and_get_user_jumps("terminate_common", &*self)
            .ok_or(ProgramError::ProverInputError(InvalidJumpdestSimulation))?;
        // self.jumpdest_table = Some(simp.clone());
        log::info!("SIMW {:#?}", &simw);
        log::info!("SIMP {:#?}", &simp);

        if rpcp.is_some() {
            dbg!(rpcp.as_ref(), Some(&simp));
            // assert!(simp.is_subset(rpcp.as_ref().unwrap()));
            self.jumpdest_table = rpcp;
        }
        // self.jumpdest_table = rpcp;
        self.jumpdest_table = Some(simp);
        return Ok(());
    }

    /// Given a HashMap containing the contexts and the jumpdest addresses,
    /// compute their respective proofs, by calling
    /// `get_proofs_and_jumpdests`
    pub(crate) fn get_jumpdest_analysis_inputs(
        &self,
        jumpdest_table: HashMap<usize, BTreeSet<usize>>,
    ) -> (JumpDestTableProcessed, JumpDestTableWitness) {
        let mut jdtw = JumpDestTableWitness::default();
        let jdtp = JumpDestTableProcessed::new(HashMap::from_iter(jumpdest_table.into_iter().map(
            |(ctx, jumpdest_table)| {
                let code = self.get_code(ctx).unwrap();
                let code_hash = keccak(code.clone());
                for offset in jumpdest_table.clone() {
                    jdtw.insert(code_hash, ctx, Some(offset));
                }
                if let Some(&largest_address) = jumpdest_table.last() {
                    let proofs = get_proofs_and_jumpdests(&code, largest_address, jumpdest_table);
                    (ctx, proofs)
                } else {
                    (ctx, vec![])
                }
            },
        )));
        (jdtp, jdtw)
    }

    pub(crate) fn get_current_code(&self) -> Result<Vec<u8>, ProgramError> {
        self.get_code(self.registers.context)
    }

    fn get_code(&self, context: usize) -> Result<Vec<u8>, ProgramError> {
        let code_len = self.get_code_len(context)?;
        let code = (0..code_len)
            .map(|i| {
                u256_to_u8(
                    self.memory
                        .get_with_init(MemoryAddress::new(context, Segment::Code, i)),
                )
            })
            .collect::<Result<Vec<u8>, _>>()?;
        Ok(code)
    }

    fn get_code_len(&self, context: usize) -> Result<usize, ProgramError> {
        let code_len = u256_to_usize(self.memory.get_with_init(MemoryAddress::new(
            context,
            Segment::ContextMetadata,
            ContextMetadata::CodeSize.unscale(),
        )))?;
        Ok(code_len)
    }

    pub(crate) fn set_jumpdest_bits(&mut self, code: &[u8]) {
        const JUMPDEST_OPCODE: u8 = 0x5b;
        for (pos, opcode) in CodeIterator::new(code) {
            if opcode == JUMPDEST_OPCODE {
                self.memory.set(
                    MemoryAddress::new(self.registers.context, Segment::JumpdestBits, pos),
                    U256::one(),
                );
            }
        }
    }
}

/// For all address in `jumpdest_table` smaller than `largest_address`,
/// this function searches for a proof. A proof is the closest address
/// for which none of the previous 32 bytes in the code (including opcodes
/// and pushed bytes) is a PUSHXX and the address is in its range. It returns
/// a vector of even size containing proofs followed by their addresses.
pub(crate) fn get_proofs_and_jumpdests(
    code: &[u8],
    largest_address: usize,
    jumpdest_table: std::collections::BTreeSet<usize>,
) -> Vec<usize> {
    const PUSH1_OPCODE: u8 = 0x60;
    const PUSH32_OPCODE: u8 = 0x7f;
    let (proofs, _) = CodeIterator::until(code, largest_address + 1).fold(
        (vec![], 0),
        |(mut proofs, last_proof), (addr, _opcode)| {
            let has_prefix = if let Some(prefix_start) = addr.checked_sub(32) {
                code[prefix_start..addr]
                    .iter()
                    .rev()
                    .zip(0..32)
                    .all(|(&byte, i)| byte > PUSH32_OPCODE || byte < PUSH1_OPCODE + i)
            } else {
                false
            };
            let last_proof = if has_prefix { addr - 32 } else { last_proof };
            if jumpdest_table.contains(&addr) {
                // Push the proof
                proofs.push(last_proof);
                // Push the address
                proofs.push(addr);
            }
            (proofs, last_proof)
        },
    );
    proofs
}

/// Return the largest prev_addr in `code` such that `code[pred_addr]` is an
/// opcode (and not the argument of some PUSHXX) and pred_addr <= address
fn get_closest_opcode_address(code: &[u8], address: usize) -> usize {
    let (prev_addr, _) = CodeIterator::until(code, address + 1)
        .last()
        .unwrap_or((0, 0));
    prev_addr
}

/// An iterator over the EVM code contained in `code`, which skips the bytes
/// that are the arguments of a PUSHXX opcode.
struct CodeIterator<'a> {
    code: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> CodeIterator<'a> {
    const fn new(code: &'a [u8]) -> Self {
        CodeIterator {
            end: code.len(),
            code,
            pos: 0,
        }
    }
    fn until(code: &'a [u8], end: usize) -> Self {
        CodeIterator {
            end: std::cmp::min(code.len(), end),
            code,
            pos: 0,
        }
    }
}

impl<'a> Iterator for CodeIterator<'a> {
    type Item = (usize, u8);

    fn next(&mut self) -> Option<Self::Item> {
        const PUSH1_OPCODE: u8 = 0x60;
        const PUSH32_OPCODE: u8 = 0x7f;
        let CodeIterator { code, pos, end } = self;
        if *pos >= *end {
            return None;
        }
        let opcode = code[*pos];
        let old_pos = *pos;
        *pos += if (PUSH1_OPCODE..=PUSH32_OPCODE).contains(&opcode) {
            (opcode - PUSH1_OPCODE + 2).into()
        } else {
            1
        };
        Some((old_pos, opcode))
    }
}

enum EvmField {
    Bls381Base,
    Bls381Scalar,
    Bn254Base,
    Bn254Scalar,
    Secp256k1Base,
    Secp256k1Scalar,
}

enum FieldOp {
    Inverse,
    Sqrt,
}

impl FromStr for EvmField {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "bls381_base" => Bls381Base,
            "bls381_scalar" => Bls381Scalar,
            "bn254_base" => Bn254Base,
            "bn254_scalar" => Bn254Scalar,
            "secp256k1_base" => Secp256k1Base,
            "secp256k1_scalar" => Secp256k1Scalar,
            _ => bail!("Unrecognized field."),
        })
    }
}

impl FromStr for FieldOp {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "inverse" => Inverse,
            "sqrt" => Sqrt,
            _ => bail!("Unrecognized field operation."),
        })
    }
}

impl EvmField {
    fn order(&self) -> U512 {
        match self {
            EvmField::Bls381Base => BLS_BASE,
            EvmField::Bls381Scalar => BLS_SCALAR.into(),
            EvmField::Bn254Base => BN_BASE.into(),
            EvmField::Bn254Scalar => todo!(),
            EvmField::Secp256k1Base => {
                U256::from_str("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
                    .unwrap()
                    .into()
            }
            EvmField::Secp256k1Scalar => {
                U256::from_str("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
                    .unwrap()
                    .into()
            }
        }
    }

    fn op(&self, op: FieldOp, x: U256) -> Result<U256, ProgramError> {
        match op {
            FieldOp::Inverse => self.inverse(x),
            FieldOp::Sqrt => self.sqrt(x),
        }
    }

    fn inverse(&self, x: U256) -> Result<U256, ProgramError> {
        let n = U256::try_from(self.order())
            .map_err(|_| ProgramError::ProverInputError(Unimplemented))?;
        if x >= n {
            return Err(ProgramError::ProverInputError(InvalidInput));
        };
        modexp(x, n - 2, n)
    }

    fn sqrt(&self, x: U256) -> Result<U256, ProgramError> {
        let n = U256::try_from(self.order())
            .map_err(|_| ProgramError::ProverInputError(Unimplemented))?;
        if x >= n {
            return Err(ProgramError::ProverInputError(InvalidInput));
        };
        let (q, r) = (n + 1).div_mod(4.into());

        if !r.is_zero() {
            return Err(ProgramError::ProverInputError(InvalidInput));
        };

        // Only naive sqrt implementation for now. If needed implement Tonelli-Shanks
        modexp(x, q, n)
    }

    fn add_lo(&self, inputs: [U256; 4]) -> U256 {
        let [y1, x0, x1, y0] = inputs;
        let x = U512::from(x0) + (U512::from(x1) << 256);
        let y = U512::from(y0) + (U512::from(y1) << 256);
        let z = BLS381 { val: x } + BLS381 { val: y };
        z.lo()
    }

    fn add_hi(&self, inputs: [U256; 4]) -> U256 {
        let [x0, x1, y0, y1] = inputs;
        let x = U512::from(x0) + (U512::from(x1) << 256);
        let y = U512::from(y0) + (U512::from(y1) << 256);
        let z = BLS381 { val: x } + BLS381 { val: y };
        z.hi()
    }

    fn mul_lo(&self, inputs: [U256; 4]) -> U256 {
        let [y1, x0, x1, y0] = inputs;
        let x = U512::from(x0) + (U512::from(x1) << 256);
        let y = U512::from(y0) + (U512::from(y1) << 256);
        let z = BLS381 { val: x } * BLS381 { val: y };
        z.lo()
    }

    fn mul_hi(&self, inputs: [U256; 4]) -> U256 {
        let [x0, x1, y0, y1] = inputs;
        let x = U512::from(x0) + (U512::from(x1) << 256);
        let y = U512::from(y0) + (U512::from(y1) << 256);
        let z = BLS381 { val: x } * BLS381 { val: y };
        z.hi()
    }

    fn sub_lo(&self, inputs: [U256; 4]) -> U256 {
        let [y1, x0, x1, y0] = inputs;
        let x = U512::from(x0) + (U512::from(x1) << 256);
        let y = U512::from(y0) + (U512::from(y1) << 256);
        let z = BLS381 { val: x } - BLS381 { val: y };
        z.lo()
    }

    fn sub_hi(&self, inputs: [U256; 4]) -> U256 {
        let [x0, x1, y0, y1] = inputs;
        let x = U512::from(x0) + (U512::from(x1) << 256);
        let y = U512::from(y0) + (U512::from(y1) << 256);
        let z = BLS381 { val: x } - BLS381 { val: y };
        z.hi()
    }

    fn field_extension_inverse(&self, n: usize, f: [U256; 12]) -> U256 {
        let f: Fp12<BN254> = unsafe { transmute(f) };
        let f_inv: [U256; 12] = unsafe { transmute(f.inv()) };
        f_inv[n]
    }
}

fn modexp(x: U256, e: U256, n: U256) -> Result<U256, ProgramError> {
    let mut current = x;
    let mut product = U256::one();

    for j in 0..256 {
        if e.bit(j) {
            product = U256::try_from(product.full_mul(current) % n)
                .map_err(|_| ProgramError::ProverInputError(InvalidInput))?;
        }
        current = U256::try_from(current.full_mul(current) % n)
            .map_err(|_| ProgramError::ProverInputError(InvalidInput))?;
    }

    Ok(product)
}

/// See EIP-4844: <https://eips.ethereum.org/EIPS/eip-4844#helpers>.
fn fake_exponential(factor: U256, numerator: U256, denominator: U256) -> U256 {
    if factor.is_zero() || numerator.is_zero() {
        return factor;
    }

    let mut i = 1;
    let mut output = U256::zero();
    let mut numerator_accum = factor * denominator;
    while !numerator_accum.is_zero() {
        output += numerator_accum;
        numerator_accum = (numerator_accum * numerator) / (denominator * i);
        i += 1;
    }

    output / denominator
}
