mod account_code;
mod add11;
mod balance;
mod bignum;
mod blake2_f;
mod blobhash;
mod block_hash;
mod bls381;
mod bn254;
mod core;
mod ecc;
mod exp;
mod hash;
mod init_exc_stop;
mod kernel_consistency;
mod log;
mod mcopy;
mod mpt;
mod packing;
mod receipt;
mod rlp;
mod signed_syscalls;
mod transaction_parsing;
mod transient_storage;

use std::{
    collections::{BTreeSet, HashMap},
    ops::Range,
    str::FromStr,
};

use anyhow::Result;
use ethereum_types::U256;
use plonky2::field::types::Field;

use super::{
    aggregator::KERNEL,
    constants::{
        context_metadata::ContextMetadata, global_metadata::GlobalMetadata,
        txn_fields::NormalizedTxnField,
    },
    interpreter::Interpreter,
};
use crate::{
    memory::segments::Segment,
    witness::{
        errors::ProgramError,
        memory::{MemoryAddress, MemoryContextState},
    },
};

pub(crate) fn u256ify<'a>(hexes: impl IntoIterator<Item = &'a str>) -> Result<Vec<U256>> {
    Ok(hexes
        .into_iter()
        .map(U256::from_str)
        .collect::<Result<Vec<_>, _>>()?)
}

pub(crate) fn run_interpreter<F: Field>(
    initial_offset: usize,
    initial_stack: Vec<U256>,
) -> anyhow::Result<Interpreter<F>> {
    let mut interpreter = Interpreter::new(initial_offset, initial_stack, None);
    interpreter.run()?;
    Ok(interpreter)
}

#[derive(Clone)]
pub(crate) struct InterpreterMemoryInitialization {
    pub label: String,
    pub stack: Vec<U256>,
    pub segment: Segment,
    pub memory: Vec<(usize, Vec<U256>)>,
}

pub(crate) fn run_interpreter_with_memory<F: Field>(
    memory_init: InterpreterMemoryInitialization,
) -> anyhow::Result<Interpreter<F>> {
    let label = KERNEL.global_labels[&memory_init.label];
    let mut stack = memory_init.stack;
    stack.reverse();
    let mut interpreter = Interpreter::new(label, stack, None);
    for (pointer, data) in memory_init.memory {
        for (i, term) in data.iter().enumerate() {
            interpreter.generation_state.memory.set(
                MemoryAddress::new(0, memory_init.segment, pointer + i),
                *term,
            )
        }
    }
    interpreter.run()?;
    Ok(interpreter)
}

impl<F: Field> Interpreter<F> {
    pub(crate) fn get_txn_field(&self, field: NormalizedTxnField) -> U256 {
        // These fields are already scaled by their respective segment.
        self.generation_state.memory.contexts[0].segments[Segment::TxnFields.unscale()]
            .get(field.unscale())
    }

    pub(crate) fn set_txn_field(&mut self, field: NormalizedTxnField, value: U256) {
        // These fields are already scaled by their respective segment.
        self.generation_state.memory.contexts[0].segments[Segment::TxnFields.unscale()]
            .set(field.unscale(), value);
    }

    pub(crate) fn get_txn_data(&self) -> Vec<U256> {
        self.generation_state.memory.contexts[0].segments[Segment::TxnData.unscale()].content()
    }

    pub(crate) fn set_context_metadata_field(
        &mut self,
        ctx: usize,
        field: ContextMetadata,
        value: U256,
    ) {
        // These fields are already scaled by their respective segment.
        self.generation_state.memory.contexts[ctx].segments[Segment::ContextMetadata.unscale()]
            .set(field.unscale(), value)
    }

    pub(crate) fn get_global_metadata_field(&self, field: GlobalMetadata) -> U256 {
        // These fields are already scaled by their respective segment.
        let field = field.unscale();
        self.generation_state.memory.contexts[0].segments[Segment::GlobalMetadata.unscale()]
            .get(field)
    }

    pub(crate) fn set_global_metadata_field(&mut self, field: GlobalMetadata, value: U256) {
        // These fields are already scaled by their respective segment.
        let field = field.unscale();
        self.generation_state.memory.contexts[0].segments[Segment::GlobalMetadata.unscale()]
            .set(field, value)
    }

    pub(crate) fn get_trie_data(&self) -> Vec<U256> {
        self.generation_state.memory.contexts[0].segments[Segment::TrieData.unscale()]
            .content
            .iter()
            .filter_map(|&elt| elt)
            .collect::<Vec<_>>()
    }

    pub(crate) fn get_trie_data_mut(&mut self) -> &mut Vec<Option<U256>> {
        &mut self.generation_state.memory.contexts[0].segments[Segment::TrieData.unscale()].content
    }

    pub(crate) fn get_memory_segment(&self, segment: Segment) -> Vec<U256> {
        if self.is_preinitialized_segment(segment.unscale()) {
            let get_vals = |opt_vals: &[Option<U256>]| {
                opt_vals
                    .iter()
                    .map(|&elt| match elt {
                        Some(val) => val,
                        None => U256::zero(),
                    })
                    .collect::<Vec<U256>>()
            };
            let mut res = get_vals(
                &self
                    .generation_state
                    .memory
                    .preinitialized_segments
                    .get(&segment)
                    .expect("The segment should be in the preinitialized segments.")
                    .content,
            );
            let init_len = res.len();
            res.extend(&get_vals(
                &self.generation_state.memory.contexts[0].segments[segment.unscale()].content
                    [init_len..],
            ));
            res
        } else {
            self.generation_state.memory.contexts[0].segments[segment.unscale()].content()
        }
    }

    pub(crate) fn get_memory_segment_bytes(&self, segment: Segment) -> Vec<u8> {
        let content = self.get_memory_segment(segment);
        content.iter().map(|x| x.low_u32() as u8).collect()
    }

    pub(crate) fn get_current_general_memory(&self) -> Vec<U256> {
        self.generation_state.memory.contexts[self.context()].segments
            [Segment::KernelGeneral.unscale()]
        .content()
    }

    pub(crate) fn get_rlp_memory(&self) -> Vec<u8> {
        self.get_memory_segment_bytes(Segment::RlpRaw)
    }

    pub(crate) fn set_current_general_memory(&mut self, memory: Vec<U256>) {
        let context = self.context();
        self.generation_state.memory.contexts[context].segments[Segment::KernelGeneral.unscale()]
            .content = memory.iter().map(|&val| Some(val)).collect();
    }

    pub(crate) fn set_memory_segment(&mut self, segment: Segment, memory: Vec<U256>) {
        self.generation_state.memory.contexts[0].segments[segment.unscale()].content =
            memory.iter().map(|&val| Some(val)).collect();
    }

    pub(crate) fn set_memory_segment_bytes(&mut self, segment: Segment, memory: Vec<u8>) {
        self.generation_state.memory.contexts[0].segments[segment.unscale()].content = memory
            .into_iter()
            .map(|val| Some(U256::from(val)))
            .collect();
    }

    pub(crate) fn extend_memory_segment_bytes(&mut self, segment: Segment, memory: Vec<u8>) {
        self.generation_state.memory.contexts[0].segments[segment.unscale()]
            .content
            .extend(
                memory
                    .into_iter()
                    .map(|elt| Some(U256::from(elt)))
                    .collect::<Vec<_>>(),
            );
    }

    pub(crate) fn set_rlp_memory(&mut self, rlp: Vec<u8>) {
        self.set_memory_segment_bytes(Segment::RlpRaw, rlp)
    }

    pub(crate) fn set_code(&mut self, context: usize, code: Vec<u8>) {
        assert_ne!(context, 0, "Can't modify kernel code.");
        while self.generation_state.memory.contexts.len() <= context {
            self.generation_state
                .memory
                .contexts
                .push(MemoryContextState::default());
        }
        self.generation_state.memory.set(
            MemoryAddress::new(
                context,
                Segment::ContextMetadata,
                ContextMetadata::CodeSize.unscale(),
            ),
            code.len().into(),
        );
        self.generation_state.memory.contexts[context].segments[Segment::Code.unscale()].content =
            code.into_iter().map(|val| Some(U256::from(val))).collect();
    }

    pub(crate) fn set_jumpdest_analysis_inputs(&mut self, jumps: HashMap<usize, BTreeSet<usize>>) {
        self.generation_state.set_jumpdest_analysis_inputs(jumps);
    }

    pub(crate) fn extract_kernel_memory(self, segment: Segment, range: Range<usize>) -> Vec<U256> {
        let mut output: Vec<U256> = Vec::with_capacity(range.end);
        for i in range {
            let term = self
                .generation_state
                .memory
                .get_with_init(MemoryAddress::new(0, segment, i));
            output.push(term);
        }
        output
    }

    pub(crate) const fn stack_len(&self) -> usize {
        self.generation_state.registers.stack_len
    }

    pub(crate) const fn stack_top(&self) -> anyhow::Result<U256, ProgramError> {
        if self.stack_len() > 0 {
            Ok(self.generation_state.registers.stack_top)
        } else {
            Err(ProgramError::StackUnderflow)
        }
    }

    // Actually pushes in memory. Only used for tests.
    pub(crate) fn push(&mut self, x: U256) -> Result<(), ProgramError> {
        use crate::cpu::stack::MAX_USER_STACK_SIZE;

        if !self.is_kernel() && self.stack_len() >= MAX_USER_STACK_SIZE {
            return Err(ProgramError::StackOverflow);
        }
        if self.stack_len() > 0 {
            let top = self
                .stack_top()
                .expect("The stack is checked to be nonempty");
            let cur_len = self.stack_len();
            let stack_addr = MemoryAddress::new(self.context(), Segment::Stack, cur_len - 1);
            self.generation_state.memory.set(stack_addr, top);
        }
        self.generation_state.registers.stack_top = x;
        self.generation_state.registers.stack_len += 1;

        Ok(())
    }

    /// Actually popping the memory. Only used in tests.
    pub(crate) fn pop(&mut self) -> Result<U256, ProgramError> {
        use crate::witness::util::stack_peek;

        let result = stack_peek(&self.generation_state, 0);

        if self.stack_len() > 1 {
            let top = stack_peek(&self.generation_state, 1)?;
            self.generation_state.registers.stack_top = top;
        }
        self.generation_state.registers.stack_len -= 1;

        result
    }

    pub(crate) fn get_jumpdest_bit(&self, offset: usize) -> U256 {
        if self.generation_state.memory.contexts[self.context()].segments
            [Segment::JumpdestBits.unscale()]
        .content
        .len()
            > offset
        {
            // Even though we are in the interpreter, `JumpdestBits` is not part of the
            // preinitialized segments, so we don't need to carry out the additional checks
            // when get the value from memory.
            self.generation_state.memory.get_with_init(MemoryAddress {
                context: self.context(),
                segment: Segment::JumpdestBits.unscale(),
                virt: offset,
            })
        } else {
            0.into()
        }
    }

    pub(crate) fn get_jumpdest_bits(&self, context: usize) -> Vec<bool> {
        self.generation_state.memory.contexts[context].segments[Segment::JumpdestBits.unscale()]
            .content
            .iter()
            .map(|x| x.unwrap_or_default().bit(0))
            .collect()
    }

    pub(crate) fn set_is_kernel(&mut self, is_kernel: bool) {
        self.generation_state.registers.is_kernel = is_kernel
    }

    pub(crate) fn set_context(&mut self, context: usize) {
        if context == 0 {
            assert!(self.is_kernel());
        }

        while self.generation_state.memory.contexts.len() <= context {
            self.generation_state
                .memory
                .contexts
                .push(MemoryContextState::default());
        }

        self.generation_state.registers.context = context;
    }
}
