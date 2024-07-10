use core::array::from_fn;
use core::fmt::Debug;

use anyhow::Result;
use ethereum_types::{BigEndianHash, U256};
use plonky2::field::extension::Extendable;
use plonky2::gates::exponentiation::ExponentiationGate;
use plonky2::gates::gate::GateRef;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::{HashOut, MerkleCapTarget, RichField};
use plonky2::hash::hashing::PlonkyPermutation;
use plonky2::iop::challenger::RecursiveChallenger;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, Witness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::util::serialization::{
    Buffer, GateSerializer, IoResult, Read, WitnessGeneratorSerializer, Write,
};
use plonky2_util::log2_ceil;
use starky::config::StarkConfig;
use starky::cross_table_lookup::{CrossTableLookup, CtlCheckVarsTarget};
use starky::lookup::{GrandProductChallenge, GrandProductChallengeSet};
use starky::proof::{StarkProofTarget, StarkProofWithMetadata};
use starky::recursive_verifier::{
    add_virtual_stark_proof, set_stark_proof_target, verify_stark_proof_with_challenges_circuit,
};
use starky::stark::Stark;

use crate::all_stark::Table;
use crate::cpu::kernel::aggregator::KERNEL;
use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::memory::segments::Segment;
use crate::memory::VALUE_LIMBS;
use crate::proof::{
    BlockHashes, BlockHashesTarget, BlockMetadata, BlockMetadataTarget, ExtraBlockData,
    ExtraBlockDataTarget, MemCap, MemCapTarget, PublicValues, PublicValuesTarget, RegistersData,
    RegistersDataTarget, TrieRoots, TrieRootsTarget,
};
use crate::util::{h256_limbs, u256_limbs, u256_to_u32, u256_to_u64};
use crate::witness::errors::ProgramError;

pub(crate) struct PublicInputs<T: Copy + Default + Eq + PartialEq + Debug, P: PlonkyPermutation<T>>
{
    pub(crate) trace_cap: Vec<Vec<T>>,
    pub(crate) ctl_zs_first: Vec<T>,
    pub(crate) ctl_challenges: GrandProductChallengeSet<T>,
    pub(crate) challenger_state_before: P,
    pub(crate) challenger_state_after: P,
}

impl<T: Copy + Debug + Default + Eq + PartialEq, P: PlonkyPermutation<T>> PublicInputs<T, P> {
    pub(crate) fn from_vec(v: &[T], config: &StarkConfig) -> Self {
        // TODO: Document magic number 4; probably comes from
        // Ethereum 256 bits = 4 * Goldilocks 64 bits
        let nelts = config.fri_config.num_cap_elements();
        let mut trace_cap = Vec::with_capacity(nelts);
        for i in 0..nelts {
            trace_cap.push(v[4 * i..4 * (i + 1)].to_vec());
        }
        let mut iter = v.iter().copied().skip(4 * nelts);
        let ctl_challenges = GrandProductChallengeSet {
            challenges: (0..config.num_challenges)
                .map(|_| GrandProductChallenge {
                    beta: iter.next().unwrap(),
                    gamma: iter.next().unwrap(),
                })
                .collect(),
        };
        let challenger_state_before = P::new(&mut iter);
        let challenger_state_after = P::new(&mut iter);
        let ctl_zs_first: Vec<_> = iter.collect();

        Self {
            trace_cap,
            ctl_zs_first,
            ctl_challenges,
            challenger_state_before,
            challenger_state_after,
        }
    }
}

/// Represents a circuit which recursively verifies a STARK proof.
#[derive(Eq, PartialEq, Debug)]
pub(crate) struct StarkWrapperCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
{
    pub(crate) circuit: CircuitData<F, C, D>,
    pub(crate) stark_proof_target: StarkProofTarget<D>,
    pub(crate) ctl_challenges_target: GrandProductChallengeSet<Target>,
    pub(crate) init_challenger_state_target:
        <C::Hasher as AlgebraicHasher<F>>::AlgebraicPermutation,
    pub(crate) zero_target: Target,
}

impl<F, C, const D: usize> StarkWrapperCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
{
    pub(crate) fn to_buffer(
        &self,
        buffer: &mut Vec<u8>,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<()> {
        buffer.write_circuit_data(&self.circuit, gate_serializer, generator_serializer)?;
        buffer.write_target_vec(self.init_challenger_state_target.as_ref())?;
        buffer.write_target(self.zero_target)?;
        self.stark_proof_target.to_buffer(buffer)?;
        self.ctl_challenges_target.to_buffer(buffer)?;

        Ok(())
    }

    pub(crate) fn from_buffer(
        buffer: &mut Buffer,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<Self> {
        let circuit = buffer.read_circuit_data(gate_serializer, generator_serializer)?;
        let target_vec = buffer.read_target_vec()?;
        let init_challenger_state_target =
            <C::Hasher as AlgebraicHasher<F>>::AlgebraicPermutation::new(target_vec);
        let zero_target = buffer.read_target()?;
        let stark_proof_target = StarkProofTarget::from_buffer(buffer)?;
        let ctl_challenges_target = GrandProductChallengeSet::from_buffer(buffer)?;

        Ok(Self {
            circuit,
            stark_proof_target,
            ctl_challenges_target,
            init_challenger_state_target,
            zero_target,
        })
    }

    pub(crate) fn prove(
        &self,
        proof_with_metadata: &StarkProofWithMetadata<F, C, D>,
        ctl_challenges: &GrandProductChallengeSet<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut inputs = PartialWitness::new();

        set_stark_proof_target(
            &mut inputs,
            &self.stark_proof_target,
            &proof_with_metadata.proof,
            self.zero_target,
        );

        for (challenge_target, challenge) in self
            .ctl_challenges_target
            .challenges
            .iter()
            .zip(&ctl_challenges.challenges)
        {
            inputs.set_target(challenge_target.beta, challenge.beta);
            inputs.set_target(challenge_target.gamma, challenge.gamma);
        }

        inputs.set_target_arr(
            self.init_challenger_state_target.as_ref(),
            proof_with_metadata.init_challenger_state.as_ref(),
        );

        self.circuit.prove(inputs)
    }
}

/// Represents a circuit which recursively verifies a PLONK proof.
#[derive(Eq, PartialEq, Debug)]
pub(crate) struct PlonkWrapperCircuit<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub(crate) circuit: CircuitData<F, C, D>,
    pub(crate) proof_with_pis_target: ProofWithPublicInputsTarget<D>,
}

impl<F, C, const D: usize> PlonkWrapperCircuit<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
{
    pub(crate) fn prove(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut inputs = PartialWitness::new();
        inputs.set_proof_with_pis_target(&self.proof_with_pis_target, proof);
        self.circuit.prove(inputs)
    }
}

/// Returns the recursive STARK circuit.
pub(crate) fn recursive_stark_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
    const D: usize,
>(
    table: Table,
    stark: &S,
    degree_bits: usize,
    cross_table_lookups: &[CrossTableLookup<F>],
    inner_config: &StarkConfig,
    circuit_config: &CircuitConfig,
    min_degree_bits: usize,
) -> StarkWrapperCircuit<F, C, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let mut builder = CircuitBuilder::<F, D>::new(circuit_config.clone());
    let zero_target = builder.zero();

    let num_lookup_columns = stark.num_lookup_helper_columns(inner_config);
    let (total_num_helpers, num_ctl_zs, num_helpers_by_ctl) =
        CrossTableLookup::num_ctl_helpers_zs_all(
            cross_table_lookups,
            *table,
            inner_config.num_challenges,
            stark.constraint_degree(),
        );
    let num_ctl_helper_zs = num_ctl_zs + total_num_helpers;

    let stark_proof_target = add_virtual_stark_proof(
        &mut builder,
        stark,
        inner_config,
        degree_bits,
        num_ctl_helper_zs,
        num_ctl_zs,
    );

    builder.register_public_inputs(
        &stark_proof_target
            .trace_cap
            .0
            .iter()
            .flat_map(|h| h.elements)
            .collect::<Vec<_>>(),
    );

    let ctl_challenges_target = GrandProductChallengeSet {
        challenges: (0..inner_config.num_challenges)
            .map(|_| GrandProductChallenge {
                beta: builder.add_virtual_public_input(),
                gamma: builder.add_virtual_public_input(),
            })
            .collect(),
    };

    let ctl_vars = CtlCheckVarsTarget::from_proof(
        *table,
        &stark_proof_target,
        cross_table_lookups,
        &ctl_challenges_target,
        num_lookup_columns,
        total_num_helpers,
        &num_helpers_by_ctl,
    );

    let init_challenger_state_target =
        <C::Hasher as AlgebraicHasher<F>>::AlgebraicPermutation::new(std::iter::from_fn(|| {
            Some(builder.add_virtual_public_input())
        }));
    let mut challenger =
        RecursiveChallenger::<F, C::Hasher, D>::from_state(init_challenger_state_target);
    let challenges = stark_proof_target.get_challenges::<F, C>(
        &mut builder,
        &mut challenger,
        Some(&ctl_challenges_target),
        true,
        inner_config,
    );
    let challenger_state = challenger.compact(&mut builder);
    builder.register_public_inputs(challenger_state.as_ref());

    builder.register_public_inputs(stark_proof_target.openings.ctl_zs_first.as_ref().unwrap());

    verify_stark_proof_with_challenges_circuit::<F, C, _, D>(
        &mut builder,
        stark,
        &stark_proof_target,
        &[], // public inputs
        challenges,
        Some(&ctl_vars),
        inner_config,
    );

    add_common_recursion_gates(&mut builder);

    // Pad to the minimum degree.
    while log2_ceil(builder.num_gates()) < min_degree_bits {
        builder.add_gate(NoopGate, vec![]);
    }

    let circuit = builder.build::<C>();
    StarkWrapperCircuit {
        circuit,
        stark_proof_target,
        ctl_challenges_target,
        init_challenger_state_target,
        zero_target,
    }
}

/// Add gates that are sometimes used by recursive circuits, even if it's not
/// actually used by this particular recursive circuit. This is done for
/// uniformity. We sometimes want all recursion circuits to have the same gate
/// set, so that we can do 1-of-n conditional recursion efficiently.
pub(crate) fn add_common_recursion_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) {
    builder.add_gate_to_gate_set(GateRef::new(ExponentiationGate::new_from_config(
        &builder.config,
    )));
}

/// Recursive version of `get_memory_extra_looking_sum`.
pub(crate) fn get_memory_extra_looking_sum_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    public_values: &PublicValuesTarget,
    challenge: GrandProductChallenge<Target>,
) -> Target {
    let mut sum = builder.zero();

    // Add metadata writes.
    let block_fields_scalars = [
        (
            GlobalMetadata::BlockTimestamp,
            public_values.block_metadata.block_timestamp,
        ),
        (
            GlobalMetadata::BlockNumber,
            public_values.block_metadata.block_number,
        ),
        (
            GlobalMetadata::BlockDifficulty,
            public_values.block_metadata.block_difficulty,
        ),
        (
            GlobalMetadata::BlockGasLimit,
            public_values.block_metadata.block_gaslimit,
        ),
        (
            GlobalMetadata::BlockChainId,
            public_values.block_metadata.block_chain_id,
        ),
        (
            GlobalMetadata::BlockGasUsed,
            public_values.block_metadata.block_gas_used,
        ),
        (
            GlobalMetadata::BlockGasUsedBefore,
            public_values.extra_block_data.gas_used_before,
        ),
        (
            GlobalMetadata::BlockGasUsedAfter,
            public_values.extra_block_data.gas_used_after,
        ),
        (
            GlobalMetadata::TxnNumberBefore,
            public_values.extra_block_data.txn_number_before,
        ),
        (
            GlobalMetadata::TxnNumberAfter,
            public_values.extra_block_data.txn_number_after,
        ),
    ];

    let beneficiary_random_base_fee_cur_hash_fields: [(GlobalMetadata, &[Target]); 4] = [
        (
            GlobalMetadata::BlockBeneficiary,
            &public_values.block_metadata.block_beneficiary,
        ),
        (
            GlobalMetadata::BlockRandom,
            &public_values.block_metadata.block_random,
        ),
        (
            GlobalMetadata::BlockBaseFee,
            &public_values.block_metadata.block_base_fee,
        ),
        (
            GlobalMetadata::BlockCurrentHash,
            &public_values.block_hashes.cur_hash,
        ),
    ];

    let metadata_segment =
        builder.constant(F::from_canonical_usize(Segment::GlobalMetadata.unscale()));
    block_fields_scalars.map(|(field, target)| {
        // Each of those fields fit in 32 bits, hence in a single Target.
        sum = add_data_write(
            builder,
            challenge,
            sum,
            metadata_segment,
            field.unscale(),
            &[target],
        );
    });

    beneficiary_random_base_fee_cur_hash_fields.map(|(field, targets)| {
        sum = add_data_write(
            builder,
            challenge,
            sum,
            metadata_segment,
            field.unscale(),
            targets,
        );
    });

    // Add block hashes writes.
    let block_hashes_segment =
        builder.constant(F::from_canonical_usize(Segment::BlockHashes.unscale()));
    for i in 0..256 {
        sum = add_data_write(
            builder,
            challenge,
            sum,
            block_hashes_segment,
            i,
            &public_values.block_hashes.prev_hashes[8 * i..8 * (i + 1)],
        );
    }

    // Add block bloom filters writes.
    let bloom_segment =
        builder.constant(F::from_canonical_usize(Segment::GlobalBlockBloom.unscale()));
    for i in 0..8 {
        sum = add_data_write(
            builder,
            challenge,
            sum,
            bloom_segment,
            i,
            &public_values.block_metadata.block_bloom[i * 8..(i + 1) * 8],
        );
    }

    // Add trie roots writes.
    let trie_fields = [
        (
            GlobalMetadata::StateTrieRootDigestBefore,
            public_values.trie_roots_before.state_root,
        ),
        (
            GlobalMetadata::TransactionTrieRootDigestBefore,
            public_values.trie_roots_before.transactions_root,
        ),
        (
            GlobalMetadata::ReceiptTrieRootDigestBefore,
            public_values.trie_roots_before.receipts_root,
        ),
        (
            GlobalMetadata::StateTrieRootDigestAfter,
            public_values.trie_roots_after.state_root,
        ),
        (
            GlobalMetadata::TransactionTrieRootDigestAfter,
            public_values.trie_roots_after.transactions_root,
        ),
        (
            GlobalMetadata::ReceiptTrieRootDigestAfter,
            public_values.trie_roots_after.receipts_root,
        ),
    ];

    trie_fields.map(|(field, targets)| {
        sum = add_data_write(
            builder,
            challenge,
            sum,
            metadata_segment,
            field.unscale(),
            &targets,
        );
    });

    // Add kernel hash and kernel length.
    let kernel_hash_limbs = h256_limbs::<F>(KERNEL.code_hash);
    let kernel_hash_targets: [Target; 8] = from_fn(|i| builder.constant(kernel_hash_limbs[i]));
    sum = add_data_write(
        builder,
        challenge,
        sum,
        metadata_segment,
        GlobalMetadata::KernelHash.unscale(),
        &kernel_hash_targets,
    );
    let kernel_len_target = builder.constant(F::from_canonical_usize(KERNEL.code.len()));
    sum = add_data_write(
        builder,
        challenge,
        sum,
        metadata_segment,
        GlobalMetadata::KernelLen.unscale(),
        &[kernel_len_target],
    );

    // Write registers.
    let registers_segment =
        builder.constant(F::from_canonical_usize(Segment::RegistersStates.unscale()));
    let registers_before: [&[Target]; 6] = [
        &[public_values.registers_before.program_counter],
        &[public_values.registers_before.is_kernel],
        &[public_values.registers_before.stack_len],
        &public_values.registers_before.stack_top,
        &[public_values.registers_before.context],
        &[public_values.registers_before.gas_used],
    ];
    for i in 0..registers_before.len() {
        sum = add_data_write(
            builder,
            challenge,
            sum,
            registers_segment,
            i,
            registers_before[i],
        );
    }

    let registers_after: [&[Target]; 6] = [
        &[public_values.registers_after.program_counter],
        &[public_values.registers_after.is_kernel],
        &[public_values.registers_after.stack_len],
        &public_values.registers_after.stack_top,
        &[public_values.registers_after.context],
        &[public_values.registers_after.gas_used],
    ];
    for i in 0..registers_before.len() {
        sum = add_data_write(
            builder,
            challenge,
            sum,
            registers_segment,
            registers_before.len() + i,
            registers_after[i],
        );
    }

    sum
}

fn add_data_write<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    challenge: GrandProductChallenge<Target>,
    running_sum: Target,
    segment: Target,
    idx: usize,
    val: &[Target],
) -> Target {
    debug_assert!(val.len() <= VALUE_LIMBS);
    let len = core::cmp::min(val.len(), VALUE_LIMBS);

    let row = builder.add_virtual_targets(13);
    // is_read = false
    builder.assert_zero(row[0]);
    // context = 0
    builder.assert_zero(row[1]);
    // segment
    builder.connect(row[2], segment);
    // virtual
    let field_target = builder.constant(F::from_canonical_usize(idx));
    builder.connect(row[3], field_target);

    // values
    for j in 0..len {
        // connect the actual value limbs
        builder.connect(row[4 + j], val[j]);
    }
    for j in len..VALUE_LIMBS {
        // assert that the remaining limbs are 0
        builder.assert_zero(row[4 + j]);
    }

    // timestamp = 2
    let two = builder.constant(F::TWO);
    builder.connect(row[12], two);

    let combined = challenge.combine_base_circuit(builder, &row);
    let inverse = builder.inverse(combined);
    builder.add(running_sum, inverse)
}

pub(crate) fn add_virtual_public_values<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    len_mem_cap: usize,
) -> PublicValuesTarget {
    let trie_roots_before = add_virtual_trie_roots(builder);
    let trie_roots_after = add_virtual_trie_roots(builder);
    let block_metadata = add_virtual_block_metadata(builder);
    let block_hashes = add_virtual_block_hashes(builder);
    let extra_block_data = add_virtual_extra_block_data(builder);
    let registers_before = add_virtual_registers_data(builder);
    let registers_after = add_virtual_registers_data(builder);

    let mem_before = MemCapTarget {
        mem_cap: MerkleCapTarget(builder.add_virtual_hashes_public_input(len_mem_cap)),
    };
    let mem_after = MemCapTarget {
        mem_cap: MerkleCapTarget(builder.add_virtual_hashes_public_input(len_mem_cap)),
    };

    PublicValuesTarget {
        trie_roots_before,
        trie_roots_after,
        block_metadata,
        block_hashes,
        extra_block_data,
        registers_before,
        registers_after,
        mem_before,
        mem_after,
    }
}

pub(crate) fn add_virtual_trie_roots<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> TrieRootsTarget {
    let state_root = builder.add_virtual_public_input_arr();
    let transactions_root = builder.add_virtual_public_input_arr();
    let receipts_root = builder.add_virtual_public_input_arr();
    TrieRootsTarget {
        state_root,
        transactions_root,
        receipts_root,
    }
}

pub(crate) fn add_virtual_block_metadata<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> BlockMetadataTarget {
    let block_beneficiary = builder.add_virtual_public_input_arr();
    let block_timestamp = builder.add_virtual_public_input();
    let block_number = builder.add_virtual_public_input();
    let block_difficulty = builder.add_virtual_public_input();
    let block_random = builder.add_virtual_public_input_arr();
    let block_gaslimit = builder.add_virtual_public_input();
    let block_chain_id = builder.add_virtual_public_input();
    let block_base_fee = builder.add_virtual_public_input_arr();
    let block_gas_used = builder.add_virtual_public_input();
    let block_bloom = builder.add_virtual_public_input_arr();
    BlockMetadataTarget {
        block_beneficiary,
        block_timestamp,
        block_number,
        block_difficulty,
        block_random,
        block_gaslimit,
        block_chain_id,
        block_base_fee,
        block_gas_used,
        block_bloom,
    }
}

pub(crate) fn add_virtual_block_hashes<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> BlockHashesTarget {
    let prev_hashes = builder.add_virtual_public_input_arr();
    let cur_hash = builder.add_virtual_public_input_arr();
    BlockHashesTarget {
        prev_hashes,
        cur_hash,
    }
}
pub(crate) fn add_virtual_extra_block_data<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> ExtraBlockDataTarget {
    let checkpoint_state_trie_root = builder.add_virtual_public_input_arr();
    let txn_number_before = builder.add_virtual_public_input();
    let txn_number_after = builder.add_virtual_public_input();
    let gas_used_before = builder.add_virtual_public_input();
    let gas_used_after = builder.add_virtual_public_input();
    ExtraBlockDataTarget {
        checkpoint_state_trie_root,
        txn_number_before,
        txn_number_after,
        gas_used_before,
        gas_used_after,
    }
}

pub(crate) fn add_virtual_registers_data<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> RegistersDataTarget {
    let program_counter = builder.add_virtual_public_input();
    let is_kernel = builder.add_virtual_public_input();
    let stack_len = builder.add_virtual_public_input();
    let stack_top = builder.add_virtual_public_input_arr();
    let context = builder.add_virtual_public_input();
    let gas_used = builder.add_virtual_public_input();
    RegistersDataTarget {
        program_counter,
        is_kernel,
        stack_len,
        stack_top,
        context,
        gas_used,
    }
}

pub(crate) fn debug_public_values(public_values: &PublicValues) {
    log::debug!("Public Values:");
    log::debug!(
        "  Trie Roots Before: {:?}",
        &public_values.trie_roots_before
    );
    log::debug!("  Trie Roots After: {:?}", &public_values.trie_roots_after);
    log::debug!("  Block Metadata: {:?}", &public_values.block_metadata);
    log::debug!("  Block Hashes: {:?}", &public_values.block_hashes);
    log::debug!("  Extra Block Data: {:?}", &public_values.extra_block_data);
}

pub fn set_public_value_targets<F, W, const D: usize>(
    witness: &mut W,
    public_values_target: &PublicValuesTarget,
    public_values: &PublicValues,
) -> Result<(), ProgramError>
where
    F: RichField + Extendable<D>,
    W: Witness<F>,
{
    debug_public_values(public_values);

    set_trie_roots_target(
        witness,
        &public_values_target.trie_roots_before,
        &public_values.trie_roots_before,
    );
    set_trie_roots_target(
        witness,
        &public_values_target.trie_roots_after,
        &public_values.trie_roots_after,
    );
    set_block_metadata_target(
        witness,
        &public_values_target.block_metadata,
        &public_values.block_metadata,
    )?;
    set_block_hashes_target(
        witness,
        &public_values_target.block_hashes,
        &public_values.block_hashes,
    );
    set_extra_public_values_target(
        witness,
        &public_values_target.extra_block_data,
        &public_values.extra_block_data,
    )?;
    set_registers_target(
        witness,
        &public_values_target.registers_before,
        &public_values.registers_before,
    )?;
    set_registers_target(
        witness,
        &public_values_target.registers_after,
        &public_values.registers_after,
    )?;

    set_mem_cap_target(
        witness,
        &public_values_target.mem_before,
        &public_values.mem_before,
    )?;
    set_mem_cap_target(
        witness,
        &public_values_target.mem_after,
        &public_values.mem_after,
    )?;

    Ok(())
}

pub(crate) fn set_trie_roots_target<F, W, const D: usize>(
    witness: &mut W,
    trie_roots_target: &TrieRootsTarget,
    trie_roots: &TrieRoots,
) where
    F: RichField + Extendable<D>,
    W: Witness<F>,
{
    for (i, limb) in trie_roots.state_root.into_uint().0.into_iter().enumerate() {
        witness.set_target(
            trie_roots_target.state_root[2 * i],
            F::from_canonical_u32(limb as u32),
        );
        witness.set_target(
            trie_roots_target.state_root[2 * i + 1],
            F::from_canonical_u32((limb >> 32) as u32),
        );
    }

    for (i, limb) in trie_roots
        .transactions_root
        .into_uint()
        .0
        .into_iter()
        .enumerate()
    {
        witness.set_target(
            trie_roots_target.transactions_root[2 * i],
            F::from_canonical_u32(limb as u32),
        );
        witness.set_target(
            trie_roots_target.transactions_root[2 * i + 1],
            F::from_canonical_u32((limb >> 32) as u32),
        );
    }

    for (i, limb) in trie_roots
        .receipts_root
        .into_uint()
        .0
        .into_iter()
        .enumerate()
    {
        witness.set_target(
            trie_roots_target.receipts_root[2 * i],
            F::from_canonical_u32(limb as u32),
        );
        witness.set_target(
            trie_roots_target.receipts_root[2 * i + 1],
            F::from_canonical_u32((limb >> 32) as u32),
        );
    }
}

pub(crate) fn set_block_metadata_target<F, W, const D: usize>(
    witness: &mut W,
    block_metadata_target: &BlockMetadataTarget,
    block_metadata: &BlockMetadata,
) -> Result<(), ProgramError>
where
    F: RichField + Extendable<D>,
    W: Witness<F>,
{
    let beneficiary_limbs: [F; 5] =
        u256_limbs::<F>(U256::from_big_endian(&block_metadata.block_beneficiary.0))[..5]
            .try_into()
            .unwrap();
    witness.set_target_arr(&block_metadata_target.block_beneficiary, &beneficiary_limbs);
    witness.set_target(
        block_metadata_target.block_timestamp,
        u256_to_u32(block_metadata.block_timestamp)?,
    );
    witness.set_target(
        block_metadata_target.block_number,
        u256_to_u32(block_metadata.block_number)?,
    );
    witness.set_target(
        block_metadata_target.block_difficulty,
        u256_to_u32(block_metadata.block_difficulty)?,
    );
    witness.set_target_arr(
        &block_metadata_target.block_random,
        &h256_limbs(block_metadata.block_random),
    );
    witness.set_target(
        block_metadata_target.block_gaslimit,
        u256_to_u32(block_metadata.block_gaslimit)?,
    );
    witness.set_target(
        block_metadata_target.block_chain_id,
        u256_to_u32(block_metadata.block_chain_id)?,
    );
    // Basefee fits in 2 limbs
    let basefee = u256_to_u64(block_metadata.block_base_fee)?;
    witness.set_target(block_metadata_target.block_base_fee[0], basefee.0);
    witness.set_target(block_metadata_target.block_base_fee[1], basefee.1);
    witness.set_target(
        block_metadata_target.block_gas_used,
        u256_to_u32(block_metadata.block_gas_used)?,
    );
    let mut block_bloom_limbs = [F::ZERO; 64];
    for (i, limbs) in block_bloom_limbs.chunks_exact_mut(8).enumerate() {
        limbs.copy_from_slice(&u256_limbs(block_metadata.block_bloom[i]));
    }
    witness.set_target_arr(&block_metadata_target.block_bloom, &block_bloom_limbs);

    Ok(())
}

pub(crate) fn set_block_hashes_target<F, W, const D: usize>(
    witness: &mut W,
    block_hashes_target: &BlockHashesTarget,
    block_hashes: &BlockHashes,
) where
    F: RichField + Extendable<D>,
    W: Witness<F>,
{
    for i in 0..256 {
        let block_hash_limbs: [F; 8] = h256_limbs::<F>(block_hashes.prev_hashes[i]);
        witness.set_target_arr(
            &block_hashes_target.prev_hashes[8 * i..8 * (i + 1)],
            &block_hash_limbs,
        );
    }
    let cur_block_hash_limbs: [F; 8] = h256_limbs::<F>(block_hashes.cur_hash);
    witness.set_target_arr(&block_hashes_target.cur_hash, &cur_block_hash_limbs);
}

pub(crate) fn set_extra_public_values_target<F, W, const D: usize>(
    witness: &mut W,
    ed_target: &ExtraBlockDataTarget,
    ed: &ExtraBlockData,
) -> Result<(), ProgramError>
where
    F: RichField + Extendable<D>,
    W: Witness<F>,
{
    witness.set_target_arr(
        &ed_target.checkpoint_state_trie_root,
        &h256_limbs::<F>(ed.checkpoint_state_trie_root),
    );
    witness.set_target(
        ed_target.txn_number_before,
        u256_to_u32(ed.txn_number_before)?,
    );
    witness.set_target(
        ed_target.txn_number_after,
        u256_to_u32(ed.txn_number_after)?,
    );
    witness.set_target(ed_target.gas_used_before, u256_to_u32(ed.gas_used_before)?);
    witness.set_target(ed_target.gas_used_after, u256_to_u32(ed.gas_used_after)?);

    Ok(())
}

pub(crate) fn set_registers_target<F, W, const D: usize>(
    witness: &mut W,
    rd_target: &RegistersDataTarget,
    rd: &RegistersData,
) -> Result<(), ProgramError>
where
    F: RichField + Extendable<D>,
    W: Witness<F>,
{
    witness.set_target(rd_target.program_counter, u256_to_u32(rd.program_counter)?);
    witness.set_target(rd_target.is_kernel, u256_to_u32(rd.is_kernel)?);
    witness.set_target(rd_target.stack_len, u256_to_u32(rd.stack_len)?);
    witness.set_target_arr(&rd_target.stack_top, &u256_limbs(rd.stack_top));
    witness.set_target(rd_target.context, u256_to_u32(rd.context)?);
    witness.set_target(rd_target.gas_used, u256_to_u32(rd.gas_used)?);

    Ok(())
}

pub(crate) fn set_mem_cap_target<F, W, const D: usize>(
    witness: &mut W,
    mc_target: &MemCapTarget,
    mc: &MemCap,
) -> Result<(), ProgramError>
where
    F: RichField + Extendable<D>,
    W: Witness<F>,
{
    for i in 0..mc.mem_cap.len() {
        witness.set_hash_target(
            mc_target.mem_cap.0[i],
            HashOut {
                elements: mc.mem_cap[i].map(|elt| F::from_canonical_u64(elt.as_u64())),
            },
        );
    }
    Ok(())
}
