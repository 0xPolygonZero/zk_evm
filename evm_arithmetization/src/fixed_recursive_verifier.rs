use core::mem::{self, MaybeUninit};
use core::ops::Range;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::anyhow;
use hashbrown::HashMap;
use itertools::{zip_eq, Itertools};
use mpt_trie::partial_trie::{HashedPartialTrie, Node, PartialTrie};
use plonky2::field::extension::Extendable;
use plonky2::fri::FriParams;
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::{MerkleCapTarget, RichField, NUM_HASH_OUT_ELTS};
use plonky2::iop::challenger::RecursiveChallenger;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitData, VerifierCircuitTarget,
};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, GenericHashOut};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use plonky2::util::serialization::{
    Buffer, GateSerializer, IoResult, Read, WitnessGeneratorSerializer, Write,
};
use plonky2::util::timing::TimingTree;
use plonky2_util::log2_ceil;
use starky::config::StarkConfig;
use starky::cross_table_lookup::{verify_cross_table_lookups_circuit, CrossTableLookup};
use starky::lookup::{get_grand_product_challenge_set_target, GrandProductChallengeSet};
use starky::proof::StarkProofWithMetadata;
use starky::stark::Stark;

use crate::all_stark::{
    all_cross_table_lookups, AllStark, Table, KECCAK_TABLES_INDICES, MEMORY_CTL_IDX, NUM_CTLS,
    NUM_TABLES,
};
use crate::cpu::kernel::aggregator::KERNEL;
use crate::generation::segments::{GenerationSegmentData, SegmentDataIterator, SegmentError};
use crate::generation::{GenerationInputs, TrimmedGenerationInputs};
use crate::get_challenges::observe_public_values_target;
use crate::proof::{
    AllProof, BlockHashesTarget, BlockMetadataTarget, BurnAddrTarget, ExtraBlockData,
    ExtraBlockDataTarget, FinalPublicValues, FinalPublicValuesTarget, MemCapTarget, PublicValues,
    PublicValuesTarget, RegistersDataTarget, TrieRoots, TrieRootsTarget, DEFAULT_CAP_LEN,
    TARGET_HASH_SIZE,
};
use crate::prover::{check_abort_signal, features_check, prove};
use crate::recursive_verifier::{
    add_common_recursion_gates, add_virtual_final_public_values_public_input,
    add_virtual_public_values_public_input, get_memory_extra_looking_sum_circuit,
    recursive_stark_circuit, set_final_public_value_targets, set_public_value_targets,
    PlonkWrapperCircuit, PublicInputs, StarkWrapperCircuit,
};
use crate::util::h256_limbs;
use crate::verifier::initial_memory_merkle_cap;

/// The recursion threshold. We end a chain of recursive proofs once we reach
/// this size.
const THRESHOLD_DEGREE_BITS: usize = 13;

#[derive(Clone)]
pub struct ProverOutputData<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
{
    pub is_dummy: bool,
    pub proof_with_pis: ProofWithPublicInputs<F, C, D>,
    pub public_values: PublicValues,
}

/// Contains all recursive circuits used in the system. For each STARK and each
/// initial `degree_bits`, this contains a chain of recursive circuits for
/// shrinking that STARK from `degree_bits` to a constant
/// `THRESHOLD_DEGREE_BITS`. It also contains a special root circuit
/// for combining each STARK's shrunk wrapper proof into a single proof.
#[derive(Eq, PartialEq, Debug)]
pub struct AllRecursiveCircuits<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
{
    /// The EVM root circuit, which aggregates the (shrunk) per-table recursive
    /// proofs.
    pub root: RootCircuitData<F, C, D>,
    /// Same as above but without Keccak and KeccakSponge tables.
    pub root_no_keccak_tables: RootCircuitData<F, C, D>,
    /// The segment aggregation circuit, which verifies that two segment proofs
    /// that can either be root or aggregation proofs.
    pub segment_aggregation: SegmentAggregationCircuitData<F, C, D>,
    /// The transaction aggregation circuit, which verifies the aggregation of
    /// two proofs that can either be a segment aggregation representing a
    /// batch of transactions or an aggregation of those batches.
    pub txn_aggregation: TxnAggregationCircuitData<F, C, D>,
    /// The block circuit, which verifies a transaction aggregation proof and an
    /// optional previous block proof.
    pub block: BlockCircuitData<F, C, D>,
    /// A single wrapping layer on top of a block proof for easy aggregation
    /// with additional block proofs from other chains.
    pub block_wrapper: BlockWrapperCircuitData<F, C, D>,
    /// The two-to-one block aggregation circuit, which verifies two unrelated
    /// block proofs.
    pub two_to_one_block: TwoToOneBlockCircuitData<F, C, D>,
    /// Holds chains of circuits for each table and for each initial
    /// `degree_bits`.
    pub by_table: [RecursiveCircuitsForTable<F, C, D>; NUM_TABLES],
}

/// Data for the EVM root circuit, which is used to combine each STARK's shrunk
/// wrapper proof into a single proof.
#[derive(Eq, PartialEq, Debug)]
pub struct RootCircuitData<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub circuit: CircuitData<F, C, D>,
    proof_with_pis: [Option<ProofWithPublicInputsTarget<D>>; NUM_TABLES],
    /// For each table, various inner circuits may be used depending on the
    /// initial table size. This target holds the index of the circuit
    /// (within `final_circuits()`) that was used.
    index_verifier_data: [Option<Target>; NUM_TABLES],
    /// Public inputs containing public values.
    public_values: PublicValuesTarget,
    /// Public inputs used for cyclic verification. These aren't actually used
    /// for EVM root proofs; the circuit has them just to match the
    /// structure of aggregation proofs.
    cyclic_vk: VerifierCircuitTarget,
}

impl<F, C, const D: usize> RootCircuitData<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    fn to_buffer(
        &self,
        buffer: &mut Vec<u8>,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<()> {
        buffer.write_circuit_data(&self.circuit, gate_serializer, generator_serializer)?;

        // Serialize proof_with_pis, adding a flag for None values
        for proof in &self.proof_with_pis {
            if let Some(proof) = proof {
                buffer.write_u8(1)?; // Indicate that this proof is Some
                buffer.write_target_proof_with_public_inputs(proof)?;
            } else {
                buffer.write_u8(0)?; // Indicate that this proof is None
            }
        }

        // Serialize index_verifier_data, adding a flag for None values
        for index in &self.index_verifier_data {
            if let Some(index) = index {
                buffer.write_u8(1)?; // Indicate that this index is Some
                buffer.write_target(*index)?;
            } else {
                buffer.write_u8(0)?; // Indicate that this index is None
            }
        }

        self.public_values.to_buffer(buffer)?;
        buffer.write_target_verifier_circuit(&self.cyclic_vk)?;
        Ok(())
    }

    fn from_buffer(
        buffer: &mut Buffer,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<Self> {
        let circuit = buffer.read_circuit_data(gate_serializer, generator_serializer)?;

        // Deserialize proof_with_pis with a flag for None values
        let mut proof_with_pis = Vec::with_capacity(NUM_TABLES);
        for _ in 0..NUM_TABLES {
            let flag = buffer.read_u8()?; // Read the flag
            if flag == 1 {
                proof_with_pis.push(Some(buffer.read_target_proof_with_public_inputs()?));
            } else {
                proof_with_pis.push(None); // No proof for this table
            }
        }

        // Deserialize index_verifier_data with a flag for None values
        let mut index_verifier_data = Vec::with_capacity(NUM_TABLES);
        for _ in 0..NUM_TABLES {
            let flag = buffer.read_u8()?; // Read the flag
            if flag == 1 {
                index_verifier_data.push(Some(buffer.read_target()?));
            } else {
                index_verifier_data.push(None); // No index for this table
            }
        }

        let public_values = PublicValuesTarget::from_buffer(buffer)?;
        let cyclic_vk = buffer.read_target_verifier_circuit()?;

        Ok(Self {
            circuit,
            proof_with_pis: proof_with_pis.try_into().unwrap(),
            index_verifier_data: index_verifier_data.try_into().unwrap(),
            public_values,
            cyclic_vk,
        })
    }
}

/// Data for the segment aggregation circuit, which is used to compress two
/// segment proofs into one. Each inner proof can be either an EVM root proof or
/// another segment aggregation proof.
#[derive(Eq, PartialEq, Debug)]
pub struct SegmentAggregationCircuitData<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub circuit: CircuitData<F, C, D>,
    lhs: AggregationChildTarget<D>,
    rhs: AggregationChildWithDummyTarget<D>,
    public_values: PublicValuesTarget,
    cyclic_vk: VerifierCircuitTarget,
}

impl<F, C, const D: usize> SegmentAggregationCircuitData<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    fn to_buffer(
        &self,
        buffer: &mut Vec<u8>,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<()> {
        buffer.write_circuit_data(&self.circuit, gate_serializer, generator_serializer)?;
        buffer.write_target_verifier_circuit(&self.cyclic_vk)?;
        self.public_values.to_buffer(buffer)?;
        self.lhs.to_buffer(buffer)?;
        self.rhs.to_buffer(buffer)?;
        Ok(())
    }

    fn from_buffer(
        buffer: &mut Buffer,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<Self> {
        let circuit = buffer.read_circuit_data(gate_serializer, generator_serializer)?;
        let cyclic_vk = buffer.read_target_verifier_circuit()?;
        let public_values = PublicValuesTarget::from_buffer(buffer)?;
        let lhs = AggregationChildTarget::from_buffer(buffer)?;
        let rhs = AggregationChildWithDummyTarget::from_buffer(buffer)?;
        Ok(Self {
            circuit,
            lhs,
            rhs,
            public_values,
            cyclic_vk,
        })
    }
}

#[derive(Eq, PartialEq, Debug)]
struct AggregationChildWithDummyTarget<const D: usize> {
    is_agg: BoolTarget,
    is_dummy: BoolTarget,
    agg_proof: ProofWithPublicInputsTarget<D>,
    real_proof: ProofWithPublicInputsTarget<D>,
}

impl<const D: usize> AggregationChildWithDummyTarget<D> {
    fn to_buffer(&self, buffer: &mut Vec<u8>) -> IoResult<()> {
        buffer.write_target_bool(self.is_agg)?;
        buffer.write_target_bool(self.is_dummy)?;
        buffer.write_target_proof_with_public_inputs(&self.agg_proof)?;
        buffer.write_target_proof_with_public_inputs(&self.real_proof)?;
        Ok(())
    }

    fn from_buffer(buffer: &mut Buffer) -> IoResult<Self> {
        let is_agg = buffer.read_target_bool()?;
        let is_dummy = buffer.read_target_bool()?;
        let agg_proof = buffer.read_target_proof_with_public_inputs()?;
        let real_proof = buffer.read_target_proof_with_public_inputs()?;
        Ok(Self {
            is_agg,
            is_dummy,
            agg_proof,
            real_proof,
        })
    }

    // `len_mem_cap` is the length of the Merkle
    // caps for `MemBefore` and `MemAfter`.
    fn public_values<F: RichField + Extendable<D>>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PublicValuesTarget {
        let agg_pv = PublicValuesTarget::from_public_inputs(&self.agg_proof.public_inputs);
        let segment_pv = PublicValuesTarget::from_public_inputs(&self.real_proof.public_inputs);

        PublicValuesTarget::select(builder, self.is_agg, agg_pv, segment_pv)
    }
}

/// Data for the transaction aggregation circuit, which is used to compress two
/// proofs into one. Each inner proof can be either a segment aggregation proof
/// or another transaction aggregation proof.
#[derive(Eq, PartialEq, Debug)]
pub struct TxnAggregationCircuitData<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub circuit: CircuitData<F, C, D>,
    lhs: AggregationChildTarget<D>,
    rhs: AggregationChildTarget<D>,
    public_values: PublicValuesTarget,
    cyclic_vk: VerifierCircuitTarget,
}

impl<F, C, const D: usize> TxnAggregationCircuitData<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    fn to_buffer(
        &self,
        buffer: &mut Vec<u8>,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<()> {
        buffer.write_circuit_data(&self.circuit, gate_serializer, generator_serializer)?;
        buffer.write_target_verifier_circuit(&self.cyclic_vk)?;
        self.public_values.to_buffer(buffer)?;
        self.lhs.to_buffer(buffer)?;
        self.rhs.to_buffer(buffer)?;
        Ok(())
    }

    fn from_buffer(
        buffer: &mut Buffer,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<Self> {
        let circuit = buffer.read_circuit_data(gate_serializer, generator_serializer)?;
        let cyclic_vk = buffer.read_target_verifier_circuit()?;
        let public_values = PublicValuesTarget::from_buffer(buffer)?;
        let lhs = AggregationChildTarget::from_buffer(buffer)?;
        let rhs = AggregationChildTarget::from_buffer(buffer)?;
        Ok(Self {
            circuit,
            lhs,
            rhs,
            public_values,
            cyclic_vk,
        })
    }
}

#[derive(Eq, PartialEq, Debug)]
struct AggregationChildTarget<const D: usize> {
    is_agg: BoolTarget,
    agg_proof: ProofWithPublicInputsTarget<D>,
    base_proof: ProofWithPublicInputsTarget<D>,
}

impl<const D: usize> AggregationChildTarget<D> {
    fn to_buffer(&self, buffer: &mut Vec<u8>) -> IoResult<()> {
        buffer.write_target_bool(self.is_agg)?;
        buffer.write_target_proof_with_public_inputs(&self.agg_proof)?;
        buffer.write_target_proof_with_public_inputs(&self.base_proof)?;
        Ok(())
    }

    fn from_buffer(buffer: &mut Buffer) -> IoResult<Self> {
        let is_agg = buffer.read_target_bool()?;
        let agg_proof = buffer.read_target_proof_with_public_inputs()?;
        let base_proof = buffer.read_target_proof_with_public_inputs()?;
        Ok(Self {
            is_agg,
            agg_proof,
            base_proof,
        })
    }

    fn public_values<F: RichField + Extendable<D>>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PublicValuesTarget {
        let agg_pv = PublicValuesTarget::from_public_inputs(&self.agg_proof.public_inputs);
        let base_pv = PublicValuesTarget::from_public_inputs(&self.base_proof.public_inputs);
        PublicValuesTarget::select(builder, self.is_agg, agg_pv, base_pv)
    }

    fn public_inputs<F: RichField + Extendable<D>>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        zip_eq(
            &self.agg_proof.public_inputs,
            &self.base_proof.public_inputs,
        )
        .map(|(&agg_pv, &base_pv)| builder.select(self.is_agg, agg_pv, base_pv))
        .collect()
    }
}

/// Data for the block circuit, which is used to generate a final block proof,
/// and compress it with an optional parent proof if present.
#[derive(Eq, PartialEq, Debug)]
pub struct BlockCircuitData<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub circuit: CircuitData<F, C, D>,
    has_parent_block: BoolTarget,
    parent_block_proof: ProofWithPublicInputsTarget<D>,
    agg_root_proof: ProofWithPublicInputsTarget<D>,
    public_values: PublicValuesTarget,
    cyclic_vk: VerifierCircuitTarget,
}

impl<F, C, const D: usize> BlockCircuitData<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    fn to_buffer(
        &self,
        buffer: &mut Vec<u8>,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<()> {
        buffer.write_circuit_data(&self.circuit, gate_serializer, generator_serializer)?;
        buffer.write_target_bool(self.has_parent_block)?;
        buffer.write_target_proof_with_public_inputs(&self.parent_block_proof)?;
        buffer.write_target_proof_with_public_inputs(&self.agg_root_proof)?;
        self.public_values.to_buffer(buffer)?;
        buffer.write_target_verifier_circuit(&self.cyclic_vk)?;
        Ok(())
    }

    fn from_buffer(
        buffer: &mut Buffer,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<Self> {
        let circuit = buffer.read_circuit_data(gate_serializer, generator_serializer)?;
        let has_parent_block = buffer.read_target_bool()?;
        let parent_block_proof = buffer.read_target_proof_with_public_inputs()?;
        let agg_root_proof = buffer.read_target_proof_with_public_inputs()?;
        let public_values = PublicValuesTarget::from_buffer(buffer)?;
        let cyclic_vk = buffer.read_target_verifier_circuit()?;
        Ok(Self {
            circuit,
            has_parent_block,
            parent_block_proof,
            agg_root_proof,
            public_values,
            cyclic_vk,
        })
    }
}

/// Data for the block wrapper circuit, which is used to generate a wrapped
/// final block proof and obfuscate the remaining private elements of a chain.
#[derive(Eq, PartialEq, Debug)]
pub struct BlockWrapperCircuitData<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub circuit: CircuitData<F, C, D>,
    parent_block_proof: ProofWithPublicInputsTarget<D>,
    public_values: FinalPublicValuesTarget,
    cyclic_vk: VerifierCircuitTarget,
}

impl<F, C, const D: usize> BlockWrapperCircuitData<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    fn to_buffer(
        &self,
        buffer: &mut Vec<u8>,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<()> {
        buffer.write_circuit_data(&self.circuit, gate_serializer, generator_serializer)?;
        buffer.write_target_proof_with_public_inputs(&self.parent_block_proof)?;
        buffer.write_target_verifier_circuit(&self.cyclic_vk)?;
        self.public_values.to_buffer(buffer)
    }

    fn from_buffer(
        buffer: &mut Buffer,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<Self> {
        let circuit = buffer.read_circuit_data(gate_serializer, generator_serializer)?;
        let parent_block_proof = buffer.read_target_proof_with_public_inputs()?;
        let cyclic_vk = buffer.read_target_verifier_circuit()?;
        let public_values = FinalPublicValuesTarget::from_buffer(buffer)?;

        Ok(Self {
            circuit,
            parent_block_proof,
            public_values,
            cyclic_vk,
        })
    }
}

/// Data for the two-to-one block circuit, which is used to generate a
/// proof of two unrelated proofs.
#[derive(Eq, PartialEq, Debug)]
pub struct TwoToOneBlockCircuitData<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub circuit: CircuitData<F, C, D>,
    lhs: AggregationChildTarget<D>,
    rhs: AggregationChildTarget<D>,
    cyclic_vk: VerifierCircuitTarget,
}

impl<F, C, const D: usize> TwoToOneBlockCircuitData<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    fn to_buffer(
        &self,
        buffer: &mut Vec<u8>,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<()> {
        buffer.write_circuit_data(&self.circuit, gate_serializer, generator_serializer)?;
        self.lhs.to_buffer(buffer)?;
        self.rhs.to_buffer(buffer)?;
        buffer.write_target_verifier_circuit(&self.cyclic_vk)?;
        Ok(())
    }

    fn from_buffer(
        buffer: &mut Buffer,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<Self> {
        let circuit = buffer.read_circuit_data(gate_serializer, generator_serializer)?;
        let lhs = AggregationChildTarget::from_buffer(buffer)?;
        let rhs = AggregationChildTarget::from_buffer(buffer)?;
        let cyclic_vk = buffer.read_target_verifier_circuit()?;
        Ok(Self {
            circuit,
            lhs,
            rhs,
            cyclic_vk,
        })
    }
}

impl<F, C, const D: usize> AllRecursiveCircuits<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
{
    /// Serializes all these preprocessed circuits into a sequence of bytes.
    ///
    /// # Arguments
    ///
    /// - `skip_tables`: a boolean indicating whether to serialize only the
    ///   upper circuits or the entire prover state, including recursive
    ///   circuits to shrink STARK proofs.
    /// - `gate_serializer`: a custom gate serializer needed to serialize
    ///   recursive circuits common data.
    /// - `generator_serializer`: a custom generator serializer needed to
    ///   serialize recursive circuits proving data.
    pub fn to_bytes(
        &self,
        skip_tables: bool,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<Vec<u8>> {
        // TODO: would be better to initialize it dynamically based on the supported max
        // degree.
        let mut buffer = Vec::with_capacity(1 << 34);
        self.root
            .to_buffer(&mut buffer, gate_serializer, generator_serializer)?;
        self.root_no_keccak_tables
            .to_buffer(&mut buffer, gate_serializer, generator_serializer)?;
        self.segment_aggregation
            .to_buffer(&mut buffer, gate_serializer, generator_serializer)?;
        self.txn_aggregation
            .to_buffer(&mut buffer, gate_serializer, generator_serializer)?;
        self.block
            .to_buffer(&mut buffer, gate_serializer, generator_serializer)?;
        self.block_wrapper
            .to_buffer(&mut buffer, gate_serializer, generator_serializer)?;
        self.two_to_one_block
            .to_buffer(&mut buffer, gate_serializer, generator_serializer)?;
        if !skip_tables {
            for table in &self.by_table {
                table.to_buffer(&mut buffer, gate_serializer, generator_serializer)?;
            }
        }
        Ok(buffer)
    }

    /// Deserializes a sequence of bytes into an entire prover state containing
    /// all recursive circuits.
    ///
    /// # Arguments
    ///
    /// - `bytes`: a slice of bytes to deserialize this prover state from.
    /// - `skip_tables`: a boolean indicating whether to deserialize only the
    ///   upper circuits or the entire prover state, including recursive
    ///   circuits to shrink STARK proofs.
    /// - `gate_serializer`: a custom gate serializer needed to serialize
    ///   recursive circuits common data.
    /// - `generator_serializer`: a custom generator serializer needed to
    ///   serialize recursive circuits proving data.
    pub fn from_bytes(
        bytes: &[u8],
        skip_tables: bool,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<Self> {
        let mut buffer = Buffer::new(bytes);
        let root =
            RootCircuitData::from_buffer(&mut buffer, gate_serializer, generator_serializer)?;
        let root_no_keccak_tables =
            RootCircuitData::from_buffer(&mut buffer, gate_serializer, generator_serializer)?;
        let segment_aggregation = SegmentAggregationCircuitData::from_buffer(
            &mut buffer,
            gate_serializer,
            generator_serializer,
        )?;
        let txn_aggregation = TxnAggregationCircuitData::from_buffer(
            &mut buffer,
            gate_serializer,
            generator_serializer,
        )?;
        let block =
            BlockCircuitData::from_buffer(&mut buffer, gate_serializer, generator_serializer)?;
        let block_wrapper = BlockWrapperCircuitData::from_buffer(
            &mut buffer,
            gate_serializer,
            generator_serializer,
        )?;
        let two_to_one_block = TwoToOneBlockCircuitData::from_buffer(
            &mut buffer,
            gate_serializer,
            generator_serializer,
        )?;

        let by_table = match skip_tables {
            true => (0..NUM_TABLES)
                .map(|_| RecursiveCircuitsForTable {
                    by_stark_size: BTreeMap::default(),
                })
                .collect_vec()
                .try_into()
                .unwrap(),
            false => {
                // Tricky use of MaybeUninit to remove the need for implementing Debug
                // for all underlying types, necessary to convert a by_table Vec to an array.
                let mut by_table: [MaybeUninit<RecursiveCircuitsForTable<F, C, D>>; NUM_TABLES] =
                    unsafe { MaybeUninit::uninit().assume_init() };
                for table in &mut by_table[..] {
                    let value = RecursiveCircuitsForTable::from_buffer(
                        &mut buffer,
                        gate_serializer,
                        generator_serializer,
                    )?;
                    *table = MaybeUninit::new(value);
                }
                unsafe {
                    mem::transmute::<
                        [std::mem::MaybeUninit<RecursiveCircuitsForTable<F, C, D>>; NUM_TABLES],
                        [RecursiveCircuitsForTable<F, C, D>; NUM_TABLES],
                    >(by_table)
                }
            }
        };

        Ok(Self {
            root,
            root_no_keccak_tables,
            segment_aggregation,
            txn_aggregation,
            block,
            block_wrapper,
            two_to_one_block,
            by_table,
        })
    }

    /// Preprocess all recursive circuits used by the system.
    ///
    /// # Arguments
    ///
    /// - `all_stark`: a structure defining the logic of all STARK modules and
    ///   their associated cross-table lookups.
    /// - `degree_bits_ranges`: the logarithmic ranges to be supported for the
    ///   recursive tables.
    ///
    /// Transactions may yield arbitrary trace lengths for each STARK module
    /// (within some bounds), unknown prior generating the witness to create
    /// a proof. Thus, for each STARK module, we construct a map from
    /// `2^{degree_bits} = length` to a chain of shrinking recursion circuits,
    /// starting from that length, for each `degree_bits` in the range specified
    /// for this STARK module. Specifying a wide enough range allows a
    /// prover to cover all possible scenarios.
    /// - `stark_config`: the configuration to be used for the STARK prover. It
    ///   will usually be a fast one yielding large proofs.
    pub fn new(
        all_stark: &AllStark<F, D>,
        degree_bits_ranges: &[Range<usize>; NUM_TABLES],
        stark_config: &StarkConfig,
    ) -> Self {
        // Sanity check on the provided config
        assert_eq!(DEFAULT_CAP_LEN, 1 << stark_config.fri_config.cap_height);

        let arithmetic = RecursiveCircuitsForTable::new(
            Table::Arithmetic,
            &all_stark.arithmetic_stark,
            degree_bits_ranges[*Table::Arithmetic].clone(),
            &all_stark.cross_table_lookups,
            stark_config,
        );
        let byte_packing = RecursiveCircuitsForTable::new(
            Table::BytePacking,
            &all_stark.byte_packing_stark,
            degree_bits_ranges[*Table::BytePacking].clone(),
            &all_stark.cross_table_lookups,
            stark_config,
        );
        let cpu = RecursiveCircuitsForTable::new(
            Table::Cpu,
            &all_stark.cpu_stark,
            degree_bits_ranges[*Table::Cpu].clone(),
            &all_stark.cross_table_lookups,
            stark_config,
        );
        let keccak = RecursiveCircuitsForTable::new(
            Table::Keccak,
            &all_stark.keccak_stark,
            degree_bits_ranges[*Table::Keccak].clone(),
            &all_stark.cross_table_lookups,
            stark_config,
        );
        let keccak_sponge = RecursiveCircuitsForTable::new(
            Table::KeccakSponge,
            &all_stark.keccak_sponge_stark,
            degree_bits_ranges[*Table::KeccakSponge].clone(),
            &all_stark.cross_table_lookups,
            stark_config,
        );
        let logic = RecursiveCircuitsForTable::new(
            Table::Logic,
            &all_stark.logic_stark,
            degree_bits_ranges[*Table::Logic].clone(),
            &all_stark.cross_table_lookups,
            stark_config,
        );
        let memory = RecursiveCircuitsForTable::new(
            Table::Memory,
            &all_stark.memory_stark,
            degree_bits_ranges[*Table::Memory].clone(),
            &all_stark.cross_table_lookups,
            stark_config,
        );
        let mem_before = RecursiveCircuitsForTable::new(
            Table::MemBefore,
            &all_stark.mem_before_stark,
            degree_bits_ranges[*Table::MemBefore].clone(),
            &all_stark.cross_table_lookups,
            stark_config,
        );
        let mem_after = RecursiveCircuitsForTable::new(
            Table::MemAfter,
            &all_stark.mem_after_stark,
            degree_bits_ranges[*Table::MemAfter].clone(),
            &all_stark.cross_table_lookups,
            stark_config,
        );
        #[cfg(feature = "cdk_erigon")]
        let poseidon = RecursiveCircuitsForTable::new(
            Table::Poseidon,
            &all_stark.poseidon_stark,
            degree_bits_ranges[*Table::Poseidon].clone(),
            &all_stark.cross_table_lookups,
            stark_config,
        );

        let by_table = [
            arithmetic,
            byte_packing,
            cpu,
            keccak,
            keccak_sponge,
            logic,
            memory,
            mem_before,
            mem_after,
            #[cfg(feature = "cdk_erigon")]
            poseidon,
        ];
        log::info!("create_segment_circuit");
        let root = Self::create_segment_circuit(&by_table, stark_config, true);
        log::info!("create root_no_keccak_tables");
        let root_no_keccak_tables = Self::create_segment_circuit(&by_table, stark_config, true);
        let segment_aggregation = Self::create_segment_aggregation_circuit(&root);
        let txn_aggregation =
            Self::create_txn_aggregation_circuit(&segment_aggregation, stark_config);
        let block = Self::create_block_circuit(&txn_aggregation);
        let block_wrapper = Self::create_block_wrapper_circuit(&block);
        let two_to_one_block = Self::create_two_to_one_block_circuit(&block_wrapper);
        Self {
            root,
            root_no_keccak_tables,
            segment_aggregation,
            txn_aggregation,
            block,
            block_wrapper,
            two_to_one_block,
            by_table,
        }
    }

    /// Outputs the `VerifierCircuitData` needed to verify any block proof
    /// generated by an honest prover.
    /// While the [`AllRecursiveCircuits`] prover state can also verify proofs,
    /// verifiers only need a fraction of the state to verify proofs. This
    /// allows much less powerful entities to behave as verifiers, by only
    /// loading the necessary data to verify block proofs.
    ///
    /// # Usage
    ///
    /// ```ignore
    /// let prover_state = AllRecursiveCircuits { ... };
    /// let verifier_state = prover_state.final_verifier_data();
    ///
    /// // Verify a provided block proof
    /// assert!(verifier_state.verify(&block_proof).is_ok());
    /// ```
    pub fn final_verifier_data(&self) -> VerifierCircuitData<F, C, D> {
        self.block.circuit.verifier_data()
    }

    fn create_segment_circuit(
        by_table: &[RecursiveCircuitsForTable<F, C, D>; NUM_TABLES],
        stark_config: &StarkConfig,
        enable_keccak_tables: bool,
    ) -> RootCircuitData<F, C, D> {
        let inner_common_data: [_; NUM_TABLES] = core::array::from_fn(|i| {
            skip_keccak_if_disabled(i, enable_keccak_tables, None, || {
                Some(&by_table[i].final_circuits()[0].common)
            })
        });

        let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_config());

        let public_values = add_virtual_public_values_public_input(&mut builder);

        let recursive_proofs: [_; NUM_TABLES] = core::array::from_fn(|i| {
            skip_keccak_if_disabled(i, enable_keccak_tables, None, || {
                Some(builder.add_virtual_proof_with_pis(inner_common_data[i].unwrap()))
            })
        });

        let pis: [_; NUM_TABLES] = core::array::from_fn(|i| {
            if let Some(recursive_proof) = &recursive_proofs[i] {
                Some(PublicInputs::<
                    Target,
                    <C::Hasher as AlgebraicHasher<F>>::AlgebraicPermutation,
                >::from_vec(
                    &recursive_proof.public_inputs, stark_config
                ))
            } else {
                None // Skip Keccak tables
            }
        });

        let index_verifier_data: [_; NUM_TABLES] = core::array::from_fn(|i| {
            skip_keccak_if_disabled(i, enable_keccak_tables, None, || {
                Some(builder.add_virtual_target())
            })
        });

        let mut challenger = RecursiveChallenger::<F, C::Hasher, D>::new(&mut builder);
        for maybe_pi in &pis {
            if let Some(pi) = maybe_pi {
                for h in &pi.trace_cap {
                    challenger.observe_elements(h);
                }
            }
        }

        observe_public_values_target::<F, C, D>(&mut challenger, &public_values);

        let ctl_challenges = get_grand_product_challenge_set_target(
            &mut builder,
            &mut challenger,
            stark_config.num_challenges,
        );

        // Check that the correct CTL challenges are used in every proof.
        for maybe_pi in &pis {
            if let Some(pi) = maybe_pi {
                for i in 0..stark_config.num_challenges {
                    builder.connect(
                        ctl_challenges.challenges[i].beta,
                        pi.ctl_challenges.challenges[i].beta,
                    );
                    builder.connect(
                        ctl_challenges.challenges[i].gamma,
                        pi.ctl_challenges.challenges[i].gamma,
                    );
                }
            }
        }

        // Initialize the state with the compacted challenger state
        let mut prev_state = challenger.compact(&mut builder);

        // Loop over the proofs and connect states
        for current_pi in pis.iter().flatten() {
            for (&before, &s) in zip_eq(
                prev_state.as_ref(),
                current_pi.challenger_state_before.as_ref(),
            ) {
                builder.connect(before, s);
            }
            prev_state = current_pi.challenger_state_after.clone();
        }

        // Extra sums to add to the looked last value. Only necessary for the Memory
        // values.
        let mut extra_looking_sums = HashMap::from_iter(
            (0..NUM_CTLS).map(|i| (i, vec![builder.zero(); stark_config.num_challenges])),
        );

        // Memory
        extra_looking_sums.insert(
            MEMORY_CTL_IDX,
            (0..stark_config.num_challenges)
                .map(|c| {
                    get_memory_extra_looking_sum_circuit(
                        &mut builder,
                        &public_values,
                        ctl_challenges.challenges[c],
                    )
                })
                .collect_vec(),
        );

        // Verify the CTL checks
        let ctl_zs_first: [_; NUM_TABLES] = pis.map(|p| {
            p.as_ref()
                .map_or_else(|| None, |pi| Some(pi.ctl_zs_first.clone()))
        });

        // Now call the `verify_cross_table_lookups_circuit` function
        verify_cross_table_lookups_circuit(
            &mut builder,
            all_cross_table_lookups(enable_keccak_tables),
            ctl_zs_first,
            &extra_looking_sums,
            stark_config,
        );

        for (i, table_circuits) in by_table.iter().enumerate() {
            if let Some(common_data) = inner_common_data[i] {
                let final_circuits = table_circuits.final_circuits();
                for final_circuit in &final_circuits {
                    assert_eq!(&final_circuit.common, common_data, "common_data mismatch");
                }
                let mut possible_vks = final_circuits
                    .into_iter()
                    .map(|c| builder.constant_verifier_data(&c.verifier_only))
                    .collect_vec();
                // random_access_verifier_data expects a vector whose length is a power of two.
                // To satisfy this, we will just add some duplicates of the first VK.
                while !possible_vks.len().is_power_of_two() {
                    possible_vks.push(possible_vks[0].clone());
                }
                let inner_verifier_data = builder
                    .random_access_verifier_data(index_verifier_data[i].unwrap(), possible_vks);

                builder.verify_proof::<C>(
                    &recursive_proofs[i].as_ref().unwrap(),
                    &inner_verifier_data,
                    common_data,
                );
            }
        }

        let merkle_before = MemCapTarget::from_public_inputs(
            &recursive_proofs[*Table::MemBefore]
                .as_ref()
                .unwrap()
                .public_inputs,
        );
        let merkle_after = MemCapTarget::from_public_inputs(
            &recursive_proofs[*Table::MemAfter]
                .as_ref()
                .unwrap()
                .public_inputs,
        );

        // Connect Memory before and after the execution with the public values.
        MemCapTarget::connect(
            &mut builder,
            public_values.mem_before.clone(),
            merkle_before,
        );
        MemCapTarget::connect(&mut builder, public_values.mem_after.clone(), merkle_after);

        // We want EVM root proofs to have the exact same structure as aggregation
        // proofs, so we add public inputs for cyclic verification, even though
        // they'll be ignored.
        let cyclic_vk = builder.add_verifier_data_public_inputs();

        builder.add_gate(
            ConstantGate::new(inner_common_data[0].unwrap().config.num_constants),
            vec![],
        );

        RootCircuitData {
            circuit: builder.build::<C>(),
            proof_with_pis: recursive_proofs,
            index_verifier_data,
            public_values,
            cyclic_vk,
        }
    }

    fn create_segment_aggregation_circuit(
        root: &RootCircuitData<F, C, D>,
    ) -> SegmentAggregationCircuitData<F, C, D> {
        let mut builder = CircuitBuilder::<F, D>::new(root.circuit.common.config.clone());
        let public_values = add_virtual_public_values_public_input(&mut builder);
        let cyclic_vk = builder.add_verifier_data_public_inputs();

        // The right hand side child might be dummy.
        let lhs_segment = Self::add_segment_agg_child(&mut builder, root);
        let rhs_segment = Self::add_segment_agg_child_with_dummy(
            &mut builder,
            root,
            lhs_segment.base_proof.clone(),
        );

        let lhs_pv = lhs_segment.public_values(&mut builder);
        let rhs_pv = rhs_segment.public_values(&mut builder);

        let is_dummy = rhs_segment.is_dummy;
        let one = builder.one();
        let is_not_dummy = builder.sub(one, is_dummy.target);
        let is_not_dummy = BoolTarget::new_unsafe(is_not_dummy);

        // Always connect the lhs to the aggregation public values.
        TrieRootsTarget::connect(
            &mut builder,
            public_values.trie_roots_before,
            lhs_pv.trie_roots_before,
        );
        TrieRootsTarget::connect(
            &mut builder,
            public_values.trie_roots_after,
            lhs_pv.trie_roots_after,
        );
        BlockMetadataTarget::connect(
            &mut builder,
            public_values.block_metadata,
            lhs_pv.block_metadata,
        );
        BlockHashesTarget::connect(
            &mut builder,
            public_values.block_hashes,
            lhs_pv.block_hashes,
        );
        ExtraBlockDataTarget::connect(
            &mut builder,
            public_values.extra_block_data,
            lhs_pv.extra_block_data,
        );
        RegistersDataTarget::connect(
            &mut builder,
            public_values.registers_before.clone(),
            lhs_pv.registers_before.clone(),
        );
        MemCapTarget::connect(
            &mut builder,
            public_values.mem_before.clone(),
            lhs_pv.mem_before.clone(),
        );

        // If the rhs is a real proof, all the block metadata must be the same for both
        // segments. It is also the case for the extra block data.
        TrieRootsTarget::conditional_assert_eq(
            &mut builder,
            is_not_dummy,
            public_values.trie_roots_before,
            rhs_pv.trie_roots_before,
        );
        TrieRootsTarget::conditional_assert_eq(
            &mut builder,
            is_not_dummy,
            public_values.trie_roots_after,
            rhs_pv.trie_roots_after,
        );

        // Connect the burn address targets.
        #[cfg(feature = "cdk_erigon")]
        {
            BurnAddrTarget::conditional_assert_eq(
                &mut builder,
                is_not_dummy,
                lhs_pv.burn_addr,
                rhs_pv.burn_addr.clone(),
            );
            BurnAddrTarget::conditional_assert_eq(
                &mut builder,
                is_not_dummy,
                public_values.burn_addr.clone(),
                rhs_pv.burn_addr,
            );
        }

        BlockMetadataTarget::conditional_assert_eq(
            &mut builder,
            is_not_dummy,
            public_values.block_metadata,
            rhs_pv.block_metadata,
        );
        BlockHashesTarget::conditional_assert_eq(
            &mut builder,
            is_not_dummy,
            public_values.block_hashes,
            rhs_pv.block_hashes,
        );
        ExtraBlockDataTarget::conditional_assert_eq(
            &mut builder,
            is_not_dummy,
            public_values.extra_block_data,
            rhs_pv.extra_block_data,
        );

        // If the rhs is a real proof: Connect registers and merkle caps between
        // segments.
        RegistersDataTarget::conditional_assert_eq(
            &mut builder,
            is_not_dummy,
            public_values.registers_after.clone(),
            rhs_pv.registers_after.clone(),
        );
        RegistersDataTarget::conditional_assert_eq(
            &mut builder,
            is_not_dummy,
            lhs_pv.registers_after.clone(),
            rhs_pv.registers_before.clone(),
        );
        MemCapTarget::conditional_assert_eq(
            &mut builder,
            is_not_dummy,
            public_values.mem_after.clone(),
            rhs_pv.mem_after.clone(),
        );
        MemCapTarget::conditional_assert_eq(
            &mut builder,
            is_not_dummy,
            lhs_pv.mem_after.clone(),
            rhs_pv.mem_before.clone(),
        );

        // If the rhs is a dummy, then the lhs must be a segment.
        let constr = builder.mul(is_dummy.target, lhs_segment.is_agg.target);
        builder.assert_zero(constr);

        // If the rhs is a dummy, then the aggregation PVs are equal to the lhs PVs.
        MemCapTarget::conditional_assert_eq(
            &mut builder,
            is_dummy,
            public_values.mem_after.clone(),
            lhs_pv.mem_after,
        );
        RegistersDataTarget::conditional_assert_eq(
            &mut builder,
            is_dummy,
            public_values.registers_after.clone(),
            lhs_pv.registers_after,
        );

        // Pad to match the root circuit's degree.
        while log2_ceil(builder.num_gates()) < root.circuit.common.degree_bits() {
            builder.add_gate(NoopGate, vec![]);
        }

        let circuit = builder.build::<C>();
        SegmentAggregationCircuitData {
            circuit,
            lhs: lhs_segment,
            rhs: rhs_segment,
            public_values,
            cyclic_vk,
        }
    }

    fn create_txn_aggregation_circuit(
        agg: &SegmentAggregationCircuitData<F, C, D>,
        stark_config: &StarkConfig,
    ) -> TxnAggregationCircuitData<F, C, D> {
        // Create a circuit for the aggregation of two transactions.

        let mut builder = CircuitBuilder::<F, D>::new(agg.circuit.common.config.clone());
        let public_values = add_virtual_public_values_public_input(&mut builder);
        let cyclic_vk = builder.add_verifier_data_public_inputs();

        let lhs_txn_proof = Self::add_txn_agg_child(&mut builder, agg);
        let rhs_txn_proof = Self::add_txn_agg_child(&mut builder, agg);

        let lhs_pv = lhs_txn_proof.public_values(&mut builder);
        let rhs_pv = rhs_txn_proof.public_values(&mut builder);

        // Connect all block hash values
        BlockHashesTarget::connect(
            &mut builder,
            public_values.block_hashes,
            rhs_pv.block_hashes,
        );
        BlockHashesTarget::connect(
            &mut builder,
            public_values.block_hashes,
            lhs_pv.block_hashes,
        );
        // Connect all block metadata values.
        BlockMetadataTarget::connect(
            &mut builder,
            public_values.block_metadata,
            rhs_pv.block_metadata,
        );
        BlockMetadataTarget::connect(
            &mut builder,
            public_values.block_metadata,
            lhs_pv.block_metadata,
        );
        // Connect aggregation `trie_roots_after` with rhs `trie_roots_after`.
        TrieRootsTarget::connect(
            &mut builder,
            public_values.trie_roots_after,
            rhs_pv.trie_roots_after,
        );
        // Connect lhs `trie_roots_after` with rhs `trie_roots_before`.
        TrieRootsTarget::connect(
            &mut builder,
            lhs_pv.trie_roots_after,
            rhs_pv.trie_roots_before,
        );
        // Connect lhs `trie_roots_before` with public values `trie_roots_before`.
        TrieRootsTarget::connect(
            &mut builder,
            public_values.trie_roots_before,
            lhs_pv.trie_roots_before,
        );

        // Connect the burn address targets.
        #[cfg(feature = "cdk_erigon")]
        {
            BurnAddrTarget::connect(
                &mut builder,
                lhs_pv.burn_addr.clone(),
                rhs_pv.burn_addr.clone(),
            );
            BurnAddrTarget::connect(
                &mut builder,
                public_values.burn_addr.clone(),
                rhs_pv.burn_addr.clone(),
            );
        }

        Self::connect_extra_public_values(
            &mut builder,
            &public_values.extra_block_data,
            &lhs_pv.extra_block_data,
            &rhs_pv.extra_block_data,
        );

        // We check the registers before and after for the current aggregation.
        RegistersDataTarget::connect(
            &mut builder,
            public_values.registers_after.clone(),
            rhs_pv.registers_after.clone(),
        );

        RegistersDataTarget::connect(
            &mut builder,
            public_values.registers_before.clone(),
            lhs_pv.registers_before.clone(),
        );

        // Check the initial and final register values.
        Self::connect_initial_final_segment(&mut builder, &rhs_pv);
        Self::connect_initial_final_segment(&mut builder, &lhs_pv);

        // Check the initial `MemBefore` `MerkleCap` value.
        Self::check_init_merkle_cap(&mut builder, &rhs_pv, stark_config);
        Self::check_init_merkle_cap(&mut builder, &lhs_pv, stark_config);

        while log2_ceil(builder.num_gates()) < agg.circuit.common.degree_bits() {
            builder.add_gate(NoopGate, vec![]);
        }

        let circuit = builder.build::<C>();
        TxnAggregationCircuitData {
            circuit,
            lhs: lhs_txn_proof,
            rhs: rhs_txn_proof,
            public_values,
            cyclic_vk,
        }
    }

    /// Extend a circuit to verify one of two proofs.
    ///
    /// # Arguments
    ///
    /// - `builder`: The circuit builder object.
    /// - `base_circuit`: Circuit data describing the circuit of the base proof.
    ///
    /// # Outputs
    ///
    /// Returns a [`TwoToOneBlockChildTarget<D>`] object.
    fn add_agg_child(
        builder: &mut CircuitBuilder<F, D>,
        base_circuit: &CircuitData<F, C, D>,
    ) -> AggregationChildTarget<D> {
        let common = &base_circuit.common;
        let base_vk = builder.constant_verifier_data(&base_circuit.verifier_only);
        let is_agg = builder.add_virtual_bool_target_safe();
        let agg_proof = builder.add_virtual_proof_with_pis(common);
        let base_proof = builder.add_virtual_proof_with_pis(common);
        builder
            .conditionally_verify_cyclic_proof::<C>(
                is_agg,
                &agg_proof,
                &base_proof,
                &base_vk,
                common,
            )
            .expect("Failed to build cyclic recursion circuit");
        AggregationChildTarget {
            is_agg,
            agg_proof,
            base_proof,
        }
    }

    fn check_init_merkle_cap(
        builder: &mut CircuitBuilder<F, D>,
        x: &PublicValuesTarget,
        stark_config: &StarkConfig,
    ) where
        F: RichField + Extendable<D>,
    {
        let cap = initial_memory_merkle_cap::<F, C, D>(
            stark_config.fri_config.rate_bits,
            stark_config.fri_config.cap_height,
        );

        let init_cap_target = MemCapTarget {
            mem_cap: MerkleCapTarget(
                cap.0
                    .iter()
                    .map(|&h| builder.constant_hash(h))
                    .collect::<Vec<_>>(),
            ),
        };

        MemCapTarget::connect(builder, x.mem_before.clone(), init_cap_target);
    }

    fn connect_initial_final_segment(builder: &mut CircuitBuilder<F, D>, x: &PublicValuesTarget)
    where
        F: RichField + Extendable<D>,
    {
        builder.assert_zero(x.registers_before.stack_len);
        builder.assert_zero(x.registers_after.stack_len);
        builder.assert_zero(x.registers_before.context);
        builder.assert_zero(x.registers_after.context);
        builder.assert_zero(x.registers_before.gas_used);
        builder.assert_one(x.registers_before.is_kernel);
        builder.assert_one(x.registers_after.is_kernel);

        let halt_label = builder.constant(F::from_canonical_usize(KERNEL.global_labels["halt"]));
        builder.connect(x.registers_after.program_counter, halt_label);

        let main_label = builder.constant(F::from_canonical_usize(KERNEL.global_labels["main"]));
        builder.connect(x.registers_before.program_counter, main_label);
    }

    fn create_block_circuit(agg: &TxnAggregationCircuitData<F, C, D>) -> BlockCircuitData<F, C, D> {
        // Here, we have two block proofs and we aggregate them together.
        // The block circuit is similar to the agg circuit; both verify two inner
        // proofs.
        let expected_common_data = CommonCircuitData {
            fri_params: FriParams {
                degree_bits: 14,
                ..agg.circuit.common.fri_params.clone()
            },
            ..agg.circuit.common.clone()
        };

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let public_values = add_virtual_public_values_public_input(&mut builder);
        let has_parent_block = builder.add_virtual_bool_target_safe();
        let parent_block_proof = builder.add_virtual_proof_with_pis(&expected_common_data);
        let agg_root_proof = builder.add_virtual_proof_with_pis(&agg.circuit.common);

        // Connect block hashes
        Self::connect_block_hashes(&mut builder, &parent_block_proof, &agg_root_proof);

        let parent_pv = PublicValuesTarget::from_public_inputs(&parent_block_proof.public_inputs);
        let agg_pv = PublicValuesTarget::from_public_inputs(&agg_root_proof.public_inputs);

        // Connect block `trie_roots_before` with parent_pv `trie_roots_before`.
        TrieRootsTarget::connect(
            &mut builder,
            public_values.trie_roots_before,
            parent_pv.trie_roots_before,
        );
        // Connect the rest of block `public_values` with agg_pv.
        TrieRootsTarget::connect(
            &mut builder,
            public_values.trie_roots_after,
            agg_pv.trie_roots_after,
        );
        BlockMetadataTarget::connect(
            &mut builder,
            public_values.block_metadata,
            agg_pv.block_metadata,
        );
        BlockHashesTarget::connect(
            &mut builder,
            public_values.block_hashes,
            agg_pv.block_hashes,
        );
        ExtraBlockDataTarget::connect(
            &mut builder,
            public_values.extra_block_data,
            agg_pv.extra_block_data,
        );

        // Connect the burn address targets.
        #[cfg(feature = "cdk_erigon")]
        {
            BurnAddrTarget::connect(
                &mut builder,
                parent_pv.burn_addr.clone(),
                agg_pv.burn_addr.clone(),
            );
            BurnAddrTarget::connect(
                &mut builder,
                public_values.burn_addr.clone(),
                agg_pv.burn_addr.clone(),
            );
        }

        // Make connections between block proofs, and check initial and final block
        // values.
        Self::connect_block_proof(&mut builder, has_parent_block, &parent_pv, &agg_pv);

        let cyclic_vk = builder.add_verifier_data_public_inputs();
        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(
                has_parent_block,
                &parent_block_proof,
                &expected_common_data,
            )
            .expect("Failed to build cyclic recursion circuit");

        let agg_verifier_data = builder.constant_verifier_data(&agg.circuit.verifier_only);
        builder.verify_proof::<C>(&agg_root_proof, &agg_verifier_data, &agg.circuit.common);

        let circuit = builder.build::<C>();
        BlockCircuitData {
            circuit,
            has_parent_block,
            parent_block_proof,
            agg_root_proof,
            public_values,
            cyclic_vk,
        }
    }

    fn connect_extra_public_values(
        builder: &mut CircuitBuilder<F, D>,
        pvs: &ExtraBlockDataTarget,
        lhs: &ExtraBlockDataTarget,
        rhs: &ExtraBlockDataTarget,
    ) {
        // Connect checkpoint state root values.
        for (&limb0, &limb1) in pvs
            .checkpoint_state_trie_root
            .iter()
            .zip(&rhs.checkpoint_state_trie_root)
        {
            builder.connect(limb0, limb1);
        }
        for (&limb0, &limb1) in pvs
            .checkpoint_state_trie_root
            .iter()
            .zip(&lhs.checkpoint_state_trie_root)
        {
            builder.connect(limb0, limb1);
        }

        // Connect the transaction number in public values to the lhs and rhs values
        // correctly.
        builder.connect(pvs.txn_number_before, lhs.txn_number_before);
        builder.connect(pvs.txn_number_after, rhs.txn_number_after);

        // Connect lhs `txn_number_after` with rhs `txn_number_before`.
        builder.connect(lhs.txn_number_after, rhs.txn_number_before);

        // Connect the gas used in public values to the lhs and rhs values correctly.
        builder.connect(pvs.gas_used_before, lhs.gas_used_before);
        builder.connect(pvs.gas_used_after, rhs.gas_used_after);

        // Connect lhs `gas_used_after` with rhs `gas_used_before`.
        builder.connect(lhs.gas_used_after, rhs.gas_used_before);
    }

    fn add_segment_agg_child(
        builder: &mut CircuitBuilder<F, D>,
        root: &RootCircuitData<F, C, D>,
    ) -> AggregationChildTarget<D> {
        let common = &root.circuit.common;
        let root_vk = builder.constant_verifier_data(&root.circuit.verifier_only);
        let is_agg = builder.add_virtual_bool_target_safe();
        let agg_proof = builder.add_virtual_proof_with_pis(common);
        let base_proof = builder.add_virtual_proof_with_pis(common);
        builder
            .conditionally_verify_cyclic_proof::<C>(
                is_agg,
                &agg_proof,
                &base_proof,
                &root_vk,
                common,
            )
            .expect("Failed to build cyclic recursion circuit");
        AggregationChildTarget {
            is_agg,
            agg_proof,
            base_proof,
        }
    }

    fn add_segment_agg_child_with_dummy(
        builder: &mut CircuitBuilder<F, D>,
        root: &RootCircuitData<F, C, D>,
        dummy_proof: ProofWithPublicInputsTarget<D>,
    ) -> AggregationChildWithDummyTarget<D> {
        let common = &root.circuit.common;
        let root_vk = builder.constant_verifier_data(&root.circuit.verifier_only);
        let is_agg = builder.add_virtual_bool_target_safe();
        let agg_proof = builder.add_virtual_proof_with_pis(common);
        let is_dummy = builder.add_virtual_bool_target_safe();
        let real_proof = builder.add_virtual_proof_with_pis(common);

        let segment_proof = builder.select_proof_with_pis(is_dummy, &dummy_proof, &real_proof);
        builder
            .conditionally_verify_cyclic_proof::<C>(
                is_agg,
                &agg_proof,
                &segment_proof,
                &root_vk,
                common,
            )
            .expect("Failed to build cyclic recursion circuit");
        AggregationChildWithDummyTarget {
            is_agg,
            is_dummy,
            agg_proof,
            real_proof,
        }
    }

    fn add_txn_agg_child(
        builder: &mut CircuitBuilder<F, D>,
        segment_agg: &SegmentAggregationCircuitData<F, C, D>,
    ) -> AggregationChildTarget<D> {
        let common = &segment_agg.circuit.common;
        let inner_segment_agg_vk =
            builder.constant_verifier_data(&segment_agg.circuit.verifier_only);
        let is_agg = builder.add_virtual_bool_target_safe();
        let agg_proof = builder.add_virtual_proof_with_pis(common);
        let base_proof = builder.add_virtual_proof_with_pis(common);
        builder
            .conditionally_verify_cyclic_proof::<C>(
                is_agg,
                &agg_proof,
                &base_proof,
                &inner_segment_agg_vk,
                common,
            )
            .expect("Failed to build cyclic recursion circuit");
        AggregationChildTarget {
            is_agg,
            agg_proof,
            base_proof,
        }
    }

    fn create_block_wrapper_circuit(
        block: &BlockCircuitData<F, C, D>,
    ) -> BlockWrapperCircuitData<F, C, D> {
        let mut builder = CircuitBuilder::<F, D>::new(block.circuit.common.config.clone());

        let parent_block_proof = builder.add_virtual_proof_with_pis(&block.circuit.common);
        let parent_pv = PublicValuesTarget::from_public_inputs(&parent_block_proof.public_inputs);

        let final_pv = add_virtual_final_public_values_public_input(&mut builder);

        // This also enforces that the initial state trie root that will be stored in
        // these `FinalPublicValues` actually matches the known checkpoint state trie
        // root.
        final_pv.connect_parent(&mut builder, &parent_pv);

        let block_verifier_data = builder.constant_verifier_data(&block.circuit.verifier_only);

        // We want these wrapped block proofs to have the exact same structure as 2-to-1
        // aggregation proofs, so we add public inputs for cyclic verification,
        // even though they'll be ignored.
        let cyclic_vk = builder.add_verifier_data_public_inputs();

        builder.verify_proof::<C>(
            &parent_block_proof,
            &block_verifier_data,
            &block.circuit.common,
        );

        // Pad to match the (non-existing yet!) 2-to-1 circuit's degree.
        // We use the block circuit's degree as target reference here, as they end up
        // having same degree.
        while log2_ceil(builder.num_gates()) < block.circuit.common.degree_bits() {
            builder.add_gate(NoopGate, vec![]);
        }

        let circuit = builder.build::<C>();

        BlockWrapperCircuitData {
            circuit,
            parent_block_proof,
            public_values: final_pv,
            cyclic_vk,
        }
    }

    /// Create two-to-one block aggregation circuit.
    ///
    /// # Arguments
    ///
    /// - `block_circuit`: circuit data for the block circuit, that constitutes
    ///   the base case for aggregation.
    ///
    /// # Outputs
    ///
    /// Returns a [`TwoToOneBlockCircuitData<F, C, D>`].
    fn create_two_to_one_block_circuit(
        block_wrapper_circuit: &BlockWrapperCircuitData<F, C, D>,
    ) -> TwoToOneBlockCircuitData<F, C, D>
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        C::Hasher: AlgebraicHasher<F>,
    {
        let mut builder =
            CircuitBuilder::<F, D>::new(block_wrapper_circuit.circuit.common.config.clone());

        let mix_hash = builder.add_virtual_hash_public_input();

        // We need to pad by PIS to match the count of PIS of the `base_proof`.
        let mut padding = block_wrapper_circuit.circuit.common.num_public_inputs;
        // The number of PIS that will be added *after* padding by
        // [`add_verifier_data_public_inputs()`].
        padding -= verification_key_len(&block_wrapper_circuit.circuit);
        // Account for `mix_pv_hash`.
        padding -= builder.num_public_inputs();

        let zero = builder.zero();
        for _ in 0..padding {
            builder.register_public_input(zero);
        }

        let cyclic_vk = builder.add_verifier_data_public_inputs();

        let lhs = Self::add_agg_child(&mut builder, &block_wrapper_circuit.circuit);
        let rhs = Self::add_agg_child(&mut builder, &block_wrapper_circuit.circuit);

        let lhs_public_inputs = lhs.public_inputs(&mut builder);
        let rhs_public_inputs = rhs.public_inputs(&mut builder);

        let lhs_public_values = extract_block_final_public_values(&lhs_public_inputs);
        let rhs_public_values = extract_block_final_public_values(&rhs_public_inputs);

        let lhs_agg_pv_hash = extract_two_to_one_block_hash(&lhs_public_inputs);
        let rhs_agg_pv_hash = extract_two_to_one_block_hash(&rhs_public_inputs);

        let lhs_base_pv_hash = builder
            .hash_n_to_hash_no_pad::<C::InnerHasher>(lhs_public_values.to_vec())
            .elements;
        let rhs_base_pv_hash = builder
            .hash_n_to_hash_no_pad::<C::InnerHasher>(rhs_public_values.to_vec())
            .elements;

        let lhs_hash: Vec<Target> = zip_eq(lhs_agg_pv_hash, lhs_base_pv_hash)
            .map(|(&agg_target, base_target)| builder.select(lhs.is_agg, agg_target, base_target))
            .collect();

        let rhs_hash: Vec<Target> = zip_eq(rhs_agg_pv_hash, rhs_base_pv_hash)
            .map(|(&agg_target, base_target)| builder.select(rhs.is_agg, agg_target, base_target))
            .collect();

        let mut mix_vec = vec![];
        mix_vec.extend(&lhs_hash);
        mix_vec.extend(&rhs_hash);

        let mix_hash_virtual = builder.hash_n_to_hash_no_pad::<C::InnerHasher>(mix_vec);

        builder.connect_hashes(mix_hash, mix_hash_virtual);

        let circuit = builder.build::<C>();
        TwoToOneBlockCircuitData {
            circuit,
            lhs,
            rhs,
            cyclic_vk,
        }
    }

    /// Connect the 256 block hashes between two blocks
    fn connect_block_hashes(
        builder: &mut CircuitBuilder<F, D>,
        lhs: &ProofWithPublicInputsTarget<D>,
        rhs: &ProofWithPublicInputsTarget<D>,
    ) {
        let lhs_public_values = PublicValuesTarget::from_public_inputs(&lhs.public_inputs);
        let rhs_public_values = PublicValuesTarget::from_public_inputs(&rhs.public_inputs);
        for i in 0..255 {
            for j in 0..8 {
                builder.connect(
                    lhs_public_values.block_hashes.prev_hashes[8 * (i + 1) + j],
                    rhs_public_values.block_hashes.prev_hashes[8 * i + j],
                );
            }
        }
        let expected_hash = lhs_public_values.block_hashes.cur_hash;
        let prev_block_hash = &rhs_public_values.block_hashes.prev_hashes[255 * 8..256 * 8];
        for i in 0..expected_hash.len() {
            builder.connect(expected_hash[i], prev_block_hash[i]);
        }
    }

    fn connect_block_proof(
        builder: &mut CircuitBuilder<F, D>,
        has_parent_block: BoolTarget,
        lhs: &PublicValuesTarget,
        rhs: &PublicValuesTarget,
    ) {
        // Between blocks, we only connect state tries.
        for (&limb0, limb1) in lhs
            .trie_roots_after
            .state_root
            .iter()
            .zip(rhs.trie_roots_before.state_root)
        {
            builder.connect(limb0, limb1);
        }

        // Between blocks, the checkpoint state trie remains unchanged.
        for (&limb0, limb1) in lhs
            .extra_block_data
            .checkpoint_state_trie_root
            .iter()
            .zip(rhs.extra_block_data.checkpoint_state_trie_root)
        {
            builder.connect(limb0, limb1);
        }

        // Connect block numbers.
        let one = builder.one();
        let prev_block_nb = builder.sub(rhs.block_metadata.block_number, one);
        builder.connect(lhs.block_metadata.block_number, prev_block_nb);

        // Check initial block values.
        Self::connect_initial_values_block(builder, rhs);

        // Connect intermediary values for gas_used and bloom filters to the block's
        // final values. We only plug on the right, so there is no need to check the
        // left-handside block.
        Self::connect_final_block_values_to_intermediary(builder, rhs);

        let has_not_parent_block = builder.sub(one, has_parent_block.target);

        // Check that the checkpoint block has the predetermined state trie root in
        // `ExtraBlockData`.
        Self::connect_checkpoint_block(builder, rhs, has_not_parent_block);
    }

    fn connect_checkpoint_block(
        builder: &mut CircuitBuilder<F, D>,
        x: &PublicValuesTarget,
        has_not_parent_block: Target,
    ) where
        F: RichField + Extendable<D>,
    {
        for (&limb0, limb1) in x
            .trie_roots_before
            .state_root
            .iter()
            .zip(x.extra_block_data.checkpoint_state_trie_root)
        {
            let mut constr = builder.sub(limb0, limb1);
            constr = builder.mul(has_not_parent_block, constr);
            builder.assert_zero(constr);
        }
    }

    fn connect_final_block_values_to_intermediary(
        builder: &mut CircuitBuilder<F, D>,
        x: &PublicValuesTarget,
    ) where
        F: RichField + Extendable<D>,
    {
        builder.connect(
            x.block_metadata.block_gas_used,
            x.extra_block_data.gas_used_after,
        );
    }

    fn connect_initial_values_block(builder: &mut CircuitBuilder<F, D>, x: &PublicValuesTarget)
    where
        F: RichField + Extendable<D>,
    {
        // The initial number of transactions is 0.
        builder.assert_zero(x.extra_block_data.txn_number_before);
        // The initial gas used is 0.
        builder.assert_zero(x.extra_block_data.gas_used_before);

        // The transactions and receipts tries are empty at the beginning of the block.
        let initial_trie = HashedPartialTrie::from(Node::Empty).hash();

        for (i, limb) in h256_limbs::<F>(initial_trie).into_iter().enumerate() {
            let limb_target = builder.constant(limb);
            builder.connect(x.trie_roots_before.transactions_root[i], limb_target);
            builder.connect(x.trie_roots_before.receipts_root[i], limb_target);
        }
    }

    /// For a given transaction payload passed as [`GenerationInputs`], create a
    /// proof for each STARK module, then recursively shrink and combine
    /// them, eventually culminating in a transaction proof, also called
    /// root proof.
    ///
    /// # Arguments
    ///
    /// - `all_stark`: a structure defining the logic of all STARK modules and
    ///   their associated cross-table lookups.
    /// - `config`: the configuration to be used for the STARK prover. It will
    ///   usually be a fast one yielding large proofs.
    /// - `generation_inputs`: a transaction and auxiliary data needed to
    ///   generate a proof, provided in Intermediary Representation.
    /// - `timing`: a profiler defining a scope hierarchy and the time consumed
    ///   by each one.
    /// - `abort_signal`: an optional [`AtomicBool`] wrapped behind an [`Arc`],
    ///   to send a kill signal early. This is only necessary in a distributed
    ///   setting where a worker may be blocking the entire queue.
    ///
    /// # Outputs
    ///
    /// This method outputs a tuple of [`ProofWithPublicInputs<F, C, D>`] and
    /// its [`PublicValues`]. Only the proof with public inputs is necessary
    /// for a verifier to assert correctness of the computation,
    /// but the public values are output for the prover convenience, as these
    /// are necessary during proof aggregation.
    pub fn prove_segment(
        &self,
        all_stark: &AllStark<F, D>,
        config: &StarkConfig,
        generation_inputs: TrimmedGenerationInputs,
        segment_data: &mut GenerationSegmentData,
        timing: &mut TimingTree,
        abort_signal: Option<Arc<AtomicBool>>,
    ) -> anyhow::Result<ProverOutputData<F, C, D>> {
        features_check(&generation_inputs);

        let all_proof = prove::<F, C, D>(
            all_stark,
            config,
            generation_inputs,
            segment_data,
            timing,
            abort_signal.clone(),
        )?;
        let mut root_inputs = PartialWitness::new();

        for table in 0..NUM_TABLES {
            if let Some(stark_proof) = &all_proof.multi_proof.stark_proofs[table] {
                let original_degree_bits = stark_proof.proof.recover_degree_bits(config);
                let table_circuits = &self.by_table[table];
                let shrunk_proof = table_circuits
                    .by_stark_size
                    .get(&original_degree_bits)
                    .ok_or_else(|| {
                        anyhow!(format!(
                            "Missing preprocessed circuits for {:?} table with size {}.",
                            Table::all()[table],
                            original_degree_bits,
                        ))
                    })?
                    .shrink(stark_proof, &all_proof.multi_proof.ctl_challenges)?;
                let index_verifier_data = table_circuits
                    .by_stark_size
                    .keys()
                    .position(|&size| size == original_degree_bits)
                    .unwrap();
                root_inputs.set_target(
                    self.root.index_verifier_data[table].unwrap(),
                    F::from_canonical_usize(index_verifier_data),
                );
                root_inputs.set_proof_with_pis_target(
                    &self.root.proof_with_pis[table].clone().unwrap(),
                    &shrunk_proof,
                );

                check_abort_signal(abort_signal.clone())?;
            }
        }

        root_inputs.set_verifier_data_target(
            &self.root.cyclic_vk,
            &self.segment_aggregation.circuit.verifier_only,
        );

        set_public_value_targets(
            &mut root_inputs,
            &self.root.public_values,
            &all_proof.public_values,
        )
        .map_err(|_| {
            anyhow::Error::msg("Invalid conversion when setting public values targets.")
        })?;

        let root_proof = self.root.circuit.prove(root_inputs)?;

        Ok(ProverOutputData {
            is_dummy: false,
            proof_with_pis: root_proof,
            public_values: all_proof.public_values,
        })
    }

    /// Returns a proof for each segment that is part of a full transaction
    /// proof.
    pub fn prove_all_segments(
        &self,
        all_stark: &AllStark<F, D>,
        config: &StarkConfig,
        generation_inputs: GenerationInputs,
        max_cpu_len_log: usize,
        timing: &mut TimingTree,
        abort_signal: Option<Arc<AtomicBool>>,
    ) -> anyhow::Result<Vec<ProverOutputData<F, C, D>>> {
        features_check(&generation_inputs.clone().trim());

        let segment_iterator =
            SegmentDataIterator::<F>::new(&generation_inputs, Some(max_cpu_len_log));

        let mut proofs = vec![];

        for segment_run in segment_iterator {
            let (_, mut next_data) =
                segment_run.map_err(|e: SegmentError| anyhow::format_err!(e))?;
            let proof = self.prove_segment(
                all_stark,
                config,
                generation_inputs.trim(),
                &mut next_data,
                timing,
                abort_signal.clone(),
            )?;
            proofs.push(proof);
        }

        // Since aggregations require at least two segment proofs, add a dummy proof if
        // there is only one proof.
        if proofs.len() == 1 {
            let mut first_proof = proofs[0].clone();
            first_proof.is_dummy = true;
            proofs.push(first_proof);
        }

        Ok(proofs)
    }

    /// From an initial set of STARK proofs passed with their associated
    /// recursive table circuits, generate a recursive transaction proof.
    /// It is aimed at being used when preprocessed table circuits have not been
    /// loaded to memory.
    ///
    /// **Note**:
    /// The type of the `table_circuits` passed as arguments is
    /// `&[(RecursiveCircuitsForTableSize<F, C, D>, u8); NUM_TABLES]`. In
    /// particular, for each STARK proof contained within the `AllProof`
    /// object provided to this method, we need to pass a tuple
    /// of [`RecursiveCircuitsForTableSize<F, C, D>`] and a [`u8`]. The former
    /// is the recursive chain corresponding to the initial degree size of
    /// the associated STARK proof. The latter is the index of this degree
    /// in the range that was originally passed when constructing the entire
    /// prover state.
    ///
    /// # Usage
    ///
    /// ```ignore
    /// // Load a prover state without its recursive table circuits.
    /// let gate_serializer = DefaultGateSerializer;
    /// let generator_serializer = DefaultGeneratorSerializer::<C, D>::new();
    /// let initial_ranges = [16..25, 10..20, 12..25, 14..25, 9..20, 12..20, 17..30];
    /// let prover_state = AllRecursiveCircuits::<F, C, D>::new(
    ///     &all_stark,
    ///     &initial_ranges,
    ///     &config,
    /// );
    ///
    /// // Generate a proof from the provided inputs.
    /// let stark_proof = prove::<F, C, D>(&all_stark, &config, inputs, &mut timing, abort_signal).unwrap();
    ///
    /// // Read the degrees of the internal STARK proofs.
    /// // Indices to be passed along the recursive tables
    /// // can be easily recovered as `initial_ranges[i]` - `degrees[i]`.
    /// let degrees = proof.degree_bits(&config);
    ///
    /// // Retrieve the corresponding recursive table circuits for each table with the corresponding degree.
    /// let table_circuits = { ... };
    ///
    /// // Finally shrink the STARK proof.
    /// let (proof, public_values) = prove_segment_after_initial_stark(
    ///     &all_stark,
    ///     &config,
    ///     &stark_proof,
    ///     &table_circuits,
    ///     &mut timing,
    ///     abort_signal,
    /// ).unwrap();
    /// ```
    pub fn prove_segment_after_initial_stark(
        &self,
        all_proof: AllProof<F, C, D>,
        table_circuits: &[Option<(RecursiveCircuitsForTableSize<F, C, D>, u8)>; NUM_TABLES],
        abort_signal: Option<Arc<AtomicBool>>,
    ) -> anyhow::Result<(ProofWithPublicInputs<F, C, D>, PublicValues)> {
        let mut root_inputs = PartialWitness::new();

        for table in 0..NUM_TABLES {
            if let (Some(stark_proof), Some((table_circuit, index_verifier_data))) = (
                &all_proof.multi_proof.stark_proofs[table],
                &table_circuits[table],
            ) {
                let shrunk_proof =
                    table_circuit.shrink(stark_proof, &all_proof.multi_proof.ctl_challenges)?;
                root_inputs.set_target(
                    self.root.index_verifier_data[table].unwrap(),
                    F::from_canonical_u8(*index_verifier_data),
                );
                root_inputs.set_proof_with_pis_target(
                    &self.root.proof_with_pis[table].clone().unwrap(),
                    &shrunk_proof,
                );

                check_abort_signal(abort_signal.clone())?;
            }
        }

        root_inputs.set_verifier_data_target(
            &self.root.cyclic_vk,
            &self.segment_aggregation.circuit.verifier_only,
        );

        set_public_value_targets(
            &mut root_inputs,
            &self.root.public_values,
            &all_proof.public_values,
        )
        .map_err(|_| {
            anyhow::Error::msg("Invalid conversion when setting public values targets.")
        })?;

        let root_proof = self.root.circuit.prove(root_inputs)?;

        Ok((root_proof, all_proof.public_values))
    }

    pub fn verify_root(&self, agg_proof: ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> {
        self.root.circuit.verify(agg_proof)
    }

    /// Create an aggregation proof, combining two contiguous proofs into a
    /// single one. The combined proofs are segment proofs: they are proofs
    /// of some parts of one execution.
    ///
    /// While regular root proofs can only assert validity of a
    /// single segment of a transaction, segment aggregation proofs
    /// can cover an arbitrary range, up to an entire transaction.
    ///
    /// # Arguments
    ///
    /// - `lhs_is_agg`: a boolean indicating whether the left child proof is an
    ///   aggregation proof or a regular segment proof.
    /// - `lhs_proof`: the left child prover output data.
    /// - `rhs_is_agg`: a boolean indicating whether the right child proof is an
    ///   aggregation proof or a regular transaction proof.
    /// - `rhs_proof`: the right child prover output data.
    ///
    /// # Outputs
    ///
    /// This method outputs a [`ProverOutputData<F, C, D>`]. Only the proof with
    /// public inputs is necessary for a verifier to assert correctness of
    /// the computation, but the public values and `is_dummy` are output for the
    /// prover convenience, as these are necessary during proof aggregation.
    pub fn prove_segment_aggregation(
        &self,
        lhs_is_agg: bool,
        lhs_prover_output: &ProverOutputData<F, C, D>,
        rhs_is_agg: bool,
        rhs_prover_output: &ProverOutputData<F, C, D>,
    ) -> anyhow::Result<ProverOutputData<F, C, D>> {
        let mut agg_inputs = PartialWitness::new();

        let lhs_proof = &lhs_prover_output.proof_with_pis;
        let rhs_proof = &rhs_prover_output.proof_with_pis;
        let rhs_is_dummy = rhs_prover_output.is_dummy;
        Self::set_dummy_if_necessary(
            &self.segment_aggregation.lhs,
            lhs_is_agg,
            &self.segment_aggregation.circuit,
            &mut agg_inputs,
            lhs_proof,
        );

        // If rhs is dummy, the rhs proof is also set to be the lhs.
        let real_rhs_proof = if rhs_is_dummy { lhs_proof } else { rhs_proof };

        Self::set_dummy_if_necessary_with_dummy(
            &self.segment_aggregation.rhs,
            rhs_is_agg,
            rhs_is_dummy,
            &self.segment_aggregation.circuit,
            &mut agg_inputs,
            real_rhs_proof,
        );

        agg_inputs.set_verifier_data_target(
            &self.segment_aggregation.cyclic_vk,
            &self.segment_aggregation.circuit.verifier_only,
        );

        // Aggregates both `PublicValues` from the provided proofs into a single one.

        let lhs_public_values = &lhs_prover_output.public_values;
        let rhs_public_values = &rhs_prover_output.public_values;

        let real_public_values = if rhs_is_dummy {
            lhs_public_values.clone()
        } else {
            rhs_public_values.clone()
        };

        let agg_public_values = PublicValues {
            trie_roots_before: lhs_public_values.trie_roots_before.clone(),
            trie_roots_after: real_public_values.trie_roots_after,
            burn_addr: lhs_public_values.burn_addr,
            extra_block_data: ExtraBlockData {
                checkpoint_state_trie_root: lhs_public_values
                    .extra_block_data
                    .checkpoint_state_trie_root,
                txn_number_before: lhs_public_values.extra_block_data.txn_number_before,
                txn_number_after: real_public_values.extra_block_data.txn_number_after,
                gas_used_before: lhs_public_values.extra_block_data.gas_used_before,
                gas_used_after: real_public_values.extra_block_data.gas_used_after,
            },
            block_metadata: real_public_values.block_metadata,
            block_hashes: real_public_values.block_hashes,
            registers_before: lhs_public_values.registers_before.clone(),
            registers_after: real_public_values.registers_after,
            mem_before: lhs_public_values.mem_before.clone(),
            mem_after: real_public_values.mem_after,
        };

        set_public_value_targets(
            &mut agg_inputs,
            &self.segment_aggregation.public_values,
            &agg_public_values,
        )
        .map_err(|_| {
            anyhow::Error::msg("Invalid conversion when setting public values targets.")
        })?;

        let aggregation_proof = self.segment_aggregation.circuit.prove(agg_inputs)?;
        let agg_output = ProverOutputData {
            is_dummy: false,
            proof_with_pis: aggregation_proof,
            public_values: agg_public_values,
        };
        Ok(agg_output)
    }

    pub fn verify_segment_aggregation(
        &self,
        agg_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<()> {
        self.segment_aggregation.circuit.verify(agg_proof.clone())?;
        check_cyclic_proof_verifier_data(
            agg_proof,
            &self.segment_aggregation.circuit.verifier_only,
            &self.segment_aggregation.circuit.common,
        )
    }

    /// Creates a final transaction proof, once all segments of a given
    /// transaction have been combined into a single aggregation proof.
    ///
    /// Transaction proofs can either be generated as a standalone, or combined
    /// with a previous transaction proof to assert validity of a range of
    /// transactions.
    ///
    /// # Arguments
    ///
    /// - `opt_parent_txn_proof`: an optional parent transaction proof. Passing
    ///   one will generate a proof of validity for both the transaction range
    ///   covered by the previous proof and the current transaction.
    /// - `agg_proof`: the final aggregation proof containing all segments
    ///   within the current transaction.
    /// - `public_values`: the public values associated to the aggregation
    ///   proof.
    ///
    /// # Outputs
    ///
    /// This method outputs a tuple of [`ProofWithPublicInputs<F, C, D>`] and
    /// its [`PublicValues`]. Only the proof with public inputs is necessary
    /// for a verifier to assert correctness of the computation.
    pub fn prove_transaction_aggregation(
        &self,
        lhs_is_agg: bool,
        lhs_proof: &ProofWithPublicInputs<F, C, D>,
        lhs_public_values: PublicValues,
        rhs_is_agg: bool,
        rhs_proof: &ProofWithPublicInputs<F, C, D>,
        rhs_public_values: PublicValues,
    ) -> anyhow::Result<(ProofWithPublicInputs<F, C, D>, PublicValues)> {
        let mut txn_inputs = PartialWitness::new();

        Self::set_dummy_if_necessary(
            &self.txn_aggregation.lhs,
            lhs_is_agg,
            &self.txn_aggregation.circuit,
            &mut txn_inputs,
            lhs_proof,
        );

        Self::set_dummy_if_necessary(
            &self.txn_aggregation.rhs,
            rhs_is_agg,
            &self.txn_aggregation.circuit,
            &mut txn_inputs,
            rhs_proof,
        );

        txn_inputs.set_verifier_data_target(
            &self.txn_aggregation.cyclic_vk,
            &self.txn_aggregation.circuit.verifier_only,
        );

        let txn_public_values = PublicValues {
            trie_roots_before: lhs_public_values.trie_roots_before,
            extra_block_data: ExtraBlockData {
                txn_number_before: lhs_public_values.extra_block_data.txn_number_before,
                gas_used_before: lhs_public_values.extra_block_data.gas_used_before,
                ..rhs_public_values.extra_block_data
            },
            ..rhs_public_values
        };

        set_public_value_targets(
            &mut txn_inputs,
            &self.txn_aggregation.public_values,
            &txn_public_values,
        )
        .map_err(|_| {
            anyhow::Error::msg("Invalid conversion when setting public values targets.")
        })?;

        let txn_proof = self.txn_aggregation.circuit.prove(txn_inputs)?;
        Ok((txn_proof, txn_public_values))
    }

    pub fn verify_txn_aggregation(
        &self,
        txn_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<()> {
        self.txn_aggregation.circuit.verify(txn_proof.clone())?;
        check_cyclic_proof_verifier_data(
            txn_proof,
            &self.txn_aggregation.circuit.verifier_only,
            &self.txn_aggregation.circuit.common,
        )
    }

    /// If the proof is not an aggregation, we set the cyclic vk to a dummy
    /// value, so that it corresponds to the aggregation cyclic vk. If the proof
    /// is dummy, we set `is_dummy` to `true`. Note that only the rhs can be
    /// dummy.
    fn set_dummy_if_necessary_with_dummy(
        agg_child: &AggregationChildWithDummyTarget<D>,
        is_agg: bool,
        is_dummy: bool,
        circuit: &CircuitData<F, C, D>,
        agg_inputs: &mut PartialWitness<F>,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) {
        agg_inputs.set_bool_target(agg_child.is_agg, is_agg);
        agg_inputs.set_bool_target(agg_child.is_dummy, is_dummy);
        if is_agg {
            agg_inputs.set_proof_with_pis_target(&agg_child.agg_proof, proof);
        } else {
            Self::set_dummy_proof_with_cyclic_vk_pis(
                circuit,
                agg_inputs,
                &agg_child.agg_proof,
                proof,
            );
        }
        agg_inputs.set_proof_with_pis_target(&agg_child.real_proof, proof);
    }

    /// Create a final block proof, once all transactions of a given block have
    /// been combined into a single aggregation proof.
    ///
    /// Block proofs can either be generated as standalone, or combined with a
    /// previous block proof to assert validity of a range of blocks.
    ///
    /// # Arguments
    ///
    /// - `opt_parent_block_proof`: an optional parent block proof. Passing one
    ///   will generate a proof of validity for both the block range covered by
    ///   the previous proof and the current block.
    /// - `agg_root_proof`: the final aggregation proof containing all
    ///   transactions within the current block.
    /// - `public_values`: the public values associated to the aggregation
    ///   proof.
    ///
    /// # Outputs
    ///
    /// This method outputs a tuple of [`ProofWithPublicInputs<F, C, D>`] and
    /// its [`PublicValues`]. Only the proof with public inputs is necessary
    /// for a verifier to assert correctness of the computation.
    pub fn prove_block(
        &self,
        opt_parent_block_proof: Option<&ProofWithPublicInputs<F, C, D>>,
        agg_root_proof: &ProofWithPublicInputs<F, C, D>,
        public_values: PublicValues,
    ) -> anyhow::Result<(ProofWithPublicInputs<F, C, D>, PublicValues)> {
        let mut block_inputs = PartialWitness::new();

        block_inputs.set_bool_target(
            self.block.has_parent_block,
            opt_parent_block_proof.is_some(),
        );
        if let Some(parent_block_proof) = opt_parent_block_proof {
            block_inputs
                .set_proof_with_pis_target(&self.block.parent_block_proof, parent_block_proof);
        } else {
            if public_values.trie_roots_before.state_root
                != public_values.extra_block_data.checkpoint_state_trie_root
            {
                return Err(anyhow::Error::msg(format!(
                    "Inconsistent pre-state for first block {:?} with checkpoint state {:?}.",
                    public_values.trie_roots_before.state_root,
                    public_values.extra_block_data.checkpoint_state_trie_root,
                )));
            }

            // Initialize some public inputs for correct connection between the checkpoint
            // block and the current one.
            let mut nonzero_pis = HashMap::new();

            // Initialize the checkpoint block roots before, and state root after.
            let state_trie_root_before_keys = 0..TARGET_HASH_SIZE;
            for (key, &value) in state_trie_root_before_keys
                .zip_eq(&h256_limbs::<F>(public_values.trie_roots_before.state_root))
            {
                nonzero_pis.insert(key, value);
            }
            let txn_trie_root_before_keys = TARGET_HASH_SIZE..TARGET_HASH_SIZE * 2;
            for (key, &value) in txn_trie_root_before_keys.clone().zip_eq(&h256_limbs::<F>(
                public_values.trie_roots_before.transactions_root,
            )) {
                nonzero_pis.insert(key, value);
            }
            let receipts_trie_root_before_keys = TARGET_HASH_SIZE * 2..TARGET_HASH_SIZE * 3;
            for (key, &value) in receipts_trie_root_before_keys
                .clone()
                .zip_eq(&h256_limbs::<F>(
                    public_values.trie_roots_before.receipts_root,
                ))
            {
                nonzero_pis.insert(key, value);
            }
            let state_trie_root_after_keys =
                TrieRootsTarget::SIZE..TrieRootsTarget::SIZE + TARGET_HASH_SIZE;
            for (key, &value) in state_trie_root_after_keys
                .zip_eq(&h256_limbs::<F>(public_values.trie_roots_before.state_root))
            {
                nonzero_pis.insert(key, value);
            }

            let burn_addr_offset = match cfg!(feature = "cdk_erigon") {
                true => BurnAddrTarget::get_size(),
                false => 0,
            };

            #[cfg(feature = "cdk_erigon")]
            {
                let burn_addr_keys =
                    TrieRootsTarget::SIZE * 2..TrieRootsTarget::SIZE * 2 + burn_addr_offset;
                for (key, &value) in burn_addr_keys.zip_eq(&crate::util::u256_limbs(
                    public_values
                        .burn_addr
                        .expect("We should have a burn addr when cdk_erigon is activated"),
                )) {
                    nonzero_pis.insert(key, value);
                }
            }
            // Initialize the checkpoint state root extra data.
            let checkpoint_state_trie_keys = burn_addr_offset
                + TrieRootsTarget::SIZE * 2
                + BlockMetadataTarget::SIZE
                + BlockHashesTarget::SIZE
                ..burn_addr_offset
                    + TrieRootsTarget::SIZE * 2
                    + BlockMetadataTarget::SIZE
                    + BlockHashesTarget::SIZE
                    + 8;
            for (key, &value) in checkpoint_state_trie_keys.zip_eq(&h256_limbs::<F>(
                public_values.extra_block_data.checkpoint_state_trie_root,
            )) {
                nonzero_pis.insert(key, value);
            }

            // Initialize checkpoint block hashes.
            // These will be all zeros the initial genesis checkpoint.
            let block_hashes_keys =
                burn_addr_offset + TrieRootsTarget::SIZE * 2 + BlockMetadataTarget::SIZE
                    ..burn_addr_offset
                        + TrieRootsTarget::SIZE * 2
                        + BlockMetadataTarget::SIZE
                        + BlockHashesTarget::SIZE
                        - 8;

            for i in 0..public_values.block_hashes.prev_hashes.len() - 1 {
                let targets = h256_limbs::<F>(public_values.block_hashes.prev_hashes[i]);
                for j in 0..8 {
                    nonzero_pis.insert(block_hashes_keys.start + 8 * (i + 1) + j, targets[j]);
                }
            }
            let block_hashes_current_start = burn_addr_offset
                + TrieRootsTarget::SIZE * 2
                + BlockMetadataTarget::SIZE
                + BlockHashesTarget::SIZE
                - 8;
            let cur_targets = h256_limbs::<F>(public_values.block_hashes.prev_hashes[255]);
            for i in 0..8 {
                nonzero_pis.insert(block_hashes_current_start + i, cur_targets[i]);
            }

            // Initialize the checkpoint block number.
            // Subtraction would result in an invalid proof for genesis, but we shouldn't
            // try proving this block anyway.
            let block_number_key = burn_addr_offset + TrieRootsTarget::SIZE * 2 + 6;
            nonzero_pis.insert(
                block_number_key,
                F::from_canonical_u64(public_values.block_metadata.block_number.low_u64() - 1),
            );

            block_inputs.set_proof_with_pis_target(
                &self.block.parent_block_proof,
                &cyclic_base_proof(
                    &self.block.circuit.common,
                    &self.block.circuit.verifier_only,
                    nonzero_pis,
                ),
            );
        }

        block_inputs.set_proof_with_pis_target(&self.block.agg_root_proof, agg_root_proof);

        block_inputs
            .set_verifier_data_target(&self.block.cyclic_vk, &self.block.circuit.verifier_only);

        // This is basically identical to this block public values, apart from the
        // `trie_roots_before` that may come from the previous proof, if any.
        let block_public_values = PublicValues {
            trie_roots_before: opt_parent_block_proof
                .map(|p| TrieRoots::from_public_inputs(&p.public_inputs[0..TrieRootsTarget::SIZE]))
                .unwrap_or(public_values.trie_roots_before),
            ..public_values
        };

        set_public_value_targets(
            &mut block_inputs,
            &self.block.public_values,
            &block_public_values,
        )
        .map_err(|_| {
            anyhow::Error::msg("Invalid conversion when setting public values targets.")
        })?;

        let block_proof = self.block.circuit.prove(block_inputs)?;
        Ok((block_proof, block_public_values))
    }

    pub fn verify_block(&self, block_proof: &ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> {
        self.block.circuit.verify(block_proof.clone())?;
        check_cyclic_proof_verifier_data(
            block_proof,
            &self.block.circuit.verifier_only,
            &self.block.circuit.common,
        )
    }

    /// Wrap a block proof, representing one or an aggregation of contiguous
    /// blocks, for easier aggregation with other chains' proofs.
    ///
    /// # Arguments
    ///
    /// - `block_proof`: the final block proof of a chain to be wrapped.
    /// - `public_values`: the public values associated to the aggregation
    ///   proof.
    ///
    /// # Outputs
    ///
    /// This method outputs a tuple of [`ProofWithPublicInputs<F, C, D>`] and
    /// associated [`FinalPublicValues`]. Only the proof with public inputs is
    /// necessary for a verifier to assert correctness of the computation.
    pub fn prove_block_wrapper(
        &self,
        block_proof: &ProofWithPublicInputs<F, C, D>,
        public_values: PublicValues,
    ) -> anyhow::Result<(ProofWithPublicInputs<F, C, D>, FinalPublicValues)> {
        let mut block_wrapper_inputs = PartialWitness::new();

        block_wrapper_inputs
            .set_proof_with_pis_target(&self.block_wrapper.parent_block_proof, block_proof);

        block_wrapper_inputs.set_verifier_data_target(
            &self.block_wrapper.cyclic_vk, // dummy
            &self.block_wrapper.circuit.verifier_only,
        );

        let final_pvs = public_values.into();
        set_final_public_value_targets(
            &mut block_wrapper_inputs,
            &self.block_wrapper.public_values,
            &final_pvs,
        )
        .map_err(|_| {
            anyhow::Error::msg("Invalid conversion when setting public values targets.")
        })?;

        let block_proof = self.block_wrapper.circuit.prove(block_wrapper_inputs)?;

        Ok((block_proof, final_pvs))
    }

    pub fn verify_block_wrapper(
        &self,
        wrapped_block_proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<()> {
        self.block_wrapper
            .circuit
            .verify(wrapped_block_proof.clone())
    }

    /// Aggregates two proofs in manner similar to [`prove_aggregation`].
    ///
    /// # Arguments
    ///
    /// - `lhs`: a proof of either a block or previous aggregation.
    /// - `lhs_is_agg`: specify which case `lhs` was.
    /// - `rhs`: a proof of either a block or previous aggregation.
    /// - `rhs_is_agg`: specify which case `rhs` was.
    ///
    /// # Outputs
    ///
    /// Returns a [`ProofWithPublicInputs<F, C, D>`].
    pub fn prove_two_to_one_block(
        &self,
        lhs: &ProofWithPublicInputs<F, C, D>,
        lhs_is_agg: bool,
        rhs: &ProofWithPublicInputs<F, C, D>,
        rhs_is_agg: bool,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut witness = PartialWitness::new();

        Self::set_dummy_if_necessary(
            &self.two_to_one_block.lhs,
            lhs_is_agg,
            &self.two_to_one_block.circuit,
            &mut witness,
            lhs,
        );

        Self::set_dummy_if_necessary(
            &self.two_to_one_block.rhs,
            rhs_is_agg,
            &self.two_to_one_block.circuit,
            &mut witness,
            rhs,
        );

        witness.set_verifier_data_target(
            &self.two_to_one_block.cyclic_vk,
            &self.two_to_one_block.circuit.verifier_only,
        );

        let proof = self.two_to_one_block.circuit.prove(witness)?;
        Ok(proof)
    }

    /// Verifies an existing block aggregation proof.
    ///
    /// # Arguments
    ///
    /// - `proof`: The proof generated with `prove_two_to_one_block`.
    ///
    /// # Outputs
    ///
    /// Returns whether the proof was valid or not.
    pub fn verify_two_to_one_block(
        &self,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> anyhow::Result<()> {
        self.two_to_one_block.circuit.verify(proof.clone())?;
        let verifier_data = &self.two_to_one_block.circuit.verifier_data();
        check_cyclic_proof_verifier_data(proof, &verifier_data.verifier_only, &verifier_data.common)
    }

    /// Creates dummy public inputs with correct verifier key at the end. Used
    /// by [`set_dummy_if_necessary`]. It cyclic vk to the aggregation circuit
    /// values, so that both aggregation and non-aggregation parts of the child
    /// share the same vk. This is possible because only the aggregation inner
    /// circuit is checked against its vk.
    fn set_dummy_proof_with_cyclic_vk_pis(
        circuit_agg: &CircuitData<F, C, D>,
        witness: &mut PartialWitness<F>,
        agg_proof_with_pis: &ProofWithPublicInputsTarget<D>,
        base_proof_with_pis: &ProofWithPublicInputs<F, C, D>,
    ) {
        let ProofWithPublicInputs {
            proof: base_proof,
            public_inputs: _,
        } = base_proof_with_pis;
        let ProofWithPublicInputsTarget {
            proof: agg_proof_targets,
            public_inputs: agg_pi_targets,
        } = agg_proof_with_pis;

        // The proof remains the same.
        witness.set_proof_target(agg_proof_targets, base_proof);

        let cyclic_verifying_data = &circuit_agg.verifier_only;
        let mut cyclic_vk = cyclic_verifying_data.circuit_digest.to_vec();
        cyclic_vk.append(&mut cyclic_verifying_data.constants_sigmas_cap.flatten());

        let mut dummy_pis = vec![F::ZERO; circuit_agg.common.num_public_inputs - cyclic_vk.len()];
        dummy_pis.append(&mut cyclic_vk);

        // Set dummy public inputs.
        for (&pi_t, pi) in agg_pi_targets.iter().zip_eq(dummy_pis) {
            witness.set_target(pi_t, pi);
        }
    }

    /// If the [`AggregationChild`] is a base proof and not an aggregation
    /// proof, we need to manually set the public inputs vector of the otherwise
    /// inert `agg_proof`, so that they correspond to the `cyclic_vk` of the
    /// aggregation circuit. The cyclic prover expects to find the `cyclic_vk`
    /// targets in the very end of the public inputs vector, and so it does not
    /// matter what the preceding values are.
    fn set_dummy_if_necessary(
        agg_child: &AggregationChildTarget<D>,
        is_agg: bool,
        circuit: &CircuitData<F, C, D>,
        agg_inputs: &mut PartialWitness<F>,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) {
        agg_inputs.set_bool_target(agg_child.is_agg, is_agg);
        if is_agg {
            agg_inputs.set_proof_with_pis_target(&agg_child.agg_proof, proof);
        } else {
            Self::set_dummy_proof_with_cyclic_vk_pis(
                circuit,
                agg_inputs,
                &agg_child.agg_proof,
                proof,
            );
        }
        agg_inputs.set_proof_with_pis_target(&agg_child.base_proof, proof);
    }
}

fn skip_keccak_if_disabled<T>(
    index: usize,
    enable_keccak_tables: bool,
    default_value: T,
    f: impl FnOnce() -> T,
) -> T {
    if !enable_keccak_tables && KECCAK_TABLES_INDICES.contains(&index) {
        default_value
    } else {
        f()
    }
}

/// A map between initial degree sizes and their associated shrinking recursion
/// circuits.
#[derive(Eq, PartialEq, Debug)]
pub struct RecursiveCircuitsForTable<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
{
    /// A map from `log_2(height)` to a chain of shrinking recursion circuits
    /// starting at that height.
    pub by_stark_size: BTreeMap<usize, RecursiveCircuitsForTableSize<F, C, D>>,
}

impl<F, C, const D: usize> RecursiveCircuitsForTable<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
{
    fn to_buffer(
        &self,
        buffer: &mut Vec<u8>,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<()> {
        buffer.write_usize(self.by_stark_size.len())?;
        for (&size, table) in &self.by_stark_size {
            buffer.write_usize(size)?;
            table.to_buffer(buffer, gate_serializer, generator_serializer)?;
        }
        Ok(())
    }

    fn from_buffer(
        buffer: &mut Buffer,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<Self> {
        let length = buffer.read_usize()?;
        let mut by_stark_size = BTreeMap::new();
        for _ in 0..length {
            let key = buffer.read_usize()?;
            let table = RecursiveCircuitsForTableSize::from_buffer(
                buffer,
                gate_serializer,
                generator_serializer,
            )?;
            by_stark_size.insert(key, table);
        }
        Ok(Self { by_stark_size })
    }

    fn new<S: Stark<F, D>>(
        table: Table,
        stark: &S,
        degree_bits_range: Range<usize>,
        all_ctls: &[CrossTableLookup<F>],
        stark_config: &StarkConfig,
    ) -> Self {
        let by_stark_size = degree_bits_range
            .map(|degree_bits| {
                (
                    degree_bits,
                    RecursiveCircuitsForTableSize::new::<S>(
                        table,
                        stark,
                        degree_bits,
                        all_ctls,
                        stark_config,
                    ),
                )
            })
            .collect();
        Self { by_stark_size }
    }

    /// For each initial `degree_bits`, get the final circuit at the end of that
    /// shrinking chain. Each of these final circuits should have degree
    /// `THRESHOLD_DEGREE_BITS`.
    fn final_circuits(&self) -> Vec<&CircuitData<F, C, D>> {
        self.by_stark_size
            .values()
            .map(|chain| {
                chain
                    .shrinking_wrappers
                    .last()
                    .map(|wrapper| &wrapper.circuit)
                    .unwrap_or(&chain.initial_wrapper.circuit)
            })
            .collect()
    }
}

/// A chain of shrinking wrapper circuits, ending with a final circuit with
/// `degree_bits` `THRESHOLD_DEGREE_BITS`.
#[derive(Eq, PartialEq, Debug)]
pub struct RecursiveCircuitsForTableSize<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
{
    initial_wrapper: StarkWrapperCircuit<F, C, D>,
    shrinking_wrappers: Vec<PlonkWrapperCircuit<F, C, D>>,
}

impl<F, C, const D: usize> RecursiveCircuitsForTableSize<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
{
    pub fn to_buffer(
        &self,
        buffer: &mut Vec<u8>,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<()> {
        buffer.write_usize(self.shrinking_wrappers.len())?;
        if !self.shrinking_wrappers.is_empty() {
            buffer.write_common_circuit_data(
                &self.shrinking_wrappers[0].circuit.common,
                gate_serializer,
            )?;
        }
        for wrapper in &self.shrinking_wrappers {
            buffer.write_prover_only_circuit_data(
                &wrapper.circuit.prover_only,
                generator_serializer,
                &wrapper.circuit.common,
            )?;
            buffer.write_verifier_only_circuit_data(&wrapper.circuit.verifier_only)?;
            buffer.write_target_proof_with_public_inputs(&wrapper.proof_with_pis_target)?;
        }
        self.initial_wrapper
            .to_buffer(buffer, gate_serializer, generator_serializer)?;
        Ok(())
    }

    pub fn from_buffer(
        buffer: &mut Buffer,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<Self> {
        let length = buffer.read_usize()?;
        let mut shrinking_wrappers = Vec::with_capacity(length);
        if length != 0 {
            let common = buffer.read_common_circuit_data(gate_serializer)?;

            for _ in 0..length {
                let prover_only =
                    buffer.read_prover_only_circuit_data(generator_serializer, &common)?;
                let verifier_only = buffer.read_verifier_only_circuit_data()?;
                let proof_with_pis_target = buffer.read_target_proof_with_public_inputs()?;
                shrinking_wrappers.push(PlonkWrapperCircuit {
                    circuit: CircuitData {
                        common: common.clone(),
                        prover_only,
                        verifier_only,
                    },
                    proof_with_pis_target,
                })
            }
        };

        let initial_wrapper =
            StarkWrapperCircuit::from_buffer(buffer, gate_serializer, generator_serializer)?;

        Ok(Self {
            initial_wrapper,
            shrinking_wrappers,
        })
    }

    fn new<S: Stark<F, D>>(
        table: Table,
        stark: &S,
        degree_bits: usize,
        all_ctls: &[CrossTableLookup<F>],
        stark_config: &StarkConfig,
    ) -> Self {
        let initial_wrapper = recursive_stark_circuit(
            table,
            stark,
            degree_bits,
            all_ctls,
            stark_config,
            &shrinking_config(),
            THRESHOLD_DEGREE_BITS,
        );
        let mut shrinking_wrappers = vec![];

        // Shrinking recursion loop.
        loop {
            let last = shrinking_wrappers
                .last()
                .map(|wrapper: &PlonkWrapperCircuit<F, C, D>| &wrapper.circuit)
                .unwrap_or(&initial_wrapper.circuit);
            let last_degree_bits = last.common.degree_bits();
            assert!(last_degree_bits >= THRESHOLD_DEGREE_BITS);
            if last_degree_bits == THRESHOLD_DEGREE_BITS {
                break;
            }

            let mut builder = CircuitBuilder::new(shrinking_config());
            let proof_with_pis_target = builder.add_virtual_proof_with_pis(&last.common);
            let last_vk = builder.constant_verifier_data(&last.verifier_only);
            builder.verify_proof::<C>(&proof_with_pis_target, &last_vk, &last.common);
            builder.register_public_inputs(&proof_with_pis_target.public_inputs); // carry PIs forward
            add_common_recursion_gates(&mut builder);
            let circuit = builder.build::<C>();

            assert!(
                circuit.common.degree_bits() < last_degree_bits,
                "Couldn't shrink to expected recursion threshold of 2^{}; stalled at 2^{}",
                THRESHOLD_DEGREE_BITS,
                circuit.common.degree_bits()
            );
            shrinking_wrappers.push(PlonkWrapperCircuit {
                circuit,
                proof_with_pis_target,
            });
        }

        Self {
            initial_wrapper,
            shrinking_wrappers,
        }
    }

    pub fn shrink(
        &self,
        stark_proof_with_metadata: &StarkProofWithMetadata<F, C, D>,
        ctl_challenges: &GrandProductChallengeSet<F>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut proof = self
            .initial_wrapper
            .prove(stark_proof_with_metadata, ctl_challenges)?;
        for wrapper_circuit in &self.shrinking_wrappers {
            proof = wrapper_circuit.prove(&proof)?;
        }
        Ok(proof)
    }
}

/// Our usual recursion threshold is 2^12 gates, but for these shrinking
/// circuits, we use a few more gates for a constant inner VK and for public
/// inputs. This pushes us over the threshold to 2^13. As long as we're at 2^13
/// gates, we might as well use a narrower witness.
fn shrinking_config() -> CircuitConfig {
    CircuitConfig {
        num_routed_wires: 40,
        ..CircuitConfig::standard_recursion_config()
    }
}

/// Extracts the two-to-one block aggregation hash from a public inputs slice.
///
/// # Arguments
///
/// - `public_inputs`: A slice of public inputs originating from the aggregation
///   case of a two-to-one block proof. This slice must consist of a hash,
///   either of public values, or of two concatenated hashes. The hash must
///   start at offset zero of the slice and is typically followed by padding and
///   then a verifier key. It is an error to call this on a slice for a base
///   proof.
///
/// # Outputs
///
/// - A slice containing exactly the hash.
pub fn extract_two_to_one_block_hash<T>(public_inputs: &[T]) -> &[T; NUM_HASH_OUT_ELTS] {
    const PV_HASH_INDEX_START: usize = 0;
    const PV_HASH_INDEX_END: usize = PV_HASH_INDEX_START + NUM_HASH_OUT_ELTS;
    public_inputs[PV_HASH_INDEX_START..PV_HASH_INDEX_END]
        .try_into()
        .expect("Public inputs vector was malformed.")
}

/// Extracts the two-to-one block aggregation public values of the block from
/// a public inputs slice.
///
/// # Arguments
///
/// - `public_inputs`: A slice of public inputs originating from the base case
///   of a two-to-one block proof. This slice must consist exactly of public
///   values starting at offset zero and is typically followed by a verifier
///   key. It is an error to call this function on a slice for an aggregation
///   proof.
///
/// # Outputs
///
/// - A slice containing exactly the final public values.
pub fn extract_block_final_public_values<T>(
    public_inputs: &[T],
) -> &[T; FinalPublicValuesTarget::SIZE] {
    const PV_INDEX_START: usize = 0;
    const PV_INDEX_END: usize = PV_INDEX_START + FinalPublicValuesTarget::SIZE;
    public_inputs[PV_INDEX_START..PV_INDEX_END]
        .try_into()
        .expect("Public inputs vector was malformed.")
}

/// Computes the length added to the public inputs vector by
/// [`CircuitBuilder::add_verifier_data_public_inputs`].
pub const fn verification_key_len<F, C, const D: usize>(circuit: &CircuitData<F, C, D>) -> usize
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
{
    circuit.verifier_only.circuit_digest.elements.len()
        + (1 << circuit.common.config.fri_config.cap_height) * NUM_HASH_OUT_ELTS
}

#[cfg(test)]
mod tests {
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    use super::*;
    use crate::testing_utils::{dummy_payload, init_logger};

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    #[ignore]
    fn test_root_proof_generation() -> anyhow::Result<()> {
        init_logger();

        let all_stark = AllStark::<F, D>::default();
        let config = StarkConfig::standard_fast_config();

        let all_circuits = AllRecursiveCircuits::<F, C, D>::new(
            &all_stark,
            &[16..17, 8..9, 9..10, 4..9, 8..9, 4..7, 17..18, 17..18, 7..18],
            &config,
        );
        let dummy = dummy_payload(100, true)?;

        let timing = &mut TimingTree::new(&format!("Blockproof"), log::Level::Info);
        let dummy_proof =
            all_circuits.prove_all_segments(&all_stark, &config, dummy, 9, timing, None)?;
        all_circuits.verify_root(dummy_proof[0].proof_with_pis.clone())?;
        timing.print();

        Ok(())
    }
}
