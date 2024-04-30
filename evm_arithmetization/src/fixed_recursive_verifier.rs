use core::mem::{self, MaybeUninit};
use core::ops::Range;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::anyhow;
use ethereum_types::U256;
use hashbrown::HashMap;
use itertools::{zip_eq, Itertools};
use mpt_trie::partial_trie::{HashedPartialTrie, Node, PartialTrie};
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::fri::oracle::PolynomialBatch;
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
use plonky2::plonk::prover::prove as prove_plonky2;
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::{self, cyclic_base_proof, dummy_circuit, dummy_proof};
use plonky2::util::serialization::{
    Buffer, GateSerializer, IoResult, Read, WitnessGeneratorSerializer, Write,
};
use plonky2::util::timing::TimingTree;
use plonky2::util::transpose;
use plonky2_util::log2_ceil;
use starky::config::StarkConfig;
use starky::cross_table_lookup::{verify_cross_table_lookups_circuit, CrossTableLookup};
use starky::lookup::{get_grand_product_challenge_set_target, GrandProductChallengeSet};
use starky::proof::StarkProofWithMetadata;
use starky::stark::Stark;

use crate::all_stark::{all_cross_table_lookups, AllStark, Table, NUM_TABLES};
use crate::cpu::kernel::aggregator::KERNEL;
use crate::generation::GenerationInputs;
use crate::get_challenges::observe_public_values_target;
use crate::memory::segments::Segment;
use crate::proof::{
    AllProof, BlockHashesTarget, BlockMetadataTarget, ExtraBlockData, ExtraBlockDataTarget, MemCap,
    MemCapTarget, PublicValues, PublicValuesTarget, RegistersDataTarget, TrieRoots,
    TrieRootsTarget,
};
use crate::prover::{check_abort_signal, generate_all_data_segments, prove, GenerationSegmentData};
use crate::recursive_verifier::{
    add_common_recursion_gates, add_virtual_public_values, get_memory_extra_looking_sum_circuit,
    recursive_stark_circuit, set_public_value_targets, PlonkWrapperCircuit, PublicInputs,
    StarkWrapperCircuit,
};
use crate::util::{h160_limbs, h256_limbs, u256_limbs};
use crate::verifier::initial_memory_merkle_cap;
use crate::witness::memory::MemoryAddress;
use crate::witness::state::RegistersState;

/// The recursion threshold. We end a chain of recursive proofs once we reach
/// this size.
const THRESHOLD_DEGREE_BITS: usize = 13;

pub struct ProverOutputData<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
{
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
    /// The segment aggregation circuit, which verifies that two segment proofs
    /// that can either be root or aggregation proofs.
    pub segment_aggregation: SegmentAggregationCircuitData<F, C, D>,
    /// The transaction aggregation circuit, which verifies the aggregation of
    /// two proofs that can either be a segment aggregation representing a
    /// transaction or an aggregation of transactions.
    pub txn_aggregation: TxnAggregationCircuitData<F, C, D>,
    /// The block circuit, which verifies a transaction aggregation proof and an
    /// optional previous block proof.
    pub block: BlockCircuitData<F, C, D>,
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
    proof_with_pis: [ProofWithPublicInputsTarget<D>; NUM_TABLES],
    /// For each table, various inner circuits may be used depending on the
    /// initial table size. This target holds the index of the circuit
    /// (within `final_circuits()`) that was used.
    index_verifier_data: [Target; NUM_TABLES],
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
        for proof in &self.proof_with_pis {
            buffer.write_target_proof_with_public_inputs(proof)?;
        }
        for index in self.index_verifier_data {
            buffer.write_target(index)?;
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
        let mut proof_with_pis = Vec::with_capacity(NUM_TABLES);
        for _ in 0..NUM_TABLES {
            proof_with_pis.push(buffer.read_target_proof_with_public_inputs()?);
        }
        let mut index_verifier_data = Vec::with_capacity(NUM_TABLES);
        for _ in 0..NUM_TABLES {
            index_verifier_data.push(buffer.read_target()?);
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
struct AggregationChildTarget<const D: usize> {
    is_agg: BoolTarget,
    agg_proof: ProofWithPublicInputsTarget<D>,
    proof: ProofWithPublicInputsTarget<D>,
}

impl<const D: usize> AggregationChildTarget<D> {
    fn to_buffer(&self, buffer: &mut Vec<u8>) -> IoResult<()> {
        buffer.write_target_bool(self.is_agg)?;
        buffer.write_target_proof_with_public_inputs(&self.agg_proof)?;
        buffer.write_target_proof_with_public_inputs(&self.proof)?;
        Ok(())
    }

    fn from_buffer(buffer: &mut Buffer) -> IoResult<Self> {
        let is_agg = buffer.read_target_bool()?;
        let agg_proof = buffer.read_target_proof_with_public_inputs()?;
        let proof = buffer.read_target_proof_with_public_inputs()?;
        Ok(Self {
            is_agg,
            agg_proof,
            proof,
        })
    }

    // `len_mem_cap` is the length of the Merkle
    // caps for `MemBefore` and `MemAfter`.
    fn public_values<F: RichField + Extendable<D>>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        len_mem_cap: usize,
    ) -> PublicValuesTarget {
        let agg_pv =
            PublicValuesTarget::from_public_inputs(&self.agg_proof.public_inputs, len_mem_cap);
        let segment_pv =
            PublicValuesTarget::from_public_inputs(&self.proof.public_inputs, len_mem_cap);
        PublicValuesTarget::select(builder, self.is_agg, agg_pv, segment_pv)
    }
}

#[derive(Eq, PartialEq, Debug)]
struct AggregationChildWithDummyTarget<const D: usize> {
    is_agg: BoolTarget,
    is_dummy: BoolTarget,
    agg_proof: ProofWithPublicInputsTarget<D>,
    real_proof: ProofWithPublicInputsTarget<D>,
    dummy_proof: ProofWithPublicInputsTarget<D>,
}

impl<const D: usize> AggregationChildWithDummyTarget<D> {
    fn to_buffer(&self, buffer: &mut Vec<u8>) -> IoResult<()> {
        buffer.write_target_bool(self.is_agg)?;
        buffer.write_target_bool(self.is_dummy)?;
        buffer.write_target_proof_with_public_inputs(&self.agg_proof)?;
        buffer.write_target_proof_with_public_inputs(&self.real_proof)?;
        buffer.write_target_proof_with_public_inputs(&self.dummy_proof)?;
        Ok(())
    }

    fn from_buffer(buffer: &mut Buffer) -> IoResult<Self> {
        let is_agg = buffer.read_target_bool()?;
        let is_dummy = buffer.read_target_bool()?;
        let agg_proof = buffer.read_target_proof_with_public_inputs()?;
        let real_proof = buffer.read_target_proof_with_public_inputs()?;
        let dummy_proof = buffer.read_target_proof_with_public_inputs()?;
        Ok(Self {
            is_agg,
            is_dummy,
            agg_proof,
            real_proof,
            dummy_proof,
        })
    }

    // `len_mem_cap` is the length of the Merkle
    // caps for `MemBefore` and `MemAfter`.
    fn public_values<F: RichField + Extendable<D>>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        len_mem_cap: usize,
    ) -> PublicValuesTarget {
        let agg_pv =
            PublicValuesTarget::from_public_inputs(&self.agg_proof.public_inputs, len_mem_cap);
        let real_pv =
            PublicValuesTarget::from_public_inputs(&self.real_proof.public_inputs, len_mem_cap);
        let dummy_pv =
            PublicValuesTarget::from_public_inputs(&self.dummy_proof.public_inputs, len_mem_cap);
        let segment_pv = PublicValuesTarget::select(builder, self.is_dummy, dummy_pv, real_pv);
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
    ///   upper circuits
    /// or the entire prover state, including recursive circuits to shrink STARK
    /// proofs.
    /// - `gate_serializer`: a custom gate serializer needed to serialize
    ///   recursive circuits
    /// common data.
    /// - `generator_serializer`: a custom generator serializer needed to
    ///   serialize recursive
    /// circuits proving data.
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
        self.segment_aggregation
            .to_buffer(&mut buffer, gate_serializer, generator_serializer)?;
        self.txn_aggregation
            .to_buffer(&mut buffer, gate_serializer, generator_serializer)?;
        self.block
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
    ///   upper circuits
    /// or the entire prover state, including recursive circuits to shrink STARK
    /// proofs.
    /// - `gate_serializer`: a custom gate serializer needed to serialize
    ///   recursive circuits
    /// common data.
    /// - `generator_serializer`: a custom generator serializer needed to
    ///   serialize recursive
    /// circuits proving data.
    pub fn from_bytes(
        bytes: &[u8],
        skip_tables: bool,
        gate_serializer: &dyn GateSerializer<F, D>,
        generator_serializer: &dyn WitnessGeneratorSerializer<F, D>,
    ) -> IoResult<Self> {
        let mut buffer = Buffer::new(bytes);
        let root =
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
            segment_aggregation,
            txn_aggregation,
            block,
            by_table,
        })
    }

    /// Preprocess all recursive circuits used by the system.
    ///
    /// # Arguments
    ///
    /// - `all_stark`: a structure defining the logic of all STARK modules and
    ///   their associated
    /// cross-table lookups.
    /// - `degree_bits_ranges`: the logarithmic ranges to be supported for the
    ///   recursive tables.
    /// Transactions may yield arbitrary trace lengths for each STARK module
    /// (within some bounds), unknown prior generating the witness to create
    /// a proof. Thus, for each STARK module, we construct a map from
    /// `2^{degree_bits} = length` to a chain of shrinking recursion circuits,
    /// starting from that length, for each `degree_bits` in the range specified
    /// for this STARK module. Specifying a wide enough range allows a
    /// prover to cover all possible scenarios.
    /// - `stark_config`: the configuration to be used for the STARK prover. It
    ///   will usually be a fast
    /// one yielding large proofs.
    pub fn new(
        all_stark: &AllStark<F, D>,
        degree_bits_ranges: &[Range<usize>; NUM_TABLES],
        stark_config: &StarkConfig,
    ) -> Self {
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
            degree_bits_ranges[Table::MemBefore as usize].clone(),
            &all_stark.cross_table_lookups,
            stark_config,
        );
        let mem_after = RecursiveCircuitsForTable::new(
            Table::MemAfter,
            &all_stark.mem_after_stark,
            degree_bits_ranges[Table::MemAfter as usize].clone(),
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
        ];
        let root = Self::create_segment_circuit(&by_table, stark_config);
        let segment_aggregation = Self::create_segment_aggregation_circuit(&root);
        let txn_aggregation =
            Self::create_txn_aggregation_circuit(&segment_aggregation, stark_config);
        let block = Self::create_block_circuit(&txn_aggregation);
        Self {
            root,
            segment_aggregation,
            txn_aggregation,
            block,
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
    ) -> RootCircuitData<F, C, D> {
        let inner_common_data: [_; NUM_TABLES] =
            core::array::from_fn(|i| &by_table[i].final_circuits()[0].common);

        let cap_length = 1
            << inner_common_data[*Table::MemBefore]
                .fri_params
                .config
                .cap_height;

        let mut builder = CircuitBuilder::new(CircuitConfig::standard_recursion_config());

        let public_values = add_virtual_public_values(&mut builder, cap_length);

        let recursive_proofs =
            core::array::from_fn(|i| builder.add_virtual_proof_with_pis(inner_common_data[i]));
        let pis: [_; NUM_TABLES] = core::array::from_fn(|i| {
            PublicInputs::<Target, <C::Hasher as AlgebraicHasher<F>>::AlgebraicPermutation>::from_vec(
                &recursive_proofs[i].public_inputs,
                stark_config,
            )
        });
        let index_verifier_data = core::array::from_fn(|_i| builder.add_virtual_target());

        let mut challenger = RecursiveChallenger::<F, C::Hasher, D>::new(&mut builder);
        for pi in &pis {
            for h in &pi.trace_cap {
                challenger.observe_elements(h);
            }
        }

        observe_public_values_target::<F, C, D>(&mut challenger, &public_values);

        let ctl_challenges = get_grand_product_challenge_set_target(
            &mut builder,
            &mut challenger,
            stark_config.num_challenges,
        );
        // Check that the correct CTL challenges are used in every proof.
        for pi in &pis {
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

        let state = challenger.compact(&mut builder);
        for (&before, &s) in zip_eq(state.as_ref(), pis[0].challenger_state_before.as_ref()) {
            builder.connect(before, s);
        }
        // Check that the challenger state is consistent between proofs.
        for i in 1..NUM_TABLES {
            for (&before, &after) in zip_eq(
                pis[i].challenger_state_before.as_ref(),
                pis[i - 1].challenger_state_after.as_ref(),
            ) {
                builder.connect(before, after);
            }
        }

        // Extra sums to add to the looked last value.
        // Only necessary for the Memory values.
        let mut extra_looking_sums =
            vec![vec![builder.zero(); stark_config.num_challenges]; NUM_TABLES];

        // Memory
        extra_looking_sums[*Table::Memory] = (0..stark_config.num_challenges)
            .map(|c| {
                get_memory_extra_looking_sum_circuit(
                    &mut builder,
                    &public_values,
                    ctl_challenges.challenges[c],
                )
            })
            .collect_vec();

        // Verify the CTL checks.
        verify_cross_table_lookups_circuit::<F, D, NUM_TABLES>(
            &mut builder,
            all_cross_table_lookups(),
            pis.map(|p| p.ctl_zs_first),
            Some(&extra_looking_sums),
            stark_config,
        );

        for (i, table_circuits) in by_table.iter().enumerate() {
            let final_circuits = table_circuits.final_circuits();
            for final_circuit in &final_circuits {
                assert_eq!(
                    &final_circuit.common, inner_common_data[i],
                    "common_data mismatch"
                );
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
            let inner_verifier_data =
                builder.random_access_verifier_data(index_verifier_data[i], possible_vks);

            builder.verify_proof::<C>(
                &recursive_proofs[i],
                &inner_verifier_data,
                inner_common_data[i],
            );
        }

        let merkle_before = MemCapTarget::from_public_inputs(
            &recursive_proofs[*Table::MemBefore].public_inputs,
            cap_length,
        );
        let merkle_after = MemCapTarget::from_public_inputs(
            &recursive_proofs[*Table::MemAfter].public_inputs,
            cap_length,
        );
        // Connect Memory before and after the execution with
        // the public values.
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
            ConstantGate::new(inner_common_data[0].config.num_constants),
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
        let cap_before_len = root.proof_with_pis[*Table::MemBefore]
            .proof
            .wires_cap
            .0
            .len();

        let mut builder = CircuitBuilder::<F, D>::new(root.circuit.common.config.clone());
        let public_values = add_virtual_public_values(&mut builder, cap_before_len);
        let cyclic_vk = builder.add_verifier_data_public_inputs();

        let lhs_segment = Self::add_segment_agg_child(&mut builder, root);
        let rhs_segment = Self::add_segment_agg_child_with_dummy(&mut builder, root);

        let lhs_pv = lhs_segment.public_values(&mut builder, cap_before_len);
        let rhs_pv = rhs_segment.public_values(&mut builder, cap_before_len);

        // All the block metadata is the same for both segments. It is also the case for
        // extra_block_data.
        TrieRootsTarget::connect(
            &mut builder,
            public_values.trie_roots_before,
            lhs_pv.trie_roots_before,
        );
        TrieRootsTarget::connect(
            &mut builder,
            lhs_pv.trie_roots_after,
            rhs_pv.trie_roots_after,
        );
        TrieRootsTarget::connect(
            &mut builder,
            public_values.trie_roots_after,
            rhs_pv.trie_roots_after,
        );
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
        ExtraBlockDataTarget::connect(
            &mut builder,
            public_values.extra_block_data,
            rhs_pv.extra_block_data,
        );
        ExtraBlockDataTarget::connect(
            &mut builder,
            public_values.extra_block_data,
            lhs_pv.extra_block_data,
        );

        // Connect registers and merkle caps between segments.
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
        RegistersDataTarget::connect(
            &mut builder,
            lhs_pv.registers_after,
            rhs_pv.registers_before.clone(),
        );
        MemCapTarget::connect(
            &mut builder,
            public_values.mem_before.clone(),
            lhs_pv.mem_before.clone(),
        );
        MemCapTarget::connect(
            &mut builder,
            public_values.mem_after.clone(),
            rhs_pv.mem_after.clone(),
        );
        MemCapTarget::connect(&mut builder, lhs_pv.mem_after, rhs_pv.mem_before.clone());

        // If the rhs is a dummy, then the lhs must be a segment.
        let segment_assert = builder.mul(rhs_segment.is_dummy.target, lhs_segment.is_agg.target);
        builder.assert_zero(segment_assert);

        // If the rhs is a dummy, then its PV after must be equal to its PV before.
        TrieRootsTarget::assert_equal_if(
            &mut builder,
            rhs_segment.is_dummy,
            rhs_pv.trie_roots_before,
            rhs_pv.trie_roots_after,
        );
        RegistersDataTarget::assert_equal_if(
            &mut builder,
            rhs_segment.is_dummy,
            rhs_pv.registers_before,
            rhs_pv.registers_after,
        );
        MemCapTarget::assert_equal_if(
            &mut builder,
            rhs_segment.is_dummy,
            rhs_pv.mem_before,
            rhs_pv.mem_after,
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

        let cap_len = agg.public_values.mem_before.mem_cap.0.len();

        let mut builder = CircuitBuilder::<F, D>::new(agg.circuit.common.config.clone());
        let public_values = add_virtual_public_values(&mut builder, cap_len);
        let cyclic_vk = builder.add_verifier_data_public_inputs();

        let lhs_txn_proof = Self::add_txn_agg_child(&mut builder, agg);
        let rhs_txn_proof = Self::add_txn_agg_child(&mut builder, agg);

        let lhs_pv = lhs_txn_proof.public_values(&mut builder, cap_len);
        let rhs_pv = rhs_txn_proof.public_values(&mut builder, cap_len);

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
        let mem_cap_len = agg.public_values.mem_before.mem_cap.0.len();
        let public_values = add_virtual_public_values(&mut builder, mem_cap_len);
        let has_parent_block = builder.add_virtual_bool_target_safe();
        let parent_block_proof = builder.add_virtual_proof_with_pis(&expected_common_data);
        let agg_root_proof = builder.add_virtual_proof_with_pis(&agg.circuit.common);

        // Connect block hashes
        Self::connect_block_hashes(&mut builder, &parent_block_proof, &agg_root_proof);

        let parent_pv =
            PublicValuesTarget::from_public_inputs(&parent_block_proof.public_inputs, mem_cap_len);
        let agg_pv =
            PublicValuesTarget::from_public_inputs(&agg_root_proof.public_inputs, mem_cap_len);

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
        let proof = builder.add_virtual_proof_with_pis(common);
        builder
            .conditionally_verify_cyclic_proof::<C>(is_agg, &agg_proof, &proof, &root_vk, common)
            .expect("Failed to build cyclic recursion circuit");
        AggregationChildTarget {
            is_agg,
            agg_proof,
            proof,
        }
    }

    fn add_segment_agg_child_with_dummy(
        builder: &mut CircuitBuilder<F, D>,
        root: &RootCircuitData<F, C, D>,
    ) -> AggregationChildWithDummyTarget<D> {
        let common = &root.circuit.common;
        let root_vk = builder.constant_verifier_data(&root.circuit.verifier_only);
        let is_agg = builder.add_virtual_bool_target_safe();
        let agg_proof = builder.add_virtual_proof_with_pis(common);
        let is_dummy = builder.add_virtual_bool_target_safe();
        let real_proof = builder.add_virtual_proof_with_pis(common);
        let (dummy_proof, dummy_vk) = builder
            .dummy_proof_and_constant_vk_no_generator::<C>(common)
            .expect("Failed to build dummy proof.");

        let segment_proof = builder.select_proof_with_pis(is_dummy, &dummy_proof, &real_proof);
        let segment_vk = builder.select_verifier_data(is_dummy, &dummy_vk, &root_vk);
        builder
            .conditionally_verify_cyclic_proof::<C>(
                is_agg,
                &agg_proof,
                &segment_proof,
                &segment_vk,
                common,
            )
            .expect("Failed to build cyclic recursion circuit");
        AggregationChildWithDummyTarget {
            is_agg,
            is_dummy,
            agg_proof,
            real_proof,
            dummy_proof,
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
        let proof = builder.add_virtual_proof_with_pis(common);
        builder
            .conditionally_verify_cyclic_proof::<C>(
                is_agg,
                &agg_proof,
                &proof,
                &inner_segment_agg_vk,
                common,
            )
            .expect("Failed to build cyclic recursion circuit");
        AggregationChildTarget {
            is_agg,
            agg_proof,
            proof,
        }
    }

    /// Connect the 256 block hashes between two blocks
    fn connect_block_hashes(
        builder: &mut CircuitBuilder<F, D>,
        lhs: &ProofWithPublicInputsTarget<D>,
        rhs: &ProofWithPublicInputsTarget<D>,
    ) {
        // We don't need `mem_before` and `mem_after` in blocks, so we set
        // the associated lengths to 0.
        let lhs_public_values = PublicValuesTarget::from_public_inputs(&lhs.public_inputs, 0);
        let rhs_public_values = PublicValuesTarget::from_public_inputs(&rhs.public_inputs, 0);
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
    ///   their associated
    /// cross-table lookups.
    /// - `config`: the configuration to be used for the STARK prover. It will
    ///   usually be a fast
    /// one yielding large proofs.
    /// - `generation_inputs`: a transaction and auxiliary data needed to
    ///   generate a proof, provided
    /// in Intermediary Representation.
    /// - `timing`: a profiler defining a scope hierarchy and the time consumed
    ///   by each one.
    /// - `abort_signal`: an optional [`AtomicBool`] wrapped behind an [`Arc`],
    ///   to send a kill signal
    /// early. This is only necessary in a distributed setting where a worker
    /// may be blocking the entire queue.
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
        generation_inputs: GenerationInputs,
        segment_data: &mut GenerationSegmentData,
        timing: &mut TimingTree,
        abort_signal: Option<Arc<AtomicBool>>,
    ) -> anyhow::Result<ProverOutputData<F, C, D>> {
        let proof = if segment_data.is_dummy() {
            let dummy_proof = Self::dummy_dummy_proof()?;
            let trie_roots_before = TrieRoots {
                state_root: generation_inputs.tries.state_trie.hash(),
                receipts_root: generation_inputs.tries.receipts_trie.hash(),
                transactions_root: generation_inputs.tries.transactions_trie.hash(),
            };
            let nb_txn = match generation_inputs.signed_txn {
                Some(_) => 1,
                None => 0,
            };
            ProverOutputData {
                proof_with_pis: dummy_proof,
                public_values: PublicValues {
                    is_dummy: U256::one(),
                    trie_roots_before,
                    trie_roots_after: generation_inputs.trie_roots_after.clone(),
                    block_hashes: generation_inputs.block_hashes.clone(),
                    block_metadata: generation_inputs.block_metadata.clone(),
                    registers_before: segment_data.registers_before.into(),
                    registers_after: segment_data.registers_after.into(),
                    mem_before: MemCap::default(),
                    mem_after: MemCap::default(),
                    extra_block_data: ExtraBlockData {
                        checkpoint_state_trie_root: generation_inputs.checkpoint_state_trie_root,
                        txn_number_before: generation_inputs.txn_number_before,
                        txn_number_after: generation_inputs.txn_number_before + nb_txn,
                        gas_used_before: generation_inputs.gas_used_before,
                        gas_used_after: generation_inputs.gas_used_after,
                    },
                },
            }
        } else {
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
                let stark_proof = &all_proof.multi_proof.stark_proofs[table];
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
                    self.root.index_verifier_data[table],
                    F::from_canonical_usize(index_verifier_data),
                );
                root_inputs
                    .set_proof_with_pis_target(&self.root.proof_with_pis[table], &shrunk_proof);

                check_abort_signal(abort_signal.clone())?;
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

            ProverOutputData {
                proof_with_pis: root_proof,
                public_values: all_proof.public_values,
            }
        };
        Ok(proof)
    }

    fn dummy_dummy_proof() -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut builder = CircuitBuilder::new(CircuitConfig::default());
        builder.add_gate(NoopGate, vec![]);
        let circuit_data = builder.build::<_>();

        let inputs = PartialWitness::new();

        prove_plonky2(
            &circuit_data.prover_only,
            &circuit_data.common,
            inputs,
            &mut TimingTree::default(),
        )
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
        let mut all_data_segments =
            generate_all_data_segments::<F>(Some(max_cpu_len_log), &generation_inputs)?;
        let mut proofs = Vec::with_capacity(all_data_segments.len());
        for mut data in all_data_segments {
            let proof = self.prove_segment(
                all_stark,
                config,
                generation_inputs.clone(),
                &mut data,
                timing,
                abort_signal.clone(),
            )?;
            proofs.push(proof);
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
        table_circuits: &[(RecursiveCircuitsForTableSize<F, C, D>, u8); NUM_TABLES],
        abort_signal: Option<Arc<AtomicBool>>,
    ) -> anyhow::Result<(ProofWithPublicInputs<F, C, D>, PublicValues)> {
        let mut root_inputs = PartialWitness::new();

        for table in 0..NUM_TABLES {
            let (table_circuit, index_verifier_data) = &table_circuits[table];

            let stark_proof = &all_proof.multi_proof.stark_proofs[table];

            let shrunk_proof =
                table_circuit.shrink(stark_proof, &all_proof.multi_proof.ctl_challenges)?;
            root_inputs.set_target(
                self.root.index_verifier_data[table],
                F::from_canonical_u8(*index_verifier_data),
            );
            root_inputs.set_proof_with_pis_target(&self.root.proof_with_pis[table], &shrunk_proof);

            check_abort_signal(abort_signal.clone())?;
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
    ///   aggregation proof or
    /// a regular segment proof.
    /// - `lhs_proof`: the left child proof.
    /// - `lhs_public_values`: the public values associated to the right child
    ///   proof.
    /// - `rhs_is_agg`: a boolean indicating whether the right child proof is an
    ///   aggregation proof or
    /// a regular transaction proof.
    /// - `rhs_proof`: the right child proof.
    /// - `rhs_public_values`: the public values associated to the right child
    ///   proof.
    ///
    /// # Outputs
    ///
    /// This method outputs a tuple of [`ProofWithPublicInputs<F, C, D>`] and
    /// its [`PublicValues`]. Only the proof with public inputs is necessary
    /// for a verifier to assert correctness of the computation,
    /// but the public values are output for the prover convenience, as these
    /// are necessary during proof aggregation.
    pub fn prove_segment_aggregation(
        &self,
        lhs_is_agg: bool,
        lhs_proof: &ProofWithPublicInputs<F, C, D>,
        lhs_public_values: PublicValues,

        rhs_is_agg: bool,
        rhs_proof: &ProofWithPublicInputs<F, C, D>,
        rhs_public_values: PublicValues,
    ) -> anyhow::Result<(ProofWithPublicInputs<F, C, D>, PublicValues)> {
        let mut agg_inputs = PartialWitness::new();

        Self::set_dummy_if_necessary(
            &self.segment_aggregation.lhs,
            lhs_is_agg,
            &self.segment_aggregation.circuit,
            &mut agg_inputs,
            lhs_proof,
        );

        let len_mem_cap = self
            .segment_aggregation
            .public_values
            .mem_before
            .mem_cap
            .0
            .len();

        let rhs_is_dummy = !rhs_public_values.is_dummy.is_zero();
        let real_rhs_proof = if rhs_is_dummy { lhs_proof } else { rhs_proof };

        Self::set_dummy_if_necessary_with_dummy(
            &self.segment_aggregation.rhs,
            rhs_is_agg,
            rhs_is_dummy,
            &self.segment_aggregation.circuit,
            &mut agg_inputs,
            real_rhs_proof,
            len_mem_cap,
        );

        agg_inputs.set_verifier_data_target(
            &self.segment_aggregation.cyclic_vk,
            &self.segment_aggregation.circuit.verifier_only,
        );

        // Aggregates both `PublicValues` from the provided proofs into a single one.
        let agg_public_values = PublicValues {
            trie_roots_before: lhs_public_values.trie_roots_before,
            trie_roots_after: rhs_public_values.trie_roots_after,
            extra_block_data: ExtraBlockData {
                checkpoint_state_trie_root: lhs_public_values
                    .extra_block_data
                    .checkpoint_state_trie_root,
                txn_number_before: lhs_public_values.extra_block_data.txn_number_before,
                txn_number_after: rhs_public_values.extra_block_data.txn_number_after,
                gas_used_before: lhs_public_values.extra_block_data.gas_used_before,
                gas_used_after: rhs_public_values.extra_block_data.gas_used_after,
            },
            block_metadata: rhs_public_values.block_metadata,
            block_hashes: rhs_public_values.block_hashes,
            registers_before: lhs_public_values.registers_before,
            registers_after: rhs_public_values.registers_after,
            mem_before: lhs_public_values.mem_before,
            mem_after: rhs_public_values.mem_after,
            is_dummy: U256::zero(),
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
        Ok((aggregation_proof, agg_public_values))
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
    ///   one will generate a proof of
    /// validity for both the transaction range covered by the previous proof
    /// and the current transaction.
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

    /// Used in the case of a non aggregation transaction child.
    /// Creates dummy public inputs to set the cyclic vk to the aggregation
    /// circuit values, so that both aggregation and non-aggregation parts
    /// of the child share the same vk. This is possible because only the
    /// aggregation inner circuit is checked against its vk.
    fn set_dummy_proof_with_cyclic_vk_pis(
        circuit_agg: &CircuitData<F, C, D>,
        witness: &mut PartialWitness<F>,
        agg_proof: &ProofWithPublicInputsTarget<D>,
        proof: &ProofWithPublicInputs<F, C, D>,
    ) {
        let ProofWithPublicInputs {
            proof,
            public_inputs,
        } = proof;
        let ProofWithPublicInputsTarget {
            proof: proof_targets,
            public_inputs: pi_targets,
        } = agg_proof;

        // The proof remains the same.
        witness.set_proof_target(proof_targets, proof);

        let num_pis = circuit_agg.common.num_public_inputs;
        let mut dummy_pis = vec![F::ZERO; num_pis];
        let cyclic_verifying_data = &circuit_agg.verifier_only;
        let mut cyclic_vk = cyclic_verifying_data.circuit_digest.to_vec();
        cyclic_vk.append(&mut cyclic_verifying_data.constants_sigmas_cap.flatten());

        let cyclic_vk_len = cyclic_vk.len();
        for i in 0..cyclic_vk_len {
            dummy_pis[num_pis - cyclic_vk_len + i] = cyclic_vk[i];
        }

        // Set dummy public inputs.
        for (&pi_t, pi) in pi_targets.iter().zip_eq(dummy_pis) {
            witness.set_target(pi_t, pi);
        }
    }

    /// If the lhs is not an aggregation, we set the cyclic vk to a dummy value,
    /// so that it corresponds to the aggregation cyclic vk.
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
            )
        }
        agg_inputs.set_proof_with_pis_target(&agg_child.proof, proof);
    }

    /// TODO: Better comment. This function also takes care of the dummy PIs.
    fn set_dummy_if_necessary_with_dummy(
        agg_child: &AggregationChildWithDummyTarget<D>,
        is_agg: bool,
        is_dummy: bool,
        circuit: &CircuitData<F, C, D>,
        agg_inputs: &mut PartialWitness<F>,
        proof: &ProofWithPublicInputs<F, C, D>,
        len_mem_cap: usize,
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
            if is_dummy {
                let mut dummy_pis = proof.public_inputs.clone();
                // We must change trie roots before, registers before and memory before.
                // Trie roots before := Trie roots after
                dummy_pis.copy_within(TrieRootsTarget::SIZE..TrieRootsTarget::SIZE * 2, 0);
                // Registers before := Registers after
                dummy_pis.copy_within(
                    TrieRootsTarget::SIZE * 2
                        + BlockMetadataTarget::SIZE
                        + BlockHashesTarget::SIZE
                        + ExtraBlockDataTarget::SIZE
                        + RegistersDataTarget::SIZE
                        ..TrieRootsTarget::SIZE * 2
                            + BlockMetadataTarget::SIZE
                            + BlockHashesTarget::SIZE
                            + ExtraBlockDataTarget::SIZE
                            + RegistersDataTarget::SIZE * 2,
                    TrieRootsTarget::SIZE * 2
                        + BlockMetadataTarget::SIZE
                        + BlockHashesTarget::SIZE
                        + ExtraBlockDataTarget::SIZE,
                );
                // Mem before := Mem after
                dummy_pis.copy_within(
                    TrieRootsTarget::SIZE * 2
                        + BlockMetadataTarget::SIZE
                        + BlockHashesTarget::SIZE
                        + ExtraBlockDataTarget::SIZE
                        + RegistersDataTarget::SIZE * 2
                        + len_mem_cap * NUM_HASH_OUT_ELTS
                        ..TrieRootsTarget::SIZE * 2
                            + BlockMetadataTarget::SIZE
                            + BlockHashesTarget::SIZE
                            + ExtraBlockDataTarget::SIZE
                            + RegistersDataTarget::SIZE * 2
                            + 2 * len_mem_cap * NUM_HASH_OUT_ELTS,
                    TrieRootsTarget::SIZE * 2
                        + BlockMetadataTarget::SIZE
                        + BlockHashesTarget::SIZE
                        + ExtraBlockDataTarget::SIZE
                        + RegistersDataTarget::SIZE * 2,
                );

                let mut dummy_pis_map = HashMap::new();
                for (idx, &pi) in dummy_pis.iter().enumerate() {
                    dummy_pis_map.insert(idx, pi);
                }

                let dummy_circuit = dummy_circuit::<F, C, D>(&circuit.common);
                let dummy_proof = dummy_proof::<F, C, D>(&dummy_circuit, dummy_pis_map)
                    .expect("Cannot generate dummy proof.");

                agg_inputs.set_proof_with_pis_target(&agg_child.dummy_proof, &dummy_proof);
            } else {
                agg_inputs.set_proof_with_pis_target(&agg_child.dummy_proof, proof);
            }
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
    ///   will generate a proof of
    /// validity for both the block range covered by the previous proof and the
    /// current block.
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
            let state_trie_root_before_keys = 0..TrieRootsTarget::HASH_SIZE;
            for (key, &value) in state_trie_root_before_keys
                .zip_eq(&h256_limbs::<F>(public_values.trie_roots_before.state_root))
            {
                nonzero_pis.insert(key, value);
            }
            let txn_trie_root_before_keys =
                TrieRootsTarget::HASH_SIZE..TrieRootsTarget::HASH_SIZE * 2;
            for (key, &value) in txn_trie_root_before_keys.clone().zip_eq(&h256_limbs::<F>(
                public_values.trie_roots_before.transactions_root,
            )) {
                nonzero_pis.insert(key, value);
            }
            let receipts_trie_root_before_keys =
                TrieRootsTarget::HASH_SIZE * 2..TrieRootsTarget::HASH_SIZE * 3;
            for (key, &value) in receipts_trie_root_before_keys
                .clone()
                .zip_eq(&h256_limbs::<F>(
                    public_values.trie_roots_before.receipts_root,
                ))
            {
                nonzero_pis.insert(key, value);
            }
            let state_trie_root_after_keys =
                TrieRootsTarget::SIZE..TrieRootsTarget::SIZE + TrieRootsTarget::HASH_SIZE;
            for (key, &value) in state_trie_root_after_keys
                .zip_eq(&h256_limbs::<F>(public_values.trie_roots_before.state_root))
            {
                nonzero_pis.insert(key, value);
            }

            // Initialize the checkpoint state root extra data.
            let checkpoint_state_trie_keys =
                TrieRootsTarget::SIZE * 2 + BlockMetadataTarget::SIZE + BlockHashesTarget::SIZE
                    ..TrieRootsTarget::SIZE * 2
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
            let block_hashes_keys = TrieRootsTarget::SIZE * 2 + BlockMetadataTarget::SIZE
                ..TrieRootsTarget::SIZE * 2 + BlockMetadataTarget::SIZE + BlockHashesTarget::SIZE
                    - 8;

            for i in 0..public_values.block_hashes.prev_hashes.len() - 1 {
                let targets = h256_limbs::<F>(public_values.block_hashes.prev_hashes[i]);
                for j in 0..8 {
                    nonzero_pis.insert(block_hashes_keys.start + 8 * (i + 1) + j, targets[j]);
                }
            }
            let block_hashes_current_start =
                TrieRootsTarget::SIZE * 2 + BlockMetadataTarget::SIZE + BlockHashesTarget::SIZE - 8;
            let cur_targets = h256_limbs::<F>(public_values.block_hashes.prev_hashes[255]);
            for i in 0..8 {
                nonzero_pis.insert(block_hashes_current_start + i, cur_targets[i]);
            }

            // Initialize the checkpoint block number.
            // Subtraction would result in an invalid proof for genesis, but we shouldn't
            // try proving this block anyway.
            let block_number_key = TrieRootsTarget::SIZE * 2 + 6;
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
