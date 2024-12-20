use ethereum_types::U256;
use plonky2::field::extension::Extendable;
use plonky2::field::polynomial::PolynomialValues;
use plonky2::fri::oracle::PolynomialBatch;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::plonk::config::GenericConfig;
use plonky2::util::timing::TimingTree;
use plonky2::util::transpose;

use crate::cpu::kernel::aggregator::KERNEL;
use crate::memory::segments::Segment;

pub(crate) fn initial_memory_merkle_cap<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    rate_bits: usize,
    cap_height: usize,
) -> MerkleCap<F, C::Hasher> {
    // At the start of a transaction proof, `MemBefore` only contains the kernel
    // `Code` segment and the `ShiftTable`.
    let mut trace = Vec::with_capacity((KERNEL.code.len() + 256).next_power_of_two());

    // Push kernel code.
    for (i, &byte) in KERNEL.code.iter().enumerate() {
        let mut row = vec![F::ZERO; crate::memory_continuation::columns::NUM_COLUMNS];
        row[crate::memory_continuation::columns::FILTER] = F::ONE;
        row[crate::memory_continuation::columns::ADDR_CONTEXT] = F::ZERO;
        row[crate::memory_continuation::columns::ADDR_SEGMENT] =
            F::from_canonical_usize(Segment::Code.unscale());
        row[crate::memory_continuation::columns::ADDR_VIRTUAL] = F::from_canonical_usize(i);
        row[crate::memory_continuation::columns::value_limb(0)] = F::from_canonical_u8(byte);
        trace.push(row);
    }
    let mut val = U256::one();
    // Push shift table.
    for i in 0..256 {
        let mut row = vec![F::ZERO; crate::memory_continuation::columns::NUM_COLUMNS];

        row[crate::memory_continuation::columns::FILTER] = F::ONE;
        row[crate::memory_continuation::columns::ADDR_CONTEXT] = F::ZERO;
        row[crate::memory_continuation::columns::ADDR_SEGMENT] =
            F::from_canonical_usize(Segment::ShiftTable.unscale());
        row[crate::memory_continuation::columns::ADDR_VIRTUAL] = F::from_canonical_usize(i);
        for j in 0..crate::memory::VALUE_LIMBS {
            row[j + 4] = F::from_canonical_u32((val >> (j * 32)).low_u32());
        }
        trace.push(row);
        val <<= 1;
    }

    // Padding.
    let num_rows = trace.len();
    let num_rows_padded = num_rows.next_power_of_two();
    trace.resize(
        num_rows_padded,
        vec![F::ZERO; crate::memory_continuation::columns::NUM_COLUMNS],
    );

    let cols = transpose(&trace);
    let polys = cols
        .into_iter()
        .map(|column| PolynomialValues::new(column))
        .collect::<Vec<_>>();

    PolynomialBatch::<F, C, D>::from_values(
        polys,
        rate_bits,
        false,
        cap_height,
        &mut TimingTree::default(),
        None,
    )
    .merkle_tree
    .cap
}

pub mod testing {
    use anyhow::{ensure, Result};
    use ethereum_types::{BigEndianHash, U256};
    use hashbrown::HashMap;
    use itertools::Itertools;
    use plonky2::field::extension::Extendable;
    use plonky2::hash::hash_types::RichField;
    use plonky2::plonk::config::{GenericConfig, GenericHashOut};
    use starky::config::StarkConfig;
    use starky::cross_table_lookup::verify_cross_table_lookups;
    use starky::cross_table_lookup::CrossTableLookup;
    use starky::cross_table_lookup::CtlCheckVars;
    use starky::lookup::GrandProductChallenge;
    use starky::stark::Stark;
    use starky::verifier::verify_stark_proof_with_challenges;

    use crate::all_stark::{Table, MEMORY_CTL_IDX, NUM_CTLS, OPTIONAL_TABLE_INDICES};
    use crate::cpu::kernel::aggregator::KERNEL;
    use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
    use crate::get_challenges::testing::AllProofChallenges;
    use crate::memory::segments::Segment;
    use crate::memory::VALUE_LIMBS;
    use crate::proof::PublicValues;
    use crate::proof::*;
    use crate::util::h2u;
    use crate::verifier::initial_memory_merkle_cap;
    use crate::{AllStark, NUM_TABLES};

    impl<F: RichField + Extendable<D>, const D: usize> AllStark<F, D> {
        pub(crate) fn num_lookups_helper_columns(
            &self,
            config: &StarkConfig,
        ) -> [usize; NUM_TABLES] {
            [
                self.arithmetic_stark.num_lookup_helper_columns(config),
                self.byte_packing_stark.num_lookup_helper_columns(config),
                self.cpu_stark.num_lookup_helper_columns(config),
                self.keccak_stark.num_lookup_helper_columns(config),
                self.keccak_sponge_stark.num_lookup_helper_columns(config),
                self.logic_stark.num_lookup_helper_columns(config),
                self.memory_stark.num_lookup_helper_columns(config),
                self.mem_before_stark.num_lookup_helper_columns(config),
                self.mem_after_stark.num_lookup_helper_columns(config),
                #[cfg(feature = "cdk_erigon")]
                self.poseidon_stark.num_lookup_helper_columns(config),
            ]
        }

        pub fn get_constraint_degree(&self, table: Table) -> usize {
            match table {
                Table::Arithmetic => self.arithmetic_stark.constraint_degree(),
                Table::BytePacking => self.byte_packing_stark.constraint_degree(),
                Table::Cpu => self.cpu_stark.constraint_degree(),
                Table::Keccak => self.keccak_stark.constraint_degree(),
                Table::KeccakSponge => self.keccak_sponge_stark.constraint_degree(),
                Table::Logic => self.logic_stark.constraint_degree(),
                Table::Memory => self.memory_stark.constraint_degree(),
                Table::MemBefore => self.mem_before_stark.constraint_degree(),
                Table::MemAfter => self.mem_after_stark.constraint_degree(),
                #[cfg(feature = "cdk_erigon")]
                Table::Poseidon => self.poseidon_stark.constraint_degree(),
            }
        }
    }

    fn verify_initial_memory<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        public_values: &PublicValues<F>,
        config: &StarkConfig,
    ) -> Result<()> {
        for (hash1, hash2) in initial_memory_merkle_cap::<F, C, D>(
            config.fri_config.rate_bits,
            config.fri_config.cap_height,
        )
        .0
        .iter()
        .zip(public_values.mem_before.mem_cap.iter())
        {
            for (&limb1, limb2) in hash1.to_vec().iter().zip(hash2) {
                ensure!(
                    limb1 == F::from_canonical_u64(limb2.as_u64()),
                    anyhow::Error::msg("Invalid initial MemBefore Merkle cap.")
                );
            }
        }

        Ok(())
    }

    pub fn verify_proof<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        all_stark: &AllStark<F, D>,
        all_proof: AllProof<F, C, D>,
        config: &StarkConfig,
        is_initial: bool,
    ) -> Result<()> {
        let AllProofChallenges {
            stark_challenges,
            ctl_challenges,
        } = all_proof
            .get_challenges(config)
            .map_err(|_| anyhow::Error::msg("Invalid sampling of proof challenges."))?;

        let num_lookup_columns = all_stark.num_lookups_helper_columns(config);

        let AllStark {
            arithmetic_stark,
            byte_packing_stark,
            cpu_stark,
            keccak_stark,
            keccak_sponge_stark,
            logic_stark,
            memory_stark,
            mem_before_stark,
            mem_after_stark,
            #[cfg(feature = "cdk_erigon")]
            poseidon_stark,
            cross_table_lookups,
        } = all_stark;

        let stark_proofs = &all_proof.multi_proof.stark_proofs;

        macro_rules! verify_table {
            ($stark:ident, $table:expr) => {
                if !OPTIONAL_TABLE_INDICES.contains(&*$table) || all_proof.table_in_use[*$table] {
                    let stark_proof = &stark_proofs[*$table]
                        .as_ref()
                        .expect("Missing stark_proof")
                        .proof;
                    let ctl_vars = {
                        let (total_num_helpers, _, num_helpers_by_ctl) =
                            CrossTableLookup::num_ctl_helpers_zs_all(
                                &all_stark.cross_table_lookups,
                                *$table,
                                config.num_challenges,
                                $stark.constraint_degree(),
                            );
                        CtlCheckVars::from_proof(
                            *$table,
                            &stark_proof,
                            &all_stark.cross_table_lookups,
                            &ctl_challenges,
                            num_lookup_columns[*$table],
                            total_num_helpers,
                            &num_helpers_by_ctl,
                        )
                    };
                    verify_stark_proof_with_challenges(
                        $stark,
                        stark_proof,
                        &stark_challenges[*$table]
                            .as_ref()
                            .expect("Missing challenges"),
                        Some(&ctl_vars),
                        &[],
                        config,
                    )?;
                }
            };
        }

        verify_table!(arithmetic_stark, Table::Arithmetic);
        verify_table!(byte_packing_stark, Table::BytePacking);
        verify_table!(cpu_stark, Table::Cpu);
        verify_table!(keccak_stark, Table::Keccak);
        verify_table!(keccak_sponge_stark, Table::KeccakSponge);
        verify_table!(logic_stark, Table::Logic);
        verify_table!(memory_stark, Table::Memory);
        verify_table!(mem_before_stark, Table::MemBefore);
        verify_table!(mem_after_stark, Table::MemAfter);

        #[cfg(feature = "cdk_erigon")]
        verify_table!(poseidon_stark, Table::Poseidon);

        let public_values = all_proof.public_values;

        // Verify shift table and kernel code.
        if is_initial {
            verify_initial_memory::<F, C, D>(&public_values, config)?;
        }

        // Extra sums to add to the looked last value.
        // Only necessary for the Memory values.
        let mut extra_looking_sums =
            HashMap::from_iter((0..NUM_CTLS).map(|i| (i, vec![F::ZERO; config.num_challenges])));

        // Memory
        extra_looking_sums.insert(
            MEMORY_CTL_IDX,
            (0..config.num_challenges)
                .map(|i| get_memory_extra_looking_sum(&public_values, ctl_challenges.challenges[i]))
                .collect_vec(),
        );

        let all_ctls = &all_stark.cross_table_lookups;

        let table_all = Table::all();
        let ctl_zs_first_values = core::array::from_fn(|i| {
            let table = table_all[i];
            if let Some(stark_proof) = &stark_proofs[i] {
                stark_proof
                    .proof
                    .openings
                    .ctl_zs_first
                    .as_ref()
                    .expect("Missing ctl_zs")
                    .clone()
            } else if OPTIONAL_TABLE_INDICES.contains(&table) {
                let degree = all_stark.get_constraint_degree(table);
                let (_, n, _) = CrossTableLookup::num_ctl_helpers_zs_all(
                    all_ctls,
                    i,
                    config.num_challenges,
                    degree,
                );
                vec![F::ZERO; n]
            } else {
                panic!("Unable to find stark_proof for table {:?}", table);
            }
        });

        verify_cross_table_lookups::<F, D, NUM_TABLES>(
            cross_table_lookups,
            ctl_zs_first_values,
            &extra_looking_sums,
            config,
        )
    }

    /// Computes the extra product to multiply to the looked value. It contains
    /// memory operations not in the CPU trace:
    /// - block metadata writes,
    /// - trie roots writes.
    pub(crate) fn get_memory_extra_looking_sum<F, const D: usize>(
        public_values: &PublicValues<F>,
        challenge: GrandProductChallenge<F>,
    ) -> F
    where
        F: RichField + Extendable<D>,
    {
        let mut sum = F::ZERO;

        // Add metadata and tries writes.
        let fields = [
            (
                GlobalMetadata::BlockBeneficiary,
                U256::from_big_endian(&public_values.block_metadata.block_beneficiary.0),
            ),
            #[cfg(feature = "cdk_erigon")]
            (
                GlobalMetadata::BurnAddr,
                public_values
                    .burn_addr
                    .expect("There should be an address set in cdk_erigon."),
            ),
            (
                GlobalMetadata::BlockTimestamp,
                public_values.block_metadata.block_timestamp,
            ),
            (
                GlobalMetadata::BlockNumber,
                public_values.block_metadata.block_number,
            ),
            (
                GlobalMetadata::BlockRandom,
                public_values.block_metadata.block_random.into_uint(),
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
                GlobalMetadata::BlockBaseFee,
                public_values.block_metadata.block_base_fee,
            ),
            #[cfg(feature = "eth_mainnet")]
            (
                GlobalMetadata::ParentBeaconBlockRoot,
                h2u(public_values.block_metadata.parent_beacon_block_root),
            ),
            (
                GlobalMetadata::BlockCurrentHash,
                h2u(public_values.block_hashes.cur_hash),
            ),
            (
                GlobalMetadata::BlockGasUsed,
                public_values.block_metadata.block_gas_used,
            ),
            #[cfg(feature = "eth_mainnet")]
            (
                GlobalMetadata::BlockBlobGasUsed,
                public_values.block_metadata.block_blob_gas_used,
            ),
            #[cfg(feature = "eth_mainnet")]
            (
                GlobalMetadata::BlockExcessBlobGas,
                public_values.block_metadata.block_excess_blob_gas,
            ),
            (
                GlobalMetadata::TxnNumberBefore,
                public_values.extra_block_data.txn_number_before,
            ),
            (
                GlobalMetadata::TxnNumberAfter,
                public_values.extra_block_data.txn_number_after,
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
                GlobalMetadata::StateTrieRootDigestBefore,
                h2u(public_values.trie_roots_before.state_root),
            ),
            (
                GlobalMetadata::TransactionTrieRootDigestBefore,
                h2u(public_values.trie_roots_before.transactions_root),
            ),
            (
                GlobalMetadata::ReceiptTrieRootDigestBefore,
                h2u(public_values.trie_roots_before.receipts_root),
            ),
            (
                GlobalMetadata::StateTrieRootDigestAfter,
                h2u(public_values.trie_roots_after.state_root),
            ),
            (
                GlobalMetadata::TransactionTrieRootDigestAfter,
                h2u(public_values.trie_roots_after.transactions_root),
            ),
            (
                GlobalMetadata::ReceiptTrieRootDigestAfter,
                h2u(public_values.trie_roots_after.receipts_root),
            ),
            (GlobalMetadata::KernelHash, h2u(KERNEL.code_hash)),
            (GlobalMetadata::KernelLen, KERNEL.code.len().into()),
        ];

        let segment = F::from_canonical_usize(Segment::GlobalMetadata.unscale());

        fields.map(|(field, val)| {
            // These fields are already scaled by their segment, and are in context 0
            // (kernel).
            sum = add_data_write(challenge, segment, sum, field.unscale(), val)
        });

        // Add block bloom writes.
        let bloom_segment = F::from_canonical_usize(Segment::GlobalBlockBloom.unscale());
        for index in 0..8 {
            let val = public_values.block_metadata.block_bloom[index];
            sum = add_data_write(challenge, bloom_segment, sum, index, val);
        }

        // Add Blockhashes writes.
        let block_hashes_segment = F::from_canonical_usize(Segment::BlockHashes.unscale());
        for index in 0..256 {
            let val = h2u(public_values.block_hashes.prev_hashes[index]);
            sum = add_data_write(challenge, block_hashes_segment, sum, index, val);
        }

        let registers_segment = F::from_canonical_usize(Segment::RegistersStates.unscale());
        let registers_before = [
            public_values.registers_before.program_counter,
            public_values.registers_before.is_kernel,
            public_values.registers_before.stack_len,
            public_values.registers_before.stack_top,
            public_values.registers_before.context,
            public_values.registers_before.gas_used,
        ];
        for i in 0..registers_before.len() {
            sum = add_data_write(challenge, registers_segment, sum, i, registers_before[i]);
        }
        let registers_after = [
            public_values.registers_after.program_counter,
            public_values.registers_after.is_kernel,
            public_values.registers_after.stack_len,
            public_values.registers_after.stack_top,
            public_values.registers_after.context,
            public_values.registers_after.gas_used,
        ];
        for i in 0..registers_before.len() {
            sum = add_data_write(
                challenge,
                registers_segment,
                sum,
                registers_before.len() + i,
                registers_after[i],
            );
        }

        sum
    }

    fn add_data_write<F, const D: usize>(
        challenge: GrandProductChallenge<F>,
        segment: F,
        running_sum: F,
        index: usize,
        val: U256,
    ) -> F
    where
        F: RichField + Extendable<D>,
    {
        let mut row = [F::ZERO; 13];
        row[0] = F::ZERO; // is_read
        row[1] = F::ZERO; // context
        row[2] = segment;
        row[3] = F::from_canonical_usize(index);

        for j in 0..VALUE_LIMBS {
            row[j + 4] = F::from_canonical_u32((val >> (j * 32)).low_u32());
        }
        row[12] = F::TWO; // timestamp
        running_sum + challenge.combine(row.iter()).inverse()
    }

    pub fn verify_all_proofs<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >(
        all_stark: &AllStark<F, D>,
        all_proofs: &[AllProof<F, C, D>],
        config: &StarkConfig,
    ) -> Result<()> {
        assert!(!all_proofs.is_empty());

        verify_proof(all_stark, all_proofs[0].clone(), config, true)?;

        for all_proof in &all_proofs[1..] {
            verify_proof(all_stark, all_proof.clone(), config, false)?;
        }

        Ok(())
    }
}

#[cfg(debug_assertions)]
pub(crate) mod debug_utils {
    use ethereum_types::BigEndianHash;

    use super::*;
    use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
    use crate::memory::VALUE_LIMBS;
    use crate::proof::*;
    use crate::util::h2u;

    /// Output all the extra memory rows that don't appear in the CPU trace but
    /// are necessary to correctly check the MemoryStark CTL.
    pub(crate) fn get_memory_extra_looking_values<F, const D: usize>(
        public_values: &PublicValues<F>,
    ) -> Vec<Vec<F>>
    where
        F: RichField + Extendable<D>,
    {
        // Add metadata and tries writes.
        let fields = [
            (
                GlobalMetadata::BlockBeneficiary,
                U256::from_big_endian(&public_values.block_metadata.block_beneficiary.0),
            ),
            #[cfg(feature = "cdk_erigon")]
            (
                GlobalMetadata::BurnAddr,
                public_values
                    .burn_addr
                    .expect("There should be an address set in cdk_erigon."),
            ),
            (
                GlobalMetadata::BlockTimestamp,
                public_values.block_metadata.block_timestamp,
            ),
            (
                GlobalMetadata::BlockNumber,
                public_values.block_metadata.block_number,
            ),
            (
                GlobalMetadata::BlockRandom,
                public_values.block_metadata.block_random.into_uint(),
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
                GlobalMetadata::BlockBaseFee,
                public_values.block_metadata.block_base_fee,
            ),
            (
                GlobalMetadata::BlockCurrentHash,
                h2u(public_values.block_hashes.cur_hash),
            ),
            (
                GlobalMetadata::BlockGasUsed,
                public_values.block_metadata.block_gas_used,
            ),
            #[cfg(feature = "eth_mainnet")]
            (
                GlobalMetadata::BlockBlobGasUsed,
                public_values.block_metadata.block_blob_gas_used,
            ),
            #[cfg(feature = "eth_mainnet")]
            (
                GlobalMetadata::BlockExcessBlobGas,
                public_values.block_metadata.block_excess_blob_gas,
            ),
            #[cfg(feature = "eth_mainnet")]
            (
                GlobalMetadata::ParentBeaconBlockRoot,
                h2u(public_values.block_metadata.parent_beacon_block_root),
            ),
            (
                GlobalMetadata::TxnNumberBefore,
                public_values.extra_block_data.txn_number_before,
            ),
            (
                GlobalMetadata::TxnNumberAfter,
                public_values.extra_block_data.txn_number_after,
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
                GlobalMetadata::StateTrieRootDigestBefore,
                h2u(public_values.trie_roots_before.state_root),
            ),
            (
                GlobalMetadata::TransactionTrieRootDigestBefore,
                h2u(public_values.trie_roots_before.transactions_root),
            ),
            (
                GlobalMetadata::ReceiptTrieRootDigestBefore,
                h2u(public_values.trie_roots_before.receipts_root),
            ),
            (
                GlobalMetadata::StateTrieRootDigestAfter,
                h2u(public_values.trie_roots_after.state_root),
            ),
            (
                GlobalMetadata::TransactionTrieRootDigestAfter,
                h2u(public_values.trie_roots_after.transactions_root),
            ),
            (
                GlobalMetadata::ReceiptTrieRootDigestAfter,
                h2u(public_values.trie_roots_after.receipts_root),
            ),
            (GlobalMetadata::KernelHash, h2u(KERNEL.code_hash)),
            (GlobalMetadata::KernelLen, KERNEL.code.len().into()),
        ];

        let segment = F::from_canonical_usize(Segment::GlobalMetadata.unscale());
        let mut extra_looking_rows = Vec::new();

        fields.map(|(field, val)| {
            extra_looking_rows.push(add_extra_looking_row(segment, field.unscale(), val))
        });

        // Add block bloom writes.
        let bloom_segment = F::from_canonical_usize(Segment::GlobalBlockBloom.unscale());
        for index in 0..8 {
            let val = public_values.block_metadata.block_bloom[index];
            extra_looking_rows.push(add_extra_looking_row(bloom_segment, index, val));
        }

        // Add Blockhashes writes.
        let block_hashes_segment = F::from_canonical_usize(Segment::BlockHashes.unscale());
        for index in 0..256 {
            let val = h2u(public_values.block_hashes.prev_hashes[index]);
            extra_looking_rows.push(add_extra_looking_row(block_hashes_segment, index, val));
        }

        // Add registers writes.
        let registers_segment = F::from_canonical_usize(Segment::RegistersStates.unscale());
        let registers_before = [
            public_values.registers_before.program_counter,
            public_values.registers_before.is_kernel,
            public_values.registers_before.stack_len,
            public_values.registers_before.stack_top,
            public_values.registers_before.context,
            public_values.registers_before.gas_used,
        ];
        for i in 0..registers_before.len() {
            extra_looking_rows.push(add_extra_looking_row(
                registers_segment,
                i,
                registers_before[i],
            ));
        }
        let registers_after = [
            public_values.registers_after.program_counter,
            public_values.registers_after.is_kernel,
            public_values.registers_after.stack_len,
            public_values.registers_after.stack_top,
            public_values.registers_after.context,
            public_values.registers_after.gas_used,
        ];
        for i in 0..registers_before.len() {
            extra_looking_rows.push(add_extra_looking_row(
                registers_segment,
                registers_before.len() + i,
                registers_after[i],
            ));
        }

        extra_looking_rows
    }

    fn add_extra_looking_row<F, const D: usize>(segment: F, index: usize, val: U256) -> Vec<F>
    where
        F: RichField + Extendable<D>,
    {
        let mut row = vec![F::ZERO; 13];
        row[0] = F::ZERO; // is_read
        row[1] = F::ZERO; // context
        row[2] = segment;
        row[3] = F::from_canonical_usize(index);

        for j in 0..VALUE_LIMBS {
            row[j + 4] = F::from_canonical_u32((val >> (j * 32)).low_u32());
        }
        row[12] = F::TWO; // timestamp
        row
    }
}
