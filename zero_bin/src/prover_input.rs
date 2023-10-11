use anyhow::Result;
use ethereum_types::{Address, Bloom, U256};
use plonky2_evm::proof::BlockMetadata;
use plonky_block_proof_gen::{
    proof_gen::{generate_agg_proof, generate_block_proof, generate_txn_proof},
    proof_types::{BlockLevelData, GeneratedBlockProof},
    prover_state::ProverState,
};
use plonky_edge_block_trace_parser::edge_payloads::EdgeBlockTrace;
use serde::Deserialize;
use tracing::debug;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EdgeBlockMetadata {
    pub(crate) miner: Address,
    pub(crate) logs_bloom: Bloom,
    pub(crate) difficulty: U256,
    pub(crate) number: U256,
    pub(crate) gas_limit: U256,
    pub(crate) gas_used: U256,
    pub(crate) timestamp: U256,
    pub(crate) base_fee_per_gas: U256,
}

const MATIC_CHAIN_ID: usize = 2001;

impl From<EdgeBlockMetadata> for BlockMetadata {
    fn from(v: EdgeBlockMetadata) -> Self {
        let mut block_bloom = [U256::zero(); 8];

        // Note that bloom can be empty.
        for (i, v) in v
            .logs_bloom
            .as_bytes()
            .iter()
            .array_chunks::<32>()
            .enumerate()
        {
            block_bloom[i] = U256::from_big_endian(&v.iter().map(|&b| *b).collect::<Vec<u8>>()[..]);
        }

        Self {
            block_beneficiary: v.miner,
            block_timestamp: v.timestamp,
            block_number: v.number,
            block_difficulty: v.difficulty,
            block_gaslimit: v.gas_limit,
            block_chain_id: MATIC_CHAIN_ID.into(),
            block_base_fee: v.base_fee_per_gas,
            block_gas_used: v.gas_used,
            block_bloom,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct ProverInput {
    pub(crate) trace: EdgeBlockTrace,
    pub(crate) metadata: EdgeBlockMetadata,
}

impl ProverInput {
    pub(crate) fn prove(self, p_state: &ProverState) -> Result<GeneratedBlockProof> {
        let number = self.metadata.number;
        let b_data = BlockLevelData {
            b_meta: self.metadata.into(),
            b_hashes: Default::default(),
        };

        debug!("Proving block #{number}: {b_data:#?}");

        let txs = self.trace.into_txn_proof_gen_payloads(number.as_u64())?;

        let mut txn_proofs = txs
            .into_iter()
            .map(|tx| generate_txn_proof(p_state, tx, b_data.clone()));

        // We should have at least two txs in a block, given dummy padding in
        // `plonky_edge_block_trace_parser`.
        let (fst, snd) = (
            txn_proofs.next().expect("Expected at least two txns")?,
            txn_proofs.next().expect("Expected at least two txns")?,
        );

        let agg_proof = txn_proofs.try_fold(
            generate_agg_proof(p_state, &fst.into(), &snd.into(), b_data.clone())?,
            |agg, tx| generate_agg_proof(p_state, &agg.into(), &tx?.into(), b_data.clone()),
        )?;

        Ok(generate_block_proof(p_state, None, &agg_proof, b_data)?)
    }
}
