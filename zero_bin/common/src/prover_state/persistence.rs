use std::{
    fs::{self, OpenOptions},
    io::Write,
};

use plonky2::{
    plonk::config::PoseidonGoldilocksConfig,
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use plonky_block_proof_gen::types::{AllRecursiveCircuits, VerifierData};
use tracing::{info, warn};

use super::circuit::CircuitConfig;

type Config = PoseidonGoldilocksConfig;
const SIZE: usize = 2;
const PROVER_STATE_FILE_PREFIX: &str = "./prover_state";
const VERIFIER_STATE_FILE_PREFIX: &str = "./verifier_state";

fn get_serializers() -> (DefaultGateSerializer, DefaultGeneratorSerializer<Config, 2>) {
    let gate_serializer = DefaultGateSerializer;
    let witness_serializer: DefaultGeneratorSerializer<Config, SIZE> = DefaultGeneratorSerializer {
        _phantom: Default::default(),
    };

    (gate_serializer, witness_serializer)
}

#[inline]
fn disk_path(circuit_config: &CircuitConfig, prefix: &str) -> String {
    format!("{}_{}", prefix, circuit_config.get_configuration_digest())
}

/// Loads [`AllRecursiveCircuits`] from disk.
pub fn prover_from_disk(circuit_config: &CircuitConfig) -> Option<AllRecursiveCircuits> {
    let path = disk_path(circuit_config, PROVER_STATE_FILE_PREFIX);
    let bytes = fs::read(&path).ok()?;
    info!("found prover state at {path}");
    let (gate_serializer, witness_serializer) = get_serializers();
    info!("deserializing prover state...");
    let state =
        AllRecursiveCircuits::from_bytes(&bytes, false, &gate_serializer, &witness_serializer);

    match state {
        Ok(state) => Some(state),
        Err(e) => {
            warn!("failed to deserialize prover state, {e:?}");
            None
        }
    }
}

/// Loads [`VerifierData`] from disk.
pub fn verifier_from_disk(circuit_config: &CircuitConfig) -> Option<VerifierData> {
    let path = disk_path(circuit_config, VERIFIER_STATE_FILE_PREFIX);
    let bytes = fs::read(&path).ok()?;
    info!("found verifier state at {path}");
    let (gate_serializer, _witness_serializer) = get_serializers();
    info!("deserializing verifier state...");
    let state = VerifierData::from_bytes(bytes, &gate_serializer);

    match state {
        Ok(state) => Some(state),
        Err(e) => {
            warn!("failed to deserialize verifier state, {e:?}");
            None
        }
    }
}

/// Writes the provided [`AllRecursiveCircuits`] to disk, along with the
/// associated [`VerifierData`], in two distinct files.
pub fn to_disk(circuits: &AllRecursiveCircuits, circuit_config: &CircuitConfig) {
    prover_to_disk(circuits, circuit_config);
    verifier_to_disk(&circuits.final_verifier_data(), circuit_config);
}

/// Writes the provided [`AllRecursiveCircuits`] to disk.
fn prover_to_disk(circuits: &AllRecursiveCircuits, circuit_config: &CircuitConfig) {
    let (gate_serializer, witness_serializer) = get_serializers();

    // Write prover state to disk
    if let Err(e) = circuits
        .to_bytes(false, &gate_serializer, &witness_serializer)
        .map(|bytes| {
            write_bytes_to_file(&bytes, disk_path(circuit_config, PROVER_STATE_FILE_PREFIX))
        })
    {
        warn!("failed to create prover state file, {e:?}");
    };
}

/// Writes the provided [`VerifierData`] to disk.
pub fn verifier_to_disk(circuit: &VerifierData, circuit_config: &CircuitConfig) {
    let (gate_serializer, _witness_serializer) = get_serializers();

    // Write verifier state to disk
    if let Err(e) = circuit.to_bytes(&gate_serializer).map(|bytes| {
        write_bytes_to_file(
            &bytes,
            disk_path(circuit_config, VERIFIER_STATE_FILE_PREFIX),
        )
    }) {
        warn!("failed to create verifier state file, {e:?}");
    };
}

fn write_bytes_to_file(bytes: &[u8], path: String) {
    let file = OpenOptions::new().write(true).create(true).open(path);

    let mut file = match file {
        Ok(file) => file,
        Err(e) => {
            warn!("failed to create circuits file, {e:?}");
            return;
        }
    };

    if let Err(e) = file.write_all(bytes) {
        warn!("failed to write circuits file, {e:?}");
    }
}
