use std::{
    fs::{self, OpenOptions},
    io::Write,
};

use plonky2::{
    plonk::config::PoseidonGoldilocksConfig,
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use plonky_block_proof_gen::types::AllRecursiveCircuits;
use tracing::{info, warn};

use super::circuit::CircuitConfig;

type Config = PoseidonGoldilocksConfig;
const SIZE: usize = 2;
const PROVER_STATE_FILE_PREFIX: &str = "./prover_state";

fn get_serializers() -> (DefaultGateSerializer, DefaultGeneratorSerializer<Config, 2>) {
    let gate_serializer = DefaultGateSerializer;
    let witness_serializer: DefaultGeneratorSerializer<Config, SIZE> = DefaultGeneratorSerializer {
        _phantom: Default::default(),
    };

    (gate_serializer, witness_serializer)
}

#[inline]
fn disk_path(circuit_config: &CircuitConfig) -> String {
    format!(
        "{}_{}",
        PROVER_STATE_FILE_PREFIX,
        circuit_config.get_configuration_digest()
    )
}

pub fn from_disk(circuit_config: &CircuitConfig) -> Option<AllRecursiveCircuits> {
    let path = disk_path(circuit_config);
    let bytes = fs::read(&path).ok()?;
    info!("found prover state at {path}");
    let (gate_serializer, witness_serializer) = get_serializers();
    info!("deserializing prover state...");
    let state = AllRecursiveCircuits::from_bytes(&bytes, &gate_serializer, &witness_serializer);

    match state {
        Ok(state) => Some(state),
        Err(e) => {
            warn!("failed to deserialize prover state, {e:?}");
            None
        }
    }
}

pub fn to_disk(circuits: &AllRecursiveCircuits, circuit_config: &CircuitConfig) {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(disk_path(circuit_config));

    let mut file = match file {
        Ok(file) => file,
        Err(e) => {
            warn!("failed to create prover state file, {e:?}");
            return;
        }
    };

    let (gate_serializer, witness_serializer) = get_serializers();

    let bytes = circuits.to_bytes(&gate_serializer, &witness_serializer);

    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!("failed to create prover state file, {e:?}");
            return;
        }
    };

    if let Err(e) = file.write_all(&bytes) {
        warn!("failed to write prover state file, {e:?}");
    }
}
