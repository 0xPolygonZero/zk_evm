use std::{
    fs::{self, OpenOptions},
    io::Write,
};

use plonky2::{
    plonk::config::PoseidonGoldilocksConfig,
    util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer},
};
use plonky_block_proof_gen::{prover_state::ProverState, types::AllRecursiveCircuits};
use tracing::warn;

type Config = PoseidonGoldilocksConfig;
const SIZE: usize = 2;
const PATH: &str = "./prover_state";

pub fn get_serializers() -> (DefaultGateSerializer, DefaultGeneratorSerializer<Config, 2>) {
    let gate_serializer = DefaultGateSerializer;
    let witness_serializer: DefaultGeneratorSerializer<Config, SIZE> = DefaultGeneratorSerializer {
        _phantom: Default::default(),
    };

    (gate_serializer, witness_serializer)
}

pub(crate) fn from_disk() -> Option<ProverState> {
    let bytes = fs::read(PATH).ok()?;
    let (gate_serializer, witness_serializer) = get_serializers();
    let state = AllRecursiveCircuits::from_bytes(&bytes, &gate_serializer, &witness_serializer);

    match state {
        Ok(state) => Some(ProverState { state }),
        Err(e) => {
            warn!("failed to deserialize prover state, {e:?}");
            None
        }
    }
}

pub(crate) fn to_disk(state: &ProverState) {
    let file = OpenOptions::new().write(true).create(true).open(PATH);

    let mut file = match file {
        Ok(file) => file,
        Err(e) => {
            warn!("failed to create prover state file, {e:?}");
            return;
        }
    };

    let (gate_serializer, witness_serializer) = get_serializers();

    let bytes = state.state.to_bytes(&gate_serializer, &witness_serializer);

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
