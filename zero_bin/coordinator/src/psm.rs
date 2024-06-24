//! This module helps with creating the [ProverStateManager]

use std::env;

use zero_bin_common::prover_state::{
    circuit::CircuitConfig, CircuitPersistence, ProverStateManager, TableLoadStrategy,
};
use tracing::{error, info, warn};

pub const PSM_CIRCUIT_TABLE_LOAD_STRAT_ENVKEY: &str = "PSM_TABLE_LOAD_STRAT";
pub const PSM_CIRCUIT_PERSISTENCE_ENVKEY: &str = "PSM_CIRCUIT_PERSISTENCE";

pub fn load_psm_from_env() -> ProverStateManager {
    let tbl_load_strat = match env::var(PSM_CIRCUIT_TABLE_LOAD_STRAT_ENVKEY) {
        Ok(tls) if tls.contains("ON_DEMAND") => {
            info!("Loaded OnDemand TabeLoadStrategy from .env");
            Some(TableLoadStrategy::OnDemand)
        }
        Ok(tls) if tls.contains("MONOLITHIC") => {
            info!("Loaded Monolithic TabeLoadStrategy from .env");
            Some(TableLoadStrategy::Monolithic)
        }
        Ok(tls) => {
            error!("Unknown Table Load Strategy: {}", tls);
            panic!("Unknown Table Load Strategy: {}", tls);
        }
        Err(env::VarError::NotPresent) => {
            info!("Table Load Strategy not present in .env");
            None
        }
        Err(env::VarError::NotUnicode(os_str)) => {
            error!("Non-Unicode string for Table Load Strategy: `{:?}`", os_str);
            panic!("Non-Unicode string for Table Load Strategy: `{:?}`", os_str);
        }
    };

    let persistence = match env::var(PSM_CIRCUIT_PERSISTENCE_ENVKEY) {
        Ok(persistence) if persistence.contains("NONE") => {
            info!("Loaded `None` CircuitPersistence from .env");
            CircuitPersistence::None
        }
        Ok(persistence) if persistence.contains("DISK") => match tbl_load_strat {
            Some(tbl_load_strat) => {
                info!("Loaded `Disk` CircuitPersistence from .env");
                CircuitPersistence::Disk(tbl_load_strat)
            }
            None => {
                warn!("Table Load Strategy not specified, using default");
                CircuitPersistence::Disk(TableLoadStrategy::default())
            }
        },
        Ok(persistence) => {
            error!("Unable to determine circiut persistence: `{}`", persistence);
            panic!("Unable to determine circiut persistence: `{}`", persistence);
        }
        Err(env::VarError::NotPresent) => {
            warn!("No circuit persistence specified, using default");
            CircuitPersistence::default()
        }
        Err(env::VarError::NotUnicode(os_str)) => {
            error!("Non-Unicode circiut persistence: {:?}", os_str);
            panic!("Non-Unicode circiut persistence: {:?}", os_str);
        }
    };

    ProverStateManager {
        circuit_config: CircuitConfig::default(),
        persistence,
    }
}
