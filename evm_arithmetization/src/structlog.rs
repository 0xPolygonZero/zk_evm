use alloy::primitives::B256;
use alloy::providers::ext::DebugApi;
use alloy::providers::Provider;
use alloy::rpc::types::trace::geth::{GethDebugTracingOptions, GethDefaultTracingOptions};
use alloy::transports::RpcError;
use alloy::transports::Transport;
use alloy::transports::TransportErrorKind;
use zerostructlog::{normalize_structlog, ZeroStructLog};

/// Pass `true` for the components needed.
fn structlog_tracing_options(stack: bool, memory: bool, storage: bool) -> GethDebugTracingOptions {
    GethDebugTracingOptions {
        config: GethDefaultTracingOptions {
            disable_stack: Some(!stack),
            // needed for CREATE2
            disable_memory: Some(!memory),
            disable_storage: Some(!storage),
            ..GethDefaultTracingOptions::default()
        },
        tracer: None,
        ..GethDebugTracingOptions::default()
    }
}

// Gets the lightest possible structlog for transcation `tx_hash`.
pub async fn get_structlog_for_debug<ProviderT, TransportT>(
    provider: &ProviderT,
    tx_hash: &B256,
) -> Result<Option<Vec<ZeroStructLog>>, RpcError<TransportErrorKind>>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let light_structlog_trace = provider
        .debug_trace_transaction(*tx_hash, structlog_tracing_options(true, false, false))
        .await?;

    let structlogs: Option<Vec<ZeroStructLog>> = normalize_structlog(light_structlog_trace);

    Ok(structlogs)
}

pub mod zerostructlog {
    use std::collections::BTreeMap;

    use alloy::rpc::types::trace::geth::{DefaultFrame, GethTrace, StructLog};
    use alloy_primitives::{Bytes, B256, U256};
    use serde::{Deserialize, Serialize};
    use serde_json::Value;

    /// Geth Default struct log trace frame
    ///
    /// <https://github.com/ethereum/go-ethereum/blob/a9ef135e2dd53682d106c6a2aede9187026cc1de/eth/tracers/logger/logger.go#L406-L411>
    #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct ZeroDefaultFrame {
        /// Whether the transaction failed
        pub failed: bool,
        /// How much gas was used.
        pub gas: u64,
        /// Output of the transaction
        #[serde(serialize_with = "alloy_serde::serialize_hex_string_no_prefix")]
        pub return_value: Bytes,
        /// Recorded traces of the transaction
        pub struct_logs: Vec<ZeroStructLog>,
    }

    /// Represents a struct log entry in a trace
    ///
    /// <https://github.com/ethereum/go-ethereum/blob/366d2169fbc0e0f803b68c042b77b6b480836dbc/eth/tracers/logger/logger.go#L413-L426>
    #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct ZeroStructLog {
        /// program counter
        pub pc: u64,
        /// opcode to be executed
        pub op: String,
        /// remaining gas
        pub gas: u64,
        /// cost for executing op
        #[serde(rename = "gasCost")]
        pub gas_cost: u64,
        /// Current call depth
        pub depth: u64,
        /// Error message if any
        #[serde(default)]
        pub error: Option<String>,
        /// EVM stack
        #[serde(default)]
        pub stack: Option<Vec<U256>>,
        /// Last call's return data. Enabled via enableReturnData
        #[serde(default, rename = "returnData")]
        pub return_data: Option<Bytes>,
        /// ref <https://github.com/ethereum/go-ethereum/blob/366d2169fbc0e0f803b68c042b77b6b480836dbc/eth/tracers/logger/logger.go#L450-L452>
        #[serde(default)]
        pub memory: Option<Vec<String>>,
        /// Size of memory.
        #[serde(default, rename = "memSize")]
        pub memory_size: Option<u64>,
        /// Storage slots of current contract read from and written to. Only
        /// emitted for SLOAD and SSTORE. Disabled via disableStorage
        #[serde(default)]
        pub storage: Option<BTreeMap<B256, B256>>,
        /// Refund counter
        #[serde(default, rename = "refund")]
        pub refund_counter: Option<u64>,
    }

    impl From<StructLog> for ZeroStructLog {
        fn from(struct_log: StructLog) -> Self {
            ZeroStructLog {
                pc: struct_log.pc,
                op: struct_log.op,
                gas: struct_log.gas,
                gas_cost: struct_log.gas_cost,
                depth: struct_log.depth,
                error: struct_log.error,
                stack: struct_log.stack,
                return_data: struct_log.return_data,
                memory: struct_log.memory,
                memory_size: struct_log.memory_size,
                storage: struct_log.storage,
                refund_counter: struct_log.refund_counter,
            }
        }
    }

    pub fn try_reserialize(structlog_object: &Value) -> anyhow::Result<DefaultFrame> {
        let mut a = serde_json::to_string(structlog_object)?;
        a = a.replace("\"error\":{},", "");

        let b = serde_json::from_str::<DefaultFrame>(&a)?;
        let d: DefaultFrame = b.try_into()?;
        Ok(d)
    }

    pub(crate) fn normalize_structlog(
        unnormalized_structlog: GethTrace,
    ) -> Option<Vec<ZeroStructLog>> {
        match unnormalized_structlog {
            GethTrace::Default(structlog_frame) => {
                let all_struct_logs = structlog_frame
                    .struct_logs
                    .into_iter()
                    .map(|log| ZeroStructLog::from(log))
                    .collect::<Vec<ZeroStructLog>>();
                Some(all_struct_logs)
            }
            GethTrace::JS(structlog_js_object) => {
                try_reserialize(&structlog_js_object).ok().map(|s| {
                    s.struct_logs
                        .into_iter()
                        .map(|log| ZeroStructLog::from(log))
                        .collect::<Vec<ZeroStructLog>>()
                })
            }
            _ => None,
        }
    }
}
