use alloy::primitives::B256;
use alloy::providers::ext::DebugApi;
use alloy::providers::Provider;
use alloy::rpc::types::trace::geth::{
    GethDebugTracingOptions, GethDefaultTracingOptions, GethTrace, StructLog,
};
use alloy::transports::RpcError;
use alloy::transports::Transport;
use alloy::transports::TransportErrorKind;

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

// Gets the struct logs with the necessary logs for debugging.
pub async fn get_structlog_for_debug<ProviderT, TransportT>(
    provider: &ProviderT,
    tx_hash: &B256,
) -> Result<Option<Vec<StructLog>>, RpcError<TransportErrorKind>>
where
    ProviderT: Provider<TransportT>,
    TransportT: Transport + Clone,
{
    let structlog_trace = provider
        .debug_trace_transaction(*tx_hash, structlog_tracing_options(true, false, false))
        .await?;

    let res = trace2structlog(structlog_trace);
    println!("retrieved struct logs {:?}", res);
    let structlogs: Option<Vec<StructLog>> = res.unwrap_or_default();

    Ok(structlogs)
}

// pub(crate) fn normalize_structlog(unnormalized_structlog: GethTrace) ->
// Option<Vec<StructLog>> {     match unnormalized_structlog {
//         GethTrace::Default(structlog_frame) => {
//             let all_struct_logs = structlog_frame
//                 .struct_logs
//                 .into_iter()
//                 .collect::<Vec<ZeroStructLog>>();
//             Some(all_struct_logs)
//         }
//         GethTrace::JS(structlog_js_object) =>
// try_reserialize(&structlog_js_object).ok().map(|s| {
// s.struct_logs                 .into_iter()
//                 .map(ZeroStructLog::from)
//                 .collect::<Vec<ZeroStructLog>>()
//         }),
//         _ => None,
//     }
// }

fn trace2structlog(trace: GethTrace) -> Result<Option<Vec<StructLog>>, serde_json::Error> {
    match trace {
        GethTrace::Default(it) => Ok(Some(it.struct_logs)),
        GethTrace::JS(it) => Ok(Some(compat::deserialize(it)?.struct_logs)),
        _ => Ok(None),
    }
}

mod compat {
    use std::{collections::BTreeMap, fmt, iter};

    use alloy::rpc::types::trace::geth::{DefaultFrame, StructLog};
    use alloy_primitives::{Bytes, B256, U256};
    use serde::{de::SeqAccess, Deserialize, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DefaultFrame, D::Error> {
        _DefaultFrame::deserialize(d)
    }

    /// The `error` field is a `string` in `geth` etc. but an `object` in
    /// `erigon`.
    fn error<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Error {
            String(String),
            #[allow(dead_code)]
            Object(serde_json::Map<String, serde_json::Value>),
        }
        Ok(match Error::deserialize(d)? {
            Error::String(it) => Some(it),
            Error::Object(_) => Some("".to_string()),
        })
    }

    #[derive(Deserialize)]
    #[serde(remote = "DefaultFrame", rename_all = "camelCase")]
    struct _DefaultFrame {
        failed: bool,
        gas: u64,
        return_value: Bytes,
        #[serde(deserialize_with = "vec_structlog")]
        struct_logs: Vec<StructLog>,
    }

    fn vec_structlog<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<StructLog>, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Vec<StructLog>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an array of `StructLog`")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                #[derive(Deserialize)]
                struct With(#[serde(with = "_StructLog")] StructLog);
                let v = iter::from_fn(|| seq.next_element().transpose())
                    .map(|it| it.map(|With(it)| it))
                    .collect::<Result<_, _>>()?;
                Ok(v)
            }
        }

        d.deserialize_seq(Visitor)
    }

    #[derive(Deserialize)]
    #[serde(remote = "StructLog", rename_all = "camelCase")]
    struct _StructLog {
        pc: u64,
        op: String,
        gas: u64,
        gas_cost: u64,
        depth: u64,
        #[serde(deserialize_with = "error")]
        error: Option<String>,
        stack: Option<Vec<U256>>,
        return_data: Option<Bytes>,
        memory: Option<Vec<String>>,
        #[serde(rename = "memSize")]
        memory_size: Option<u64>,
        storage: Option<BTreeMap<B256, B256>>,
        #[serde(rename = "refund")]
        refund_counter: Option<u64>,
    }
}
