use std::time::Duration;
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use alloy::transports::http::reqwest;
use alloy::{
    providers::{ProviderBuilder, RootProvider},
    rpc::{
        client::ClientBuilder,
        json_rpc::{RequestPacket, ResponsePacket},
    },
    transports::TransportError,
};
use tower::{retry::Policy, Layer, Service};

const HTTP_CLIENT_CONNECTION_POOL_IDLE_TIMEOUT: u64 = 90;
const HTTP_CLIENT_MAX_IDLE_CONNECTIONS_PER_HOST: usize = 64;

#[derive(Debug)]
pub struct RetryPolicy {
    backoff: tokio::time::Duration,
    retries: u32,
    max_retries: u32,
}

impl Clone for RetryPolicy {
    fn clone(&self) -> Self {
        Self {
            backoff: self.backoff,
            retries: self.retries,
            max_retries: self.max_retries,
        }
    }
}

impl RetryPolicy {
    pub const fn new(backoff: tokio::time::Duration, max_retries: u32) -> Self {
        Self {
            backoff,
            retries: 0,
            max_retries,
        }
    }

    pub fn backoff(&self) -> tokio::time::Sleep {
        tokio::time::sleep(self.backoff)
    }
}

impl Policy<RequestPacket, ResponsePacket, TransportError> for RetryPolicy {
    type Future = Pin<Box<dyn Future<Output = Self> + Send + 'static>>;

    fn retry(
        &self,
        _req: &RequestPacket,
        result: Result<&ResponsePacket, &TransportError>,
    ) -> Option<Self::Future> {
        // TODO: Use rate-limit specific errors/codes and retry accordingly.
        if result.is_err() && self.retries < self.max_retries {
            let mut policy = self.clone();
            Some(Box::pin(async move {
                policy.backoff().await;
                policy.retries += 1;
                policy
            }))
        } else {
            None
        }
    }

    fn clone_request(&self, req: &RequestPacket) -> Option<RequestPacket> {
        Some(req.clone())
    }
}

/// RetryLayer
pub struct RetryLayer {
    policy: RetryPolicy,
}

impl RetryLayer {
    pub const fn new(policy: RetryPolicy) -> Self {
        Self { policy }
    }
}

impl<S> Layer<S> for RetryLayer {
    type Service = RetryService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RetryService {
            inner,
            policy: self.policy.clone(),
        }
    }
}

/// RetryService
#[derive(Debug, Clone)]
pub struct RetryService<S> {
    inner: S,
    policy: RetryPolicy,
}

impl<S> Service<RequestPacket> for RetryService<S>
where
    S: Service<RequestPacket, Response = ResponsePacket, Error = TransportError>
        + Send
        + 'static
        + Clone,
    S::Future: Send + 'static,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        let inner = self.inner.clone();
        let mut policy = self.policy.clone();

        let mut inner = std::mem::replace(&mut self.inner, inner);
        Box::pin(async move {
            let mut res = inner.call(req.clone()).await;

            while let Some(new_policy) = policy.retry(&req, res.as_ref()) {
                policy = new_policy.await;
                res = inner.call(req.clone()).await;
            }

            res
        })
    }
}

pub fn build_http_retry_provider(
    rpc_url: url::Url,
    backoff: u64,
    max_retries: u32,
) -> Result<RootProvider<RetryService<alloy::transports::http::ReqwestTransport>>, anyhow::Error> {
    let retry_policy = RetryLayer::new(RetryPolicy::new(
        Duration::from_millis(backoff),
        max_retries,
    ));
    let reqwest_client = reqwest::ClientBuilder::new()
        .pool_max_idle_per_host(HTTP_CLIENT_MAX_IDLE_CONNECTIONS_PER_HOST)
        .pool_idle_timeout(Duration::from_secs(
            HTTP_CLIENT_CONNECTION_POOL_IDLE_TIMEOUT,
        ))
        .build()?;

    let http = alloy::transports::http::Http::with_client(reqwest_client, rpc_url);
    let is_local = http.guess_local();
    let client = ClientBuilder::default()
        .layer(retry_policy)
        .transport(http, is_local);
    Ok(ProviderBuilder::new().on_client(client))
}
