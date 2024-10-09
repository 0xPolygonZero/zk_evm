use tracing_subscriber::{prelude::*, util::SubscriberInitExt, EnvFilter};

pub fn init() {
    tracing_subscriber::Registry::default()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_filter(EnvFilter::from_default_env()),
        )
        .init();
}
