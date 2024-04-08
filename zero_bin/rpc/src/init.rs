use tracing_subscriber::{prelude::*, util::SubscriberInitExt, EnvFilter};
pub(crate) fn tracing() {
    tracing_subscriber::Registry::default()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .compact()
                .with_filter(EnvFilter::from_default_env()),
        )
        .init();
}
