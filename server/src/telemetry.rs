// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! OpenTelemetry-enhanced tracing initialization.
//!
//! When the `otel` feature is enabled, this module replaces the
//! standard [`praxis_core::logging::init_tracing`] with a version
//! that adds an [`OpenTelemetryLayer`] to the tracing subscriber.
//! Spans are exported via OTLP HTTP to the configured collector.
//!
//! Configuration is via standard OpenTelemetry environment variables:
//!
//! - `OTEL_EXPORTER_OTLP_ENDPOINT` — collector endpoint (default `http://localhost:4318`)
//! - `OTEL_SERVICE_NAME` — service name (default `praxis-ai`)
//!
//! [`OpenTelemetryLayer`]: tracing_opentelemetry::OpenTelemetryLayer

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig as _;
use opentelemetry_sdk::trace::SdkTracerProvider;
use praxis_core::{config::Config, errors::ProxyError};
use tracing_subscriber::{layer::SubscriberExt as _, util::SubscriberInitExt as _};

/// Global provider handle kept alive for the server lifetime.
static PROVIDER: std::sync::OnceLock<SdkTracerProvider> = std::sync::OnceLock::new();

/// Initialize tracing with OpenTelemetry export.
///
/// Sets up the W3C `TraceContext` propagator, an OTLP HTTP span
/// exporter, and a tracing subscriber with both `fmt` and
/// OpenTelemetry layers.
///
/// # Errors
///
/// Returns [`ProxyError::Config`] if log overrides are invalid
/// or the OTLP exporter cannot be initialized.
///
/// [`ProxyError::Config`]: praxis_core::errors::ProxyError::Config
pub(crate) fn init_tracing(config: &Config) -> Result<(), ProxyError> {
    init_propagator();
    let env_filter = build_env_filter(config)?;
    let provider = build_provider()?;
    let tracer = provider.tracer("praxis-ai");
    drop(PROVIDER.set(provider));

    if is_json_format() {
        install_json_subscriber(env_filter, tracer);
    } else {
        install_fmt_subscriber(env_filter, tracer);
    }

    Ok(())
}

/// Install the JSON-formatted subscriber with `OpenTelemetry` layer.
fn install_json_subscriber(env_filter: tracing_subscriber::EnvFilter, tracer: opentelemetry_sdk::trace::Tracer) {
    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().json())
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .init();
}

/// Install the human-readable subscriber with `OpenTelemetry` layer.
fn install_fmt_subscriber(env_filter: tracing_subscriber::EnvFilter, tracer: opentelemetry_sdk::trace::Tracer) {
    tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .init();
}

/// Set the global W3C `TraceContext` propagator.
fn init_propagator() {
    opentelemetry::global::set_text_map_propagator(opentelemetry_sdk::propagation::TraceContextPropagator::new());
}

/// Check if JSON log format is requested.
fn is_json_format() -> bool {
    std::env::var("PRAXIS_LOG_FORMAT").is_ok_and(|v| v.eq_ignore_ascii_case("json"))
}

/// Build the tracing `EnvFilter` from `RUST_LOG` and config overrides.
fn build_env_filter(config: &Config) -> Result<tracing_subscriber::EnvFilter, ProxyError> {
    praxis_core::logging::validate_log_overrides(config)?;
    let mut base = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    for (module, level) in &config.runtime.log_overrides {
        let directive = format!("{module}={level}");
        base = base.add_directive(
            directive
                .parse()
                .map_err(|e| ProxyError::Config(format!("invalid log override: {e}")))?,
        );
    }
    Ok(base)
}

/// Build the OTLP tracer provider.
fn build_provider() -> Result<SdkTracerProvider, ProxyError> {
    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").unwrap_or_else(|_| "http://localhost:4318".to_owned());
    let service_name = std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "praxis-ai".to_owned());

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(format!("{endpoint}/v1/traces"))
        .build()
        .map_err(|e| ProxyError::Config(format!("OTLP exporter: {e}")))?;

    let resource = opentelemetry_sdk::Resource::builder()
        .with_service_name(service_name)
        .build();

    Ok(SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build())
}
