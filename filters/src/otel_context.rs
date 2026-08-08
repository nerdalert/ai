// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Request-lifecycle `OTel` context filter.
//!
//! When placed first in a filter chain, this filter creates a SERVER
//! span in [`on_request`] that persists until [`on_response`] completes,
//! giving accurate request-lifecycle duration. It also extracts inbound
//! W3C `traceparent`/`tracestate` headers and injects outbound context
//! into upstream requests.
//!
//! When the `otel` feature is disabled, the filter is a no-op
//! passthrough — safe to include in any config without compilation
//! errors.
//!
//! [`on_request`]: OtelContextFilter::on_request
//! [`on_response`]: OtelContextFilter::on_response

#[cfg(feature = "otel")]
use std::collections::HashMap;

use async_trait::async_trait;
#[cfg(feature = "otel")]
use http::{HeaderName, HeaderValue};
#[cfg(feature = "otel")]
use opentelemetry::propagation::{Extractor, Injector};
use praxis_filter::{FilterAction, FilterError, HttpFilter, HttpFilterContext, parse_filter_config};
#[cfg(feature = "otel")]
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

// -----------------------------------------------------------------------------
// OTel adapters (feature-gated)
// -----------------------------------------------------------------------------

/// Wrapper storing the lifecycle span in request extensions.
#[cfg(feature = "otel")]
struct OtelLifecycleSpan(tracing::Span);

/// Extracts W3C trace context from HTTP headers.
#[cfg(feature = "otel")]
struct HeaderExtractor<'a> {
    /// The HTTP headers to extract from.
    headers: &'a http::HeaderMap,
}

#[cfg(feature = "otel")]
impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.headers.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.headers.keys().map(HeaderName::as_str).collect()
    }
}

/// Injects W3C trace context into a string map.
#[cfg(feature = "otel")]
struct MapInjector<'a> {
    /// Target map for injected key-value pairs.
    map: &'a mut HashMap<String, String>,
}

#[cfg(feature = "otel")]
impl Injector for MapInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        self.map.insert(key.to_owned(), value);
    }
}

// -----------------------------------------------------------------------------
// Filter config and construction
// -----------------------------------------------------------------------------

/// Configuration for the `OTel` context filter.
#[derive(serde::Deserialize)]
struct OtelContextConfig {
    /// Whether to inject traceparent into upstream requests.
    #[serde(default)]
    #[cfg_attr(not(feature = "otel"), allow(dead_code))]
    inject_upstream: bool,
}

/// Request-lifecycle `OTel` context filter.
///
/// Creates a SERVER span covering the full request/response cycle and
/// optionally injects W3C trace context into upstream requests.
/// No-op passthrough when the `otel` feature is disabled.
pub struct OtelContextFilter {
    /// Whether to inject `traceparent` into upstream requests.
    #[cfg_attr(not(feature = "otel"), allow(dead_code))]
    inject_upstream: bool,
}

impl OtelContextFilter {
    /// Build from YAML configuration.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the YAML value is not a valid configuration.
    pub fn from_config(value: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let config: OtelContextConfig = parse_filter_config("otel_context", value)?;
        Ok(Box::new(Self {
            inject_upstream: config.inject_upstream,
        }))
    }
}

// -----------------------------------------------------------------------------
// HttpFilter implementation
// -----------------------------------------------------------------------------

/// Inject W3C trace context headers from the current span context.
#[cfg(feature = "otel")]
fn inject_context_headers(span: &tracing::Span, headers_to_set: &mut Vec<(HeaderName, HeaderValue)>) {
    let _guard = span.enter();
    let cx = tracing::Span::current().context();
    let mut map = HashMap::new();
    opentelemetry::global::get_text_map_propagator(|p| {
        p.inject_context(&cx, &mut MapInjector { map: &mut map });
    });
    for (k, v) in &map {
        if let (Ok(name), Ok(value)) = (k.parse::<HeaderName>(), v.parse::<HeaderValue>()) {
            headers_to_set.push((name, value));
        }
    }
}

#[async_trait]
impl HttpFilter for OtelContextFilter {
    fn name(&self) -> &'static str {
        "otel_context"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        #[cfg(feature = "otel")]
        {
            let span = tracing::info_span!(
                "http.request",
                "http.request.method" = %ctx.request.method,
                "http.route" = %ctx.request.uri.path(),
                "otel.kind" = "SERVER",
                "http.response.status_code" = tracing::field::Empty,
            );

            let extractor = HeaderExtractor {
                headers: &ctx.request.headers,
            };
            let parent_cx = opentelemetry::global::get_text_map_propagator(|p| p.extract(&extractor));
            span.set_parent(parent_cx);

            if self.inject_upstream {
                inject_context_headers(&span, &mut ctx.request_headers_to_set);
            }
            ctx.extensions.insert(OtelLifecycleSpan(span));
        }
        let _ = ctx;
        Ok(FilterAction::Continue)
    }

    async fn on_response(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        #[cfg(feature = "otel")]
        {
            if let Some(lifecycle) = ctx.extensions.remove::<OtelLifecycleSpan>() {
                if let Some(response) = &ctx.response_header {
                    lifecycle
                        .0
                        .record("http.response.status_code", response.status.as_u16());
                }
                drop(lifecycle);
            }
        }
        let _ = ctx;
        Ok(FilterAction::Continue)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[cfg(feature = "otel")]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use http::Method;

    use super::*;
    use crate::test_utils::{make_filter_context, make_request, make_response};

    fn make_filter(inject: bool) -> OtelContextFilter {
        OtelContextFilter {
            inject_upstream: inject,
        }
    }

    #[tokio::test]
    async fn creates_span_in_extensions() {
        let req = make_request(Method::POST, "/v1/chat/completions");
        let mut ctx = make_filter_context(&req);
        let filter = make_filter(false);
        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
        assert!(ctx.extensions.get::<OtelLifecycleSpan>().is_some());
    }

    #[tokio::test]
    async fn on_response_removes_span() {
        let req = make_request(Method::POST, "/v1/chat/completions");
        let mut ctx = make_filter_context(&req);
        let filter = make_filter(false);
        let _action = filter.on_request(&mut ctx).await.unwrap();
        assert!(ctx.extensions.get::<OtelLifecycleSpan>().is_some());

        let mut resp = make_response();
        ctx.response_header = Some(&mut resp);
        let _action = filter.on_response(&mut ctx).await.unwrap();
        assert!(ctx.extensions.get::<OtelLifecycleSpan>().is_none());
    }

    #[tokio::test]
    async fn inject_upstream_completes_without_error() {
        let req = make_request(Method::POST, "/v1/chat/completions");
        let mut ctx = make_filter_context(&req);
        let filter = make_filter(true);
        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
        assert!(ctx.extensions.get::<OtelLifecycleSpan>().is_some());
    }

    #[tokio::test]
    async fn no_inject_when_disabled() {
        let req = make_request(Method::POST, "/v1/chat/completions");
        let mut ctx = make_filter_context(&req);
        let filter = make_filter(false);
        let _action = filter.on_request(&mut ctx).await.unwrap();
        let has_traceparent = ctx
            .request_headers_to_set
            .iter()
            .any(|(name, _)| name.as_str() == "traceparent");
        assert!(!has_traceparent, "should not inject traceparent when disabled");
    }

    #[tokio::test]
    async fn extracts_inbound_traceparent() {
        let mut req = make_request(Method::POST, "/v1/chat/completions");
        req.headers.insert(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .unwrap(),
        );
        let mut ctx = make_filter_context(&req);
        let filter = make_filter(false);
        let _action = filter.on_request(&mut ctx).await.unwrap();
        assert!(ctx.extensions.get::<OtelLifecycleSpan>().is_some());
    }

    #[tokio::test]
    async fn handles_malformed_traceparent() {
        let mut req = make_request(Method::POST, "/v1/chat/completions");
        req.headers.insert("traceparent", "not-valid".parse().unwrap());
        let mut ctx = make_filter_context(&req);
        let filter = make_filter(false);
        let action = filter.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
    }

    #[tokio::test]
    async fn on_response_without_request_span() {
        let req = make_request(Method::GET, "/health");
        let mut ctx = make_filter_context(&req);
        let filter = make_filter(false);
        let mut resp = make_response();
        ctx.response_header = Some(&mut resp);
        let action = filter.on_response(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
    }

    #[tokio::test]
    async fn no_sensitive_headers_injected() {
        let req = make_request(Method::POST, "/v1/chat/completions");
        let mut ctx = make_filter_context(&req);
        let filter = make_filter(true);
        let _action = filter.on_request(&mut ctx).await.unwrap();
        for (name, _) in &ctx.request_headers_to_set {
            let n = name.as_str().to_lowercase();
            assert!(!n.contains("authorization"), "no auth headers");
            assert!(!n.contains("cookie"), "no cookie headers");
            assert!(!n.contains("api-key"), "no api-key headers");
        }
    }
}
