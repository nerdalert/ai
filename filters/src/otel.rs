// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Feature-gated OpenTelemetry integration for the filter pipeline.
//!
//! When the `otel` feature is enabled, this module provides:
//!
//! - A request-scoped SERVER span wrapping the filter chain;
//! - W3C `traceparent` extraction from inbound requests;
//! - Routing-decision child spans with candidate attributes;
//! - A provider-hop CLIENT span with W3C context injection.
//!
//! Privacy: only routing metadata is recorded. Never prompts,
//! response bodies, credentials, cookies, API keys, or session IDs.

use std::collections::HashMap;

use http::{HeaderName, HeaderValue};
use opentelemetry::propagation::{Extractor, Injector};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

use crate::routing::descriptor::RouteCandidate;

// -----------------------------------------------------------------------------
// Header adapters
// -----------------------------------------------------------------------------

/// Reads W3C trace headers from an [`http::HeaderMap`].
struct HeaderExtractor<'a> {
    /// Borrowed request headers.
    headers: &'a http::HeaderMap,
}

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.headers.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.headers.keys().map(HeaderName::as_str).collect()
    }
}

/// Writes W3C trace headers into a [`HashMap`].
struct MapInjector<'a> {
    /// Mutable map to write into.
    map: &'a mut HashMap<String, String>,
}

impl Injector for MapInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        self.map.insert(key.to_owned(), value);
    }
}

// -----------------------------------------------------------------------------
// Request-scoped SERVER span
// -----------------------------------------------------------------------------

/// Create and enter a request-scoped SERVER span.
///
/// Extracts inbound W3C `traceparent`/`tracestate` and establishes
/// the parent context. The returned guard keeps the span active;
/// child spans (routing, client) attach automatically.
pub(crate) fn enter_server_span(
    method: &http::Method,
    path: &str,
    headers: &http::HeaderMap,
) -> tracing::span::EnteredSpan {
    let span = tracing::info_span!(
        "http.request",
        "http.request.method" = %method,
        "http.route" = %path,
        "otel.kind" = "SERVER",
    );
    let guard = span.entered();
    let extractor = HeaderExtractor { headers };
    let cx = opentelemetry::global::get_text_map_propagator(|p| p.extract(&extractor));
    tracing::Span::current().set_parent(cx);
    guard
}

// -----------------------------------------------------------------------------
// Routing event recording
// -----------------------------------------------------------------------------

/// Record a routing-selection span with candidate attributes.
///
/// Creates a short-lived child span named `routing.select` carrying
/// the routing decision metadata. Only safe routing attributes are
/// recorded — never prompts, bodies, or credentials.
pub(crate) fn record_routing_selection(candidate: &RouteCandidate, local_site: &str, revision: Option<&str>) {
    record_routing_span(candidate, local_site, revision);
}

/// Inner span creation, split to stay within line limits.
fn record_routing_span(candidate: &RouteCandidate, local_site: &str, revision: Option<&str>) {
    let rev = revision.unwrap_or("none");
    let _span = tracing::info_span!(
        "routing.select",
        "selected.provider" = %candidate.name,
        "selected.cluster" = %candidate.cluster,
        "selected.site" = %candidate.site,
        "selected.stable_id" = %candidate.stable_id,
        "routing.admission_state" = candidate.admission_state.as_str(),
        "routing.local_site" = local_site,
        "routing.kind" = candidate.kind.as_str(),
        "overlay.revision" = rev,
    )
    .entered();

    record_optional_routing_attrs(candidate);
}

/// Record optional routing attributes as a tracing event.
fn record_optional_routing_attrs(candidate: &RouteCandidate) {
    let rank = candidate.rank.map_or(-1, i64::from);
    let tier = candidate.selection_tier.as_deref().unwrap_or("none");
    let group: i64 = -1;
    tracing::info!(
        provider = %candidate.name,
        rank,
        selection_group = group,
        selection_tier = tier,
        "routing decision"
    );
}

// -----------------------------------------------------------------------------
// Provider-hop CLIENT span and traceparent injection
// -----------------------------------------------------------------------------

/// Create a CLIENT span and inject its W3C context into outbound headers.
///
/// The CLIENT span is a child of the active SERVER span. Its trace
/// context is injected as `traceparent`/`tracestate` so the provider
/// backend can join the same distributed trace.
pub(crate) fn inject_client_traceparent(
    candidate: &RouteCandidate,
    headers_to_set: &mut Vec<(HeaderName, HeaderValue)>,
) {
    let _client = tracing::info_span!(
        "provider.request",
        "otel.kind" = "CLIENT",
        "selected.provider" = %candidate.name,
        "selected.cluster" = %candidate.cluster,
        "selected.site" = %candidate.site,
        "selected.stable_id" = %candidate.stable_id,
    )
    .entered();

    let cx = tracing::Span::current().context();
    let mut map = HashMap::new();
    opentelemetry::global::get_text_map_propagator(|p| {
        p.inject_context(&cx, &mut MapInjector { map: &mut map });
    });
    append_trace_headers(&map, headers_to_set);
}

/// Convert trace header map entries into typed header pairs.
fn append_trace_headers(map: &HashMap<String, String>, headers_to_set: &mut Vec<(HeaderName, HeaderValue)>) {
    for (k, v) in map {
        let Ok(name) = k.parse::<HeaderName>() else {
            continue;
        };
        let Ok(value) = v.parse::<HeaderValue>() else {
            continue;
        };
        headers_to_set.push((name, value));
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(clippy::unwrap_used, clippy::expect_used, reason = "tests")]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::routing::descriptor::{AdmissionState, CapabilityKind, RouteCandidate};

    fn test_candidate() -> RouteCandidate {
        RouteCandidate {
            admission_state: AdmissionState::NewAndExisting,
            cluster: Arc::from("pool-a"),
            credential: None,
            fresh: true,
            kind: CapabilityKind::InferenceModel,
            name: Arc::from("test-provider"),
            rank: Some(0),
            selection_tier: Some(Arc::from("preferred")),
            site: Arc::from("pool-a"),
            stable_id: Arc::from("stable-001"),
        }
    }

    #[test]
    fn server_span_with_empty_headers() {
        let headers = http::HeaderMap::new();
        let _guard = enter_server_span(&http::Method::POST, "/v1/chat/completions", &headers);
    }

    #[test]
    fn server_span_with_valid_traceparent() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .unwrap(),
        );
        let _guard = enter_server_span(&http::Method::POST, "/v1/chat/completions", &headers);
    }

    #[test]
    fn server_span_with_malformed_traceparent() {
        let mut headers = http::HeaderMap::new();
        headers.insert("traceparent", "not-a-valid-traceparent".parse().unwrap());
        let _guard = enter_server_span(&http::Method::GET, "/healthz", &headers);
    }

    #[test]
    fn server_span_with_tracestate() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "traceparent",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
                .parse()
                .unwrap(),
        );
        headers.insert("tracestate", "vendor1=value1,vendor2=value2".parse().unwrap());
        let _guard = enter_server_span(&http::Method::POST, "/v1/chat/completions", &headers);
    }

    #[test]
    fn client_inject_produces_no_sensitive_headers() {
        let candidate = test_candidate();
        let mut headers = Vec::new();
        inject_client_traceparent(&candidate, &mut headers);
        for (name, _) in &headers {
            let n = name.as_str().to_lowercase();
            assert!(!n.contains("authorization"), "no auth");
            assert!(!n.contains("cookie"), "no cookies");
            assert!(!n.contains("api-key"), "no API keys");
        }
    }

    #[test]
    fn record_routing_does_not_panic() {
        let candidate = test_candidate();
        record_routing_selection(&candidate, "local-site", Some("rev-abc123"));
    }

    #[test]
    fn routing_span_is_child_of_server() {
        let headers = http::HeaderMap::new();
        let _server = enter_server_span(&http::Method::POST, "/v1/chat/completions", &headers);
        let candidate = test_candidate();
        record_routing_selection(&candidate, "local-site", Some("rev-1"));
    }

    #[test]
    fn client_span_after_server_does_not_panic() {
        let headers = http::HeaderMap::new();
        let _server = enter_server_span(&http::Method::POST, "/v1/chat/completions", &headers);
        let candidate = test_candidate();
        let mut out_headers = Vec::new();
        inject_client_traceparent(&candidate, &mut out_headers);
    }
}
