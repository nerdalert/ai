// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Grid route filter: selects an upstream cluster for the request
//! based on the inference model name or MCP tool name.
//!
//! **Lookup precedence:** if `mcp.method` filter metadata exists, the
//! filter attempts MCP tool routing first.  `tools/call` with a valid
//! `mcp.name` matches `mcp_tool` candidates.  Any other MCP method
//! returns `Continue` without routing.  When no `mcp.method` metadata
//! is present, the filter reads the configured model header and matches
//! `inference_model` candidates.
//!
//! MCP metadata takes precedence over the model header to prevent a
//! client-supplied model name from hijacking MCP routing.
//!
//! Candidate selection is deterministic and lexicographic:
//! 1. **Freshness class** — fresh (0) beats stale (-100).
//! 2. **Locality** — local site (+10) beats remote within the same freshness class.
//! 3. **Config order** — first configured candidate wins on equal scores.
//!
//! This is the `grid_route` filter's own scoring; it is not a
//! recomputation of Grid's ranking.  Grid-rendered order is used
//! only as the tie-break within equal scores.
//!
//! No request-time metrics or control-plane lookups are performed.

use std::{path::PathBuf, sync::Arc};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use praxis_filter::{FilterAction, FilterError, HttpFilter, HttpFilterContext, Rejection, parse_filter_config};
use serde::Deserialize;

use super::{
    descriptor::{self, CandidateConfig, CapabilityKind, RouteCandidate},
    overlay::{self, OverlayReloadHandle, RouteSnapshot},
};

/// Maximum length for header values read from the request.
const MAX_HEADER_VALUE_LEN: usize = 256;

/// Score penalty for stale candidates.
const STALE_PENALTY: i32 = 100;

/// Score bonus for candidates on the local site.
const LOCAL_PREFERENCE: i32 = 10;

// -----------------------------------------------------------------------------
// Config
// -----------------------------------------------------------------------------

/// Deserialized YAML config for the grid route filter.
///
/// Supports two modes:
///
/// **Static mode** — candidates and `local_site` are specified inline:
///
/// ```yaml
/// filter: grid_route
/// local_site: site-a
/// model_header: x-model
/// candidates:
///   - kind: inference_model
///     name: local-model
///     site: site-a
///     cluster: local-inference
/// ```
///
/// **Overlay mode** — candidates are loaded from a Grid overlay file:
///
/// ```yaml
/// filter: grid_route
/// overlay_file: /etc/grid/grid-config.json
/// model_header: x-model
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GridRouteConfig {
    /// Static list of route candidates (mutually exclusive with `overlay_file`).
    candidates: Option<Vec<CandidateConfig>>,

    /// Name of the local site (required in static mode, provided by overlay
    /// in overlay mode).
    local_site: Option<String>,

    /// Header name that carries the model name (default: `X-Model`).
    #[serde(default = "default_model_header")]
    model_header: String,

    /// Path to a Grid overlay JSON file (`grid-config.json`).
    ///
    /// When set, candidates and `local_site` are read from the overlay
    /// instead of the YAML config.
    overlay_file: Option<PathBuf>,

    /// Hot reload configuration for overlay mode.
    ///
    /// Only valid when `overlay_file` is set.  Providing a `reload:`
    /// block with static `candidates` is rejected — static candidates
    /// are immutable for the lifetime of the filter.
    reload: Option<ReloadConfig>,
}

/// Hot reload settings for overlay file watching.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReloadConfig {
    /// Whether file watching is enabled (default: `true`).
    #[serde(default = "default_reload_enabled")]
    enabled: bool,

    /// Debounce window in milliseconds (default: 500).
    #[serde(default = "default_debounce_ms")]
    debounce_ms: u64,
}

impl Default for ReloadConfig {
    fn default() -> Self {
        Self {
            enabled: default_reload_enabled(),
            debounce_ms: default_debounce_ms(),
        }
    }
}

/// Default model header name.
fn default_model_header() -> String {
    "X-Model".to_owned()
}

/// Default reload enabled state.
fn default_reload_enabled() -> bool {
    true
}

/// Default debounce window in milliseconds.
fn default_debounce_ms() -> u64 {
    overlay::DEFAULT_DEBOUNCE_MS
}

// -----------------------------------------------------------------------------
// GridRouteFilter
// -----------------------------------------------------------------------------

/// Selects an upstream cluster from a site/capability descriptor
/// by matching either an inference model name or MCP tool name.
///
/// This filter is registered by the AI proxy (not Praxis core) because it
/// encodes AI/Grid-specific routing semantics: candidate freshness preference,
/// local-site scoring, and MCP tool-call routing.  Praxis core provides the
/// generic filter runtime; this filter adds the Grid candidate model on top.
///
/// **Modes:**
/// - **Static:** candidates are declared inline in the YAML config.
/// - **Overlay:** candidates are loaded from a Grid `grid-config.json` file and hot-reloaded via [`ArcSwap`] when the
///   file changes.
///
/// **Behavior:**
/// - If `ctx.cluster` is already set by an earlier filter, the selection is preserved and no metadata is written.
/// - If no routing source is present, the filter returns `Continue` without routing.
/// - If the model header or MCP tool name is blank, oversized, or invalid, the filter rejects with 400.
/// - If a matching candidate is found, `ctx.cluster` is set and bounded route-decision metadata is written.
/// - If no matching candidate is found, the filter rejects with 404.
///
/// **Scoring:** candidates are scored deterministically with
/// lexicographic priority: fresh (0) beats stale (-100); local
/// site (+10) beats remote within the same freshness class; first
/// configured candidate wins on equal scores.  This is the
/// `grid_route` filter's own scoring, not a recomputation of
/// Grid's ranking.
///
/// **Metadata:** on successful selection, bounded in-process filter
/// metadata is written under the `grid.route.` namespace (`kind`, `name`,
/// `site`, `cluster`, `local_site`).  No HTTP forwarding headers are
/// written.  No request-time database, control-plane, or metrics
/// lookups are performed.
///
/// **MCP lookup:** if `mcp.method` filter metadata is set to `tools/call`
/// and `mcp.name` is present, `mcp_tool` candidates are matched.
/// Other MCP methods (`initialize`, `notifications/*`, etc.) skip routing.
///
/// **Hot reload:** when `reload.enabled` is `true` (the default in overlay
/// mode), the filter watches the overlay file's parent directory for
/// filesystem events.  On change, the file is re-read, SHA-256 hashed
/// (skipped if identical), parsed, validated, and atomically swapped in
/// via `ArcSwap`.  In-flight requests continue using their previously
/// loaded snapshot.  Unreadable or invalid files retain the previous
/// snapshot.  Kubernetes `ConfigMap` projected volumes use atomic symlink
/// replacement (`..data`), which the watcher detects as a Create/Modify
/// event on the parent directory.  The overlay `ConfigMap` **must not**
/// use `subPath` volume mounts — `subPath` bypasses the `..data` symlink
/// mechanism and the watcher will not detect updates.
///
/// **Scope:** overlay hot reload swaps the candidate list and `local_site`
/// only.  It cannot add or remove `load_balancer` clusters, change
/// cluster endpoints or TLS configuration, or inject credential values.
/// Those changes require a full pipeline reload or pod restart.
/// Every cluster name that may appear in any overlay version must
/// already be configured in the downstream `load_balancer` filter.
/// An overlay that references an unknown cluster will cause
/// request-time failures, not a reload rejection.
///
/// [`ArcSwap`]: arc_swap::ArcSwap
pub struct GridRouteFilter {
    /// Atomic snapshot of routing state (candidates + `local_site`).
    snapshot: Arc<ArcSwap<RouteSnapshot>>,
    /// Header that carries the model name.
    model_header: http::header::HeaderName,
    /// Watcher handle for overlay hot reload (None in static mode).
    _reload_handle: Option<OverlayReloadHandle>,
}

impl GridRouteFilter {
    /// Create a grid route filter from parsed YAML config.
    ///
    /// In **overlay mode** (`overlay_file` set), reads the overlay file,
    /// builds an initial snapshot, and optionally spawns a background
    /// watcher for hot reload.
    ///
    /// In **static mode** (`candidates` set), validates the inline
    /// candidates and builds a static snapshot with no watcher.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if:
    /// - both `overlay_file` and `candidates` are set
    /// - neither `overlay_file` nor `candidates` is set
    /// - the overlay file cannot be read or parsed
    /// - the candidate list is empty or invalid
    /// - the model header is invalid
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: GridRouteConfig = parse_filter_config("grid_route", config)?;
        let model_header = descriptor::validate_model_header(&cfg.model_header)?;

        if cfg.overlay_file.is_some() && cfg.candidates.is_some() {
            return Err("grid: cannot set both overlay_file and candidates".into());
        }

        let (snapshot, reload_handle) = if let Some(path) = cfg.overlay_file {
            let reload = cfg.reload.unwrap_or_default();
            build_overlay_snapshot(path, &reload)?
        } else if let Some(candidates_raw) = cfg.candidates {
            if cfg.reload.is_some() {
                return Err("grid: reload block is not valid with static candidates".into());
            }
            build_static_snapshot(candidates_raw, cfg.local_site)?
        } else {
            return Err("grid: either overlay_file or candidates must be set".into());
        };

        Ok(Box::new(Self {
            snapshot,
            model_header,
            _reload_handle: reload_handle,
        }))
    }
}

/// Return type for snapshot builders: shared snapshot + optional watcher.
type SnapshotResult = Result<(Arc<ArcSwap<RouteSnapshot>>, Option<OverlayReloadHandle>), FilterError>;

/// Build an overlay-backed snapshot with optional watcher.
fn build_overlay_snapshot(path: PathBuf, reload: &ReloadConfig) -> SnapshotResult {
    let content = overlay::read_overlay_bounded(&path)
        .map_err(|e| FilterError::from(format!("grid: failed to read overlay file {}: {e}", path.display())))?;
    let snap = RouteSnapshot::from_overlay(&content)?;
    let shared = Arc::new(ArcSwap::from_pointee(snap));
    let handle = reload
        .enabled
        .then(|| overlay::spawn_overlay_watcher(path, Arc::clone(&shared), reload.debounce_ms));
    Ok((shared, handle))
}

/// Build a static snapshot from inline candidates.
fn build_static_snapshot(candidates_raw: Vec<CandidateConfig>, local_site: Option<String>) -> SnapshotResult {
    let local_site_str =
        local_site.ok_or_else(|| FilterError::from("grid: local_site is required when candidates is set"))?;
    descriptor::validate_local_site(&local_site_str)?;
    let candidates = descriptor::validate_candidates(candidates_raw)?;
    let snap = RouteSnapshot::from_static(candidates, Arc::from(local_site_str.as_str()));
    Ok((Arc::new(ArcSwap::from_pointee(snap)), None))
}

#[async_trait]
impl HttpFilter for GridRouteFilter {
    fn name(&self) -> &'static str {
        "grid_route"
    }

    /// `grid_route` selects `ctx.cluster` from configured candidates.
    ///
    /// Returning `true` here tells the Praxis pipeline validator that this
    /// filter satisfies the "cluster-selecting filter before `load_balancer`"
    /// requirement.  Without this, the validator would reject pipelines that
    /// use `grid_route → load_balancer` without an intervening `router`.
    fn selects_cluster(&self) -> bool {
        true
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        if ctx.cluster.is_some() {
            tracing::debug!("grid_route: cluster already set; preserving");
            return Ok(FilterAction::Continue);
        }

        let snap = self.snapshot.load();

        let lookup = extract_lookup(ctx, &self.model_header);

        let (kind, name) = match lookup {
            Lookup::Route { kind, name } => (kind, name),
            Lookup::Skip => return Ok(FilterAction::Continue),
            Lookup::Invalid => return Ok(FilterAction::Reject(Rejection::status(400))),
        };

        if let Some(c) = select_candidate(&snap.candidates, kind, &name, &snap.local_site) {
            tracing::debug!(
                kind = kind.as_str(),
                name = %name,
                site = &*c.site,
                cluster = &*c.cluster,
                fresh = c.fresh,
                score = score_candidate(c, &snap.local_site),
                "grid_route: selected"
            );
            ctx.cluster = Some(Arc::clone(&c.cluster));
            record_route_decision(ctx, &snap.local_site, c);
            Ok(FilterAction::Continue)
        } else {
            tracing::debug!(kind = kind.as_str(), name = %name, "grid_route: no candidate");
            Ok(FilterAction::Reject(Rejection::status(404)))
        }
    }
}

// -----------------------------------------------------------------------------
// Lookup Extraction
// -----------------------------------------------------------------------------

/// Result of extracting a routable capability from the request.
enum Lookup {
    /// A routable capability was found.
    Route {
        /// Capability kind.
        kind: CapabilityKind,
        /// Capability name.
        name: String,
    },
    /// No routable capability; continue without routing.
    Skip,
    /// Input is present but invalid; fail closed.
    Invalid,
}

/// Extract the routable capability from request context.
///
/// MCP metadata takes precedence over the model header: if `mcp.method`
/// metadata is present (set by an upstream MCP classifier filter), the
/// filter dispatches to MCP tool lookup.  Otherwise it falls back to the
/// configured model header.
fn extract_lookup(ctx: &HttpFilterContext<'_>, model_header: &http::header::HeaderName) -> Lookup {
    if let Some(mcp_method) = ctx.get_metadata("mcp.method") {
        return extract_mcp_lookup(ctx, mcp_method);
    }
    extract_model_lookup(ctx, model_header)
}

/// Extract an MCP tool lookup from filter metadata.
///
/// Only `tools/call` is routable.  Any other MCP method continues without
/// routing even if a model header is present — the request is an MCP
/// protocol message, not an inference request.
fn extract_mcp_lookup(ctx: &HttpFilterContext<'_>, method: &str) -> Lookup {
    if method != "tools/call" {
        tracing::debug!(method = method, "grid_route: non-tools/call MCP method; skipping");
        return Lookup::Skip;
    }
    let Some(name) = ctx.get_metadata("mcp.name") else {
        tracing::debug!("grid_route: tools/call without mcp.name; rejecting");
        return Lookup::Invalid;
    };
    if name.trim().is_empty() || name.len() > MAX_HEADER_VALUE_LEN {
        tracing::debug!("grid_route: mcp.name blank or oversized; rejecting");
        return Lookup::Invalid;
    }
    Lookup::Route {
        kind: CapabilityKind::McpTool,
        name: name.to_owned(),
    }
}

/// Extract an inference model lookup from the promoted model header.
fn extract_model_lookup(ctx: &HttpFilterContext<'_>, model_header: &http::header::HeaderName) -> Lookup {
    let Some(value) = ctx.request.headers.get(model_header) else {
        tracing::debug!("grid_route: no model header; skipping");
        return Lookup::Skip;
    };
    let Ok(model) = value.to_str() else {
        tracing::debug!("grid_route: model header is not valid UTF-8; rejecting");
        return Lookup::Invalid;
    };
    if model.trim().is_empty() || model.len() > MAX_HEADER_VALUE_LEN {
        tracing::debug!("grid_route: model header blank or oversized; rejecting");
        return Lookup::Invalid;
    }
    Lookup::Route {
        kind: CapabilityKind::InferenceModel,
        name: model.to_owned(),
    }
}

// -----------------------------------------------------------------------------
// Candidate Selection
// -----------------------------------------------------------------------------

/// Select the best candidate by deterministic lexicographic scoring.
///
/// Priority: fresh > stale; local > remote within the same freshness
/// class; first configured candidate wins on equal scores.
///
/// Returns `None` when no candidate of the given `kind` matches
/// `name`.
fn select_candidate<'a>(
    candidates: &'a [RouteCandidate],
    kind: CapabilityKind,
    name: &str,
    local_site: &str,
) -> Option<&'a RouteCandidate> {
    let mut best: Option<(i32, &RouteCandidate)> = None;
    for c in candidates {
        if c.kind != kind || &*c.name != name {
            continue;
        }
        let s = score_candidate(c, local_site);
        match best {
            Some((best_score, _)) if s <= best_score => {},
            _ => best = Some((s, c)),
        }
    }
    best.map(|(_, c)| c)
}

/// Deterministic score for a candidate. Higher is better.
fn score_candidate(candidate: &RouteCandidate, local_site: &str) -> i32 {
    let mut s: i32 = 0;
    if !candidate.fresh {
        s -= STALE_PENALTY;
    }
    if *candidate.site == *local_site {
        s += LOCAL_PREFERENCE;
    }
    s
}

// -----------------------------------------------------------------------------
// Route Decision Metadata
// -----------------------------------------------------------------------------

/// Write bounded route-decision metadata on successful selection.
///
/// Keys use `grid.route.` namespace. All values are bounded by the
/// existing `set_metadata` limits.  No HTTP forwarding headers are
/// written by this function.
fn record_route_decision(ctx: &mut HttpFilterContext<'_>, local_site: &Arc<str>, candidate: &RouteCandidate) {
    ctx.set_metadata("grid.route.kind", candidate.kind.as_str());
    ctx.set_metadata("grid.route.name", &*candidate.name);
    ctx.set_metadata("grid.route.site", &*candidate.site);
    ctx.set_metadata("grid.route.cluster", &*candidate.cluster);
    ctx.set_metadata("grid.route.local_site", &**local_site);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use http::Method;

    use super::*;

    // ---- Config validation ----

    #[test]
    fn valid_minimal_config() {
        let yaml = "local_site: site-a\ncandidates:\n  - kind: inference_model\n    name: llama\n    site: site-a\n    cluster: inf\n    fresh: true\n";
        assert!(parse(yaml).is_ok(), "minimal valid config should parse");
    }

    #[tokio::test]
    async fn default_model_header_is_x_model() {
        let f = make_filter(&[("inference_model", "llama", "site-a", "inf")]);
        let mut req = crate::test_utils::make_request(Method::POST, "/chat");
        req.headers.insert("X-Model", http::HeaderValue::from_static("llama"));
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "default model header X-Model should route"
        );
        assert_eq!(ctx.cluster.as_deref(), Some("inf"), "cluster should be set");
    }

    #[test]
    fn blank_local_site_rejected() {
        let err = parse_err(
            "local_site: \"\"\ncandidates:\n  - kind: inference_model\n    name: m\n    site: s\n    cluster: c\n    fresh: true\n",
        );
        assert!(
            err.to_string().contains("blank") || err.to_string().contains("non-blank"),
            "blank local_site should be rejected: {err}"
        );
    }

    #[test]
    fn missing_candidates_rejected() {
        let err = parse_err("local_site: site-a\ncandidates: []\n");
        assert!(
            err.to_string().contains("empty"),
            "empty candidates should be rejected: {err}"
        );
    }

    #[test]
    fn blank_model_header_rejected() {
        let err = parse_err(
            "local_site: site-a\nmodel_header: \"\"\ncandidates:\n  - kind: inference_model\n    name: m\n    site: s\n    cluster: c\n    fresh: true\n",
        );
        assert!(
            err.to_string().contains("blank") || err.to_string().contains("empty"),
            "blank model_header should be rejected: {err}"
        );
    }

    #[test]
    fn reserved_model_header_rejected() {
        let err = parse_err(
            "local_site: site-a\nmodel_header: x-praxis-foo\ncandidates:\n  - kind: inference_model\n    name: m\n    site: s\n    cluster: c\n    fresh: true\n",
        );
        assert!(
            err.to_string().contains("reserved"),
            "reserved model_header should be rejected: {err}"
        );
    }

    #[test]
    fn invalid_candidate_rejected() {
        let err = parse_err(
            "local_site: site-a\ncandidates:\n  - kind: inference_model\n    name: \"\"\n    site: s\n    cluster: c\n    fresh: true\n",
        );
        assert!(
            err.to_string().contains("blank") || err.to_string().contains("non-blank"),
            "blank candidate name should be rejected: {err}"
        );
    }

    // ---- Model header extraction ----

    #[tokio::test]
    async fn absent_model_header_continues() {
        let f = make_filter(&[("inference_model", "llama", "site-a", "inf")]);
        let req = crate::test_utils::make_request(Method::POST, "/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "absent model header should continue without routing"
        );
        assert!(ctx.cluster.is_none(), "no cluster should be set");
        assert_no_route_metadata(&ctx);
    }

    #[tokio::test]
    async fn blank_model_header_rejects() {
        let f = make_filter(&[("inference_model", "llama", "site-a", "inf")]);
        let mut req = crate::test_utils::make_request(Method::POST, "/chat");
        req.headers.insert("X-Model", http::HeaderValue::from_static(""));
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 400),
            "blank model header should reject 400"
        );
        assert_no_route_metadata(&ctx);
    }

    #[tokio::test]
    async fn oversized_model_header_rejects_no_metadata() {
        let f = make_filter(&[("inference_model", "llama", "site-a", "inf")]);
        let mut req = crate::test_utils::make_request(Method::POST, "/chat");
        let big = "a".repeat(MAX_HEADER_VALUE_LEN + 1);
        req.headers
            .insert("X-Model", http::HeaderValue::from_str(&big).unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 400),
            "oversized model header should reject 400"
        );
        assert_no_route_metadata(&ctx);
    }

    #[tokio::test]
    async fn invalid_utf8_model_header_rejects_no_metadata() {
        let f = make_filter(&[("inference_model", "llama", "site-a", "inf")]);
        let mut req = crate::test_utils::make_request(Method::POST, "/chat");
        req.headers
            .insert("X-Model", http::HeaderValue::from_bytes(b"\xff\xfe").unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 400),
            "non-UTF-8 model header should reject 400"
        );
        assert_no_route_metadata(&ctx);
    }

    // ---- Candidate selection ----

    #[tokio::test]
    async fn unknown_model_rejects_404() {
        let f = make_filter(&[("inference_model", "llama", "site-a", "inf")]);
        let mut req = crate::test_utils::make_request(Method::POST, "/chat");
        req.headers
            .insert("X-Model", http::HeaderValue::from_static("unknown-model"));
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 404),
            "unknown model should reject 404"
        );
        assert_no_route_metadata(&ctx);
    }

    #[tokio::test]
    async fn local_inference_sets_cluster() {
        let f = make_filter(&[("inference_model", "llama", "site-a", "local-inf")]);
        let mut req = crate::test_utils::make_request(Method::POST, "/chat");
        req.headers.insert("X-Model", http::HeaderValue::from_static("llama"));
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
        assert_eq!(ctx.cluster.as_deref(), Some("local-inf"), "cluster should be set");
    }

    #[tokio::test]
    async fn remote_inference_sets_gateway_cluster() {
        let f = make_filter(&[("inference_model", "llama", "site-b", "remote-gw")]);
        let mut req = crate::test_utils::make_request(Method::POST, "/chat");
        req.headers.insert("X-Model", http::HeaderValue::from_static("llama"));
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
        assert_eq!(ctx.cluster.as_deref(), Some("remote-gw"));
    }

    // ---- MCP tool routing ----

    #[tokio::test]
    async fn mcp_tools_call_routes_to_matching_tool() {
        let f = make_filter(&[
            ("mcp_tool", "weather", "site-c", "grid-site-c"),
            ("inference_model", "llama", "site-a", "local-inf"),
        ]);
        let req = crate::test_utils::make_request(Method::POST, "/mcp");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_metadata("mcp.method", "tools/call");
        ctx.set_metadata("mcp.name", "weather");

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue), "valid MCP tool should route");
        assert_eq!(
            ctx.cluster.as_deref(),
            Some("grid-site-c"),
            "cluster should be mcp_tool cluster"
        );
        assert_eq!(ctx.get_metadata("grid.route.kind"), Some("mcp_tool"));
        assert_eq!(ctx.get_metadata("grid.route.name"), Some("weather"));
    }

    #[tokio::test]
    async fn mcp_tools_call_beats_model_header() {
        let f = make_filter(&[
            ("mcp_tool", "weather", "site-c", "mcp-cluster"),
            ("inference_model", "llama", "site-a", "inf-cluster"),
        ]);
        let mut req = crate::test_utils::make_request(Method::POST, "/mcp");
        req.headers.insert("X-Model", http::HeaderValue::from_static("llama"));
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_metadata("mcp.method", "tools/call");
        ctx.set_metadata("mcp.name", "weather");

        let _unused = f.on_request(&mut ctx).await.unwrap();
        assert_eq!(
            ctx.cluster.as_deref(),
            Some("mcp-cluster"),
            "MCP metadata must win over model header"
        );
    }

    #[tokio::test]
    async fn mcp_non_tools_call_skips_even_with_model_header() {
        let f = make_filter(&[("inference_model", "llama", "site-a", "inf-cluster")]);
        let mut req = crate::test_utils::make_request(Method::POST, "/mcp");
        req.headers.insert("X-Model", http::HeaderValue::from_static("llama"));
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_metadata("mcp.method", "initialize");

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Continue),
            "non-tools/call MCP method must skip without routing"
        );
        assert!(ctx.cluster.is_none(), "no cluster should be set for non-tools/call");
        assert_no_route_metadata(&ctx);
    }

    #[tokio::test]
    async fn mcp_tools_call_missing_name_rejects_400() {
        let f = make_filter(&[("mcp_tool", "weather", "site-c", "c")]);
        let req = crate::test_utils::make_request(Method::POST, "/mcp");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_metadata("mcp.method", "tools/call");
        // mcp.name not set

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 400),
            "missing mcp.name must reject 400"
        );
        assert_no_route_metadata(&ctx);
    }

    #[tokio::test]
    async fn mcp_tools_call_blank_name_rejects_400() {
        let f = make_filter(&[("mcp_tool", "weather", "site-c", "c")]);
        let req = crate::test_utils::make_request(Method::POST, "/mcp");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_metadata("mcp.method", "tools/call");
        ctx.set_metadata("mcp.name", "");

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 400),
            "blank mcp.name must reject 400"
        );
        assert_no_route_metadata(&ctx);
    }

    #[tokio::test]
    async fn unknown_mcp_tool_rejects_404() {
        let f = make_filter(&[("mcp_tool", "weather", "site-c", "c")]);
        let req = crate::test_utils::make_request(Method::POST, "/mcp");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_metadata("mcp.method", "tools/call");
        ctx.set_metadata("mcp.name", "unknown-tool");

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 404),
            "unknown mcp_tool must reject 404"
        );
        assert_no_route_metadata(&ctx);
    }

    #[tokio::test]
    async fn inference_candidate_not_matched_by_mcp_lookup() {
        // Only inference_model candidates configured; MCP tools/call should not match them.
        let f = make_filter(&[("inference_model", "llama", "site-a", "inf")]);
        let req = crate::test_utils::make_request(Method::POST, "/mcp");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_metadata("mcp.method", "tools/call");
        ctx.set_metadata("mcp.name", "llama");

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 404),
            "inference_model candidates must not match MCP lookup"
        );
    }

    #[tokio::test]
    async fn mcp_tool_applies_scoring() {
        let f = make_scored_filter(&[
            ("mcp_tool", "weather", "site-b", "remote-mcp", true),
            ("mcp_tool", "weather", "site-a", "local-mcp", true),
        ]);
        let req = crate::test_utils::make_request(Method::POST, "/mcp");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.set_metadata("mcp.method", "tools/call");
        ctx.set_metadata("mcp.name", "weather");

        let _unused = f.on_request(&mut ctx).await.unwrap();
        assert_eq!(ctx.cluster.as_deref(), Some("local-mcp"), "local MCP tool should win");
    }

    // ---- Cluster preservation ----

    #[tokio::test]
    async fn preserves_existing_cluster() {
        let f = make_filter(&[("inference_model", "llama", "site-a", "inf")]);
        let mut req = crate::test_utils::make_request(Method::POST, "/chat");
        req.headers.insert("X-Model", http::HeaderValue::from_static("llama"));
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.cluster = Some(Arc::from("pre-set-cluster"));

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
        assert_eq!(
            ctx.cluster.as_deref(),
            Some("pre-set-cluster"),
            "pre-set cluster should be preserved"
        );
        assert_no_route_metadata(&ctx);
    }

    // ---- Scoring ----

    #[tokio::test]
    async fn local_fresh_beats_remote_fresh() {
        let f = make_filter(&[
            ("inference_model", "llama", "site-b", "remote-inf"),
            ("inference_model", "llama", "site-a", "local-inf"),
        ]);
        let mut req = crate::test_utils::make_request(Method::POST, "/chat");
        req.headers.insert("X-Model", http::HeaderValue::from_static("llama"));
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let _unused = f.on_request(&mut ctx).await.unwrap();
        assert_eq!(
            ctx.cluster.as_deref(),
            Some("local-inf"),
            "local candidate should win over remote"
        );
    }

    #[tokio::test]
    async fn config_order_breaks_equal_score_ties() {
        let f = make_filter(&[
            ("inference_model", "llama", "site-b", "first-remote"),
            ("inference_model", "llama", "site-c", "second-remote"),
        ]);
        let mut req = crate::test_utils::make_request(Method::POST, "/chat");
        req.headers.insert("X-Model", http::HeaderValue::from_static("llama"));
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let _unused = f.on_request(&mut ctx).await.unwrap();
        assert_eq!(
            ctx.cluster.as_deref(),
            Some("first-remote"),
            "first configured candidate wins on equal score"
        );
    }

    #[tokio::test]
    async fn fresh_remote_beats_stale_remote() {
        let f = make_scored_filter(&[
            ("inference_model", "llama", "site-b", "stale-remote", false),
            ("inference_model", "llama", "site-c", "fresh-remote", true),
        ]);
        let mut req = crate::test_utils::make_request(Method::POST, "/chat");
        req.headers.insert("X-Model", http::HeaderValue::from_static("llama"));
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let _unused = f.on_request(&mut ctx).await.unwrap();
        assert_eq!(
            ctx.cluster.as_deref(),
            Some("fresh-remote"),
            "fresh candidate should beat stale"
        );
    }

    #[tokio::test]
    async fn fresh_remote_beats_stale_local() {
        let f = make_scored_filter(&[
            ("inference_model", "llama", "site-a", "stale-local", false),
            ("inference_model", "llama", "site-b", "fresh-remote", true),
        ]);
        let mut req = crate::test_utils::make_request(Method::POST, "/chat");
        req.headers.insert("X-Model", http::HeaderValue::from_static("llama"));
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let _unused = f.on_request(&mut ctx).await.unwrap();
        assert_eq!(
            ctx.cluster.as_deref(),
            Some("fresh-remote"),
            "fresh remote beats stale local"
        );
    }

    #[tokio::test]
    async fn stale_local_beats_stale_remote() {
        let f = make_scored_filter(&[
            ("inference_model", "llama", "site-b", "stale-remote", false),
            ("inference_model", "llama", "site-a", "stale-local", false),
        ]);
        let mut req = crate::test_utils::make_request(Method::POST, "/chat");
        req.headers.insert("X-Model", http::HeaderValue::from_static("llama"));
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let _unused = f.on_request(&mut ctx).await.unwrap();
        assert_eq!(
            ctx.cluster.as_deref(),
            Some("stale-local"),
            "stale local beats stale remote"
        );
    }

    // ---- Route metadata ----

    #[tokio::test]
    async fn scored_route_metadata_reflects_winner() {
        let f = make_filter(&[
            ("inference_model", "llama", "site-b", "remote-inf"),
            ("inference_model", "llama", "site-a", "local-inf"),
        ]);
        let mut req = crate::test_utils::make_request(Method::POST, "/chat");
        req.headers.insert("X-Model", http::HeaderValue::from_static("llama"));
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let _unused = f.on_request(&mut ctx).await.unwrap();
        assert_eq!(ctx.get_metadata("grid.route.cluster"), Some("local-inf"));
        assert_eq!(ctx.get_metadata("grid.route.kind"), Some("inference_model"));
        assert_eq!(ctx.get_metadata("grid.route.name"), Some("llama"));
        assert_eq!(ctx.get_metadata("grid.route.site"), Some("site-a"));
        assert_eq!(ctx.get_metadata("grid.route.local_site"), Some("site-a"));
    }

    #[tokio::test]
    async fn local_route_writes_metadata() {
        let f = make_filter(&[("inference_model", "llama", "site-a", "local-inf")]);
        let mut req = crate::test_utils::make_request(Method::POST, "/chat");
        req.headers.insert("X-Model", http::HeaderValue::from_static("llama"));
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let _unused = f.on_request(&mut ctx).await.unwrap();
        assert_eq!(ctx.get_metadata("grid.route.cluster"), Some("local-inf"));
        assert_eq!(ctx.get_metadata("grid.route.local_site"), Some("site-a"));
    }

    #[tokio::test]
    async fn remote_route_writes_metadata() {
        let f = make_filter(&[("inference_model", "llama", "site-b", "remote-gw")]);
        let mut req = crate::test_utils::make_request(Method::POST, "/chat");
        req.headers.insert("X-Model", http::HeaderValue::from_static("llama"));
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let _unused = f.on_request(&mut ctx).await.unwrap();
        assert_eq!(ctx.get_metadata("grid.route.cluster"), Some("remote-gw"));
        assert_eq!(ctx.get_metadata("grid.route.site"), Some("site-b"));
    }

    #[tokio::test]
    async fn unknown_model_writes_no_metadata() {
        let f = make_filter(&[("inference_model", "llama", "site-a", "inf")]);
        let mut req = crate::test_utils::make_request(Method::POST, "/chat");
        req.headers.insert("X-Model", http::HeaderValue::from_static("unknown"));
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let _unused = f.on_request(&mut ctx).await.unwrap();
        assert_no_route_metadata(&ctx);
    }

    #[tokio::test]
    async fn blank_model_writes_no_metadata() {
        let f = make_filter(&[("inference_model", "llama", "site-a", "inf")]);
        let mut req = crate::test_utils::make_request(Method::POST, "/chat");
        req.headers.insert("X-Model", http::HeaderValue::from_static(""));
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let _unused = f.on_request(&mut ctx).await.unwrap();
        assert_no_route_metadata(&ctx);
    }

    #[tokio::test]
    async fn missing_header_writes_no_metadata() {
        let f = make_filter(&[("inference_model", "llama", "site-a", "inf")]);
        let req = crate::test_utils::make_request(Method::POST, "/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let _unused = f.on_request(&mut ctx).await.unwrap();
        assert_no_route_metadata(&ctx);
    }

    #[tokio::test]
    async fn preserved_cluster_writes_no_metadata() {
        let f = make_filter(&[("inference_model", "llama", "site-a", "inf")]);
        let req = crate::test_utils::make_request(Method::POST, "/chat");
        let mut ctx = crate::test_utils::make_filter_context(&req);
        ctx.cluster = Some(Arc::from("pre-set"));

        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
        assert!(
            ctx.get_metadata("grid.route.kind").is_none(),
            "preserved cluster path should not write route metadata"
        );
    }

    // ---- Overlay config validation ----

    #[test]
    fn from_config_overlay_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");
        std::fs::write(
            &path,
            r#"{"local_site":"site-a","candidates":[{"kind":"inference_model","name":"llama","site":"site-a","cluster":"local","fresh":true}]}"#,
        )
        .unwrap();
        let yaml = format!("overlay_file: {}\nreload:\n  enabled: false\n", path.display());
        assert!(parse(&yaml).is_ok(), "overlay_file config should parse");
    }

    #[test]
    fn from_config_overlay_file_missing() {
        let yaml = "overlay_file: /nonexistent/grid-config.json\nreload:\n  enabled: false\n";
        let err = parse_err(yaml);
        assert!(
            err.to_string().contains("failed to read"),
            "missing overlay file should error: {err}"
        );
    }

    #[test]
    fn from_config_both_candidates_and_overlay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");
        std::fs::write(
            &path,
            r#"{"local_site":"a","candidates":[{"kind":"inference_model","name":"m","site":"s","cluster":"c","fresh":true}]}"#,
        )
        .unwrap();
        let yaml = format!(
            "overlay_file: {}\nlocal_site: site-a\ncandidates:\n  - kind: inference_model\n    name: m\n    site: s\n    cluster: c\n    fresh: true\n",
            path.display()
        );
        let err = parse_err(&yaml);
        assert!(
            err.to_string().contains("cannot set both"),
            "both overlay_file and candidates should be rejected: {err}"
        );
    }

    #[test]
    fn from_config_neither_candidates_nor_overlay() {
        let yaml = "model_header: X-Model\n";
        let err = parse_err(yaml);
        assert!(
            err.to_string().contains("either overlay_file or candidates"),
            "neither source should be rejected: {err}"
        );
    }

    #[test]
    fn from_config_static_backwards_compat() {
        let yaml = "local_site: site-a\ncandidates:\n  - kind: inference_model\n    name: llama\n    site: site-a\n    cluster: inf\n    fresh: true\n";
        assert!(parse(yaml).is_ok(), "existing static config should still work");
    }

    #[tokio::test]
    async fn on_request_after_snapshot_swap() {
        let shared = Arc::new(ArcSwap::from_pointee(make_snapshot("cluster-v1")));
        let filter = GridRouteFilter {
            snapshot: Arc::clone(&shared),
            model_header: http::header::HeaderName::from_static("x-model"),
            _reload_handle: None,
        };

        assert_eq!(route_model(&filter, "llama").await.as_deref(), Some("cluster-v1"));

        shared.store(Arc::new(make_snapshot("cluster-v2")));

        assert_eq!(route_model(&filter, "llama").await.as_deref(), Some("cluster-v2"));
    }

    #[test]
    fn reload_config_defaults() {
        let cfg: ReloadConfig = serde_yaml::from_str("{}").unwrap();
        assert!(cfg.enabled, "default enabled should be true");
        assert_eq!(cfg.debounce_ms, overlay::DEFAULT_DEBOUNCE_MS, "default debounce_ms");
    }

    #[test]
    fn reload_config_custom_debounce() {
        let cfg: ReloadConfig = serde_yaml::from_str("debounce_ms: 1000\n").unwrap();
        assert_eq!(cfg.debounce_ms, 1000);
    }

    #[test]
    fn reload_disabled_no_watcher() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");
        std::fs::write(
            &path,
            r#"{"local_site":"site-a","candidates":[{"kind":"inference_model","name":"m","site":"s","cluster":"c","fresh":true}]}"#,
        )
        .unwrap();
        let yaml = format!("overlay_file: {}\nreload:\n  enabled: false\n", path.display());
        let _filter = parse(&yaml).unwrap();
    }

    // ---- Static/dynamic config matrix (item 6) ----

    #[test]
    fn reload_block_with_static_candidates_rejected() {
        let yaml = "local_site: site-a\nreload:\n  enabled: true\ncandidates:\n  - kind: inference_model\n    name: m\n    site: s\n    cluster: c\n    fresh: true\n";
        let err = parse_err(yaml);
        assert!(
            err.to_string()
                .contains("reload block is not valid with static candidates"),
            "reload block with static candidates should be rejected: {err}"
        );
    }

    #[test]
    fn reload_block_disabled_with_static_candidates_rejected() {
        let yaml = "local_site: site-a\nreload:\n  enabled: false\ncandidates:\n  - kind: inference_model\n    name: m\n    site: s\n    cluster: c\n    fresh: true\n";
        let err = parse_err(yaml);
        assert!(
            err.to_string()
                .contains("reload block is not valid with static candidates"),
            "reload block with static candidates should be rejected even if enabled=false: {err}"
        );
    }

    #[test]
    fn overlay_without_reload_block_uses_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");
        std::fs::write(
            &path,
            r#"{"local_site":"a","candidates":[{"kind":"inference_model","name":"m","site":"s","cluster":"c","fresh":true}]}"#,
        )
        .unwrap();
        let yaml = format!("overlay_file: {}\n", path.display());
        assert!(parse(&yaml).is_ok(), "overlay without reload block should use defaults");
    }

    #[test]
    fn overlay_with_reload_enabled_false() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");
        std::fs::write(
            &path,
            r#"{"local_site":"a","candidates":[{"kind":"inference_model","name":"m","site":"s","cluster":"c","fresh":true}]}"#,
        )
        .unwrap();
        let yaml = format!("overlay_file: {}\nreload:\n  enabled: false\n", path.display());
        assert!(parse(&yaml).is_ok(), "overlay with reload disabled should work");
    }

    #[test]
    fn overlay_with_reload_enabled_true() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");
        std::fs::write(
            &path,
            r#"{"local_site":"a","candidates":[{"kind":"inference_model","name":"m","site":"s","cluster":"c","fresh":true}]}"#,
        )
        .unwrap();
        let yaml = format!(
            "overlay_file: {}\nreload:\n  enabled: true\n  debounce_ms: 100\n",
            path.display()
        );
        assert!(parse(&yaml).is_ok(), "overlay with reload enabled should work");
    }

    #[test]
    fn static_candidates_no_reload_block() {
        let yaml = "local_site: site-a\ncandidates:\n  - kind: inference_model\n    name: m\n    site: s\n    cluster: c\n    fresh: true\n";
        assert!(
            parse(yaml).is_ok(),
            "static candidates without reload block should work"
        );
    }

    #[test]
    fn overlay_with_custom_debounce() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");
        std::fs::write(
            &path,
            r#"{"local_site":"a","candidates":[{"kind":"inference_model","name":"m","site":"s","cluster":"c","fresh":true}]}"#,
        )
        .unwrap();
        let yaml = format!(
            "overlay_file: {}\nreload:\n  enabled: false\n  debounce_ms: 2000\n",
            path.display()
        );
        assert!(parse(&yaml).is_ok(), "overlay with custom debounce should work");
    }

    #[test]
    fn neither_source_no_reload_rejected() {
        let yaml = "model_header: X-Model\nreload:\n  enabled: true\n";
        let err = parse_err(yaml);
        assert!(
            err.to_string().contains("either overlay_file or candidates"),
            "no source + reload should still be rejected: {err}"
        );
    }

    // ---- Selection contract (item 7) ----

    #[tokio::test]
    async fn reorder_after_reload_changes_selection() {
        let shared = Arc::new(ArcSwap::from_pointee(make_two_candidate_snapshot(
            "cluster-a",
            "site-b",
            "cluster-b",
            "site-a",
        )));
        let filter = GridRouteFilter {
            snapshot: Arc::clone(&shared),
            model_header: http::header::HeaderName::from_static("x-model"),
            _reload_handle: None,
        };
        assert_eq!(route_model(&filter, "llama").await.as_deref(), Some("cluster-b"));

        shared.store(Arc::new(make_two_candidate_snapshot(
            "cluster-c",
            "site-c",
            "cluster-a",
            "site-a",
        )));
        assert_eq!(route_model(&filter, "llama").await.as_deref(), Some("cluster-a"));
    }

    #[tokio::test]
    async fn stale_first_does_not_beat_fresh_later() {
        let f = make_scored_filter(&[
            ("inference_model", "llama", "site-a", "stale-local", false),
            ("inference_model", "llama", "site-b", "fresh-remote", true),
        ]);
        let mut req = crate::test_utils::make_request(Method::POST, "/chat");
        req.headers.insert("X-Model", http::HeaderValue::from_static("llama"));
        let mut ctx = crate::test_utils::make_filter_context(&req);

        let _unused = f.on_request(&mut ctx).await.unwrap();
        assert_eq!(
            ctx.cluster.as_deref(),
            Some("fresh-remote"),
            "stale candidate listed first must NOT beat fresh candidate listed later"
        );
    }

    // ---- Overlay bounded read at startup (item 3) ----

    #[test]
    fn from_config_overlay_oversized() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");
        let content = vec![b'x'; (overlay::MAX_OVERLAY_SIZE + 1) as usize];
        std::fs::write(&path, &content).unwrap();
        let yaml = format!("overlay_file: {}\nreload:\n  enabled: false\n", path.display());
        let err = parse_err(&yaml);
        assert!(
            err.to_string().contains("exceeds"),
            "oversized overlay at startup should be rejected: {err}"
        );
    }

    // ---- Test utilities ----

    fn assert_no_route_metadata(ctx: &HttpFilterContext<'_>) {
        assert!(
            ctx.get_metadata("grid.route.kind").is_none(),
            "grid.route.kind should be absent"
        );
        assert!(
            ctx.get_metadata("grid.route.name").is_none(),
            "grid.route.name should be absent"
        );
        assert!(
            ctx.get_metadata("grid.route.site").is_none(),
            "grid.route.site should be absent"
        );
        assert!(
            ctx.get_metadata("grid.route.cluster").is_none(),
            "grid.route.cluster should be absent"
        );
        assert!(
            ctx.get_metadata("grid.route.local_site").is_none(),
            "grid.route.local_site should be absent"
        );
    }

    fn parse(yaml: &str) -> Result<Box<dyn HttpFilter>, FilterError> {
        let val: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        GridRouteFilter::from_config(&val)
    }

    fn parse_err(yaml: &str) -> FilterError {
        parse(yaml).err().expect("config should have been rejected")
    }

    fn make_filter(candidates: &[(&str, &str, &str, &str)]) -> Box<dyn HttpFilter> {
        let scored: Vec<(&str, &str, &str, &str, bool)> =
            candidates.iter().map(|(k, n, s, c)| (*k, *n, *s, *c, true)).collect();
        make_scored_filter(&scored)
    }

    fn make_scored_filter(candidates: &[(&str, &str, &str, &str, bool)]) -> Box<dyn HttpFilter> {
        use std::fmt::Write as _;

        let mut yaml = String::from("local_site: site-a\ncandidates:\n");
        for (kind, name, site, cluster, fresh) in candidates {
            writeln!(
                yaml,
                "  - kind: {kind}\n    name: {name}\n    site: {site}\n    cluster: {cluster}\n    fresh: {fresh}"
            )
            .expect("String write is infallible");
        }
        parse(&yaml).unwrap()
    }

    fn make_two_candidate_snapshot(cluster1: &str, site1: &str, cluster2: &str, site2: &str) -> RouteSnapshot {
        RouteSnapshot::from_static(
            descriptor::validate_candidates(vec![
                CandidateConfig {
                    cluster: cluster1.to_owned(),
                    fresh: true,
                    kind: CapabilityKind::InferenceModel,
                    name: "llama".to_owned(),
                    site: site1.to_owned(),
                },
                CandidateConfig {
                    cluster: cluster2.to_owned(),
                    fresh: true,
                    kind: CapabilityKind::InferenceModel,
                    name: "llama".to_owned(),
                    site: site2.to_owned(),
                },
            ])
            .unwrap(),
            Arc::from("site-a"),
        )
    }

    fn make_snapshot(cluster: &str) -> RouteSnapshot {
        RouteSnapshot::from_static(
            descriptor::validate_candidates(vec![CandidateConfig {
                cluster: cluster.to_owned(),
                fresh: true,
                kind: CapabilityKind::InferenceModel,
                name: "llama".to_owned(),
                site: "site-a".to_owned(),
            }])
            .unwrap(),
            Arc::from("site-a"),
        )
    }

    async fn route_model(filter: &GridRouteFilter, model: &str) -> Option<String> {
        let mut req = crate::test_utils::make_request(Method::POST, "/chat");
        req.headers
            .insert("X-Model", http::HeaderValue::from_str(model).unwrap());
        let mut ctx = crate::test_utils::make_filter_context(&req);
        let _unused = filter.on_request(&mut ctx).await.unwrap();
        ctx.cluster.as_deref().map(str::to_owned)
    }
}
