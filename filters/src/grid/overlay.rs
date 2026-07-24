// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Grid routing overlay types, snapshot, and file watcher.
//!
//! Provides [`RouteSnapshot`] (the atomic unit of routing state swapped
//! by [`ArcSwap`]) and the file watcher that detects `grid-config.json`
//! changes and performs filter-local hot reload.
//!
//! The overlay wire types ([`OverlayDocument`], [`OverlayCandidate`])
//! mirror the JSON structure rendered by the Grid operator into a
//! Kubernetes `ConfigMap`.  Only the fields needed for routing are
//! consumed; credential references are deserialized for type
//! compatibility but not used by `grid_route`.
//!
//! [`ArcSwap`]: arc_swap::ArcSwap

use std::{
    io::Read as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use arc_swap::ArcSwap;
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher as _};
use praxis_filter::FilterError;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::descriptor::{self, AdmissionState, CandidateConfig, CapabilityKind, RouteCandidate};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default debounce window for overlay file events (milliseconds).
pub(crate) const DEFAULT_DEBOUNCE_MS: u64 = 500;

/// Maximum overlay file size (2 MiB).
///
/// Kubernetes `ConfigMaps` are limited to 1 MiB, so this provides
/// headroom while preventing unbounded memory allocation from a
/// misconfigured or malicious mount.
pub(crate) const MAX_OVERLAY_SIZE: u64 = 2 * 1024 * 1024;

/// Timeout for joining the watcher thread during [`Drop`].
///
/// The watcher is cancellation-aware, so it should exit within one
/// debounce window after shutdown is signalled.  If it has not exited
/// after this timeout, a warning is logged and the thread is detached.
const JOIN_TIMEOUT: Duration = Duration::from_secs(2);

// -----------------------------------------------------------------------------
// Overlay wire types (JSON)
// -----------------------------------------------------------------------------

/// Top-level routing overlay document as rendered by the Grid operator.
///
/// Serialised as JSON under the `grid-config.json` key of the overlay
/// `ConfigMap`.
#[derive(Debug, Deserialize)]
pub(crate) struct OverlayDocument {
    /// Local site identifier for scoring and metadata.
    pub(crate) local_site: String,

    /// Routing candidates, ordered by the Grid scoring engine.
    pub(crate) candidates: Vec<OverlayCandidate>,

    /// ISO-8601 timestamp when the overlay was generated.
    #[serde(default)]
    pub(crate) generated_at: Option<String>,

    /// Network name.  Accepted but not used by `grid_route`.
    #[serde(default)]
    #[expect(dead_code, reason = "accepted for forward compatibility")]
    network: Option<String>,
}

/// A single routing candidate from the Grid overlay.
///
/// Does **not** use `deny_unknown_fields` — the Grid operator may
/// add new metadata fields before AI is updated.
#[derive(Debug, Deserialize)]
pub(crate) struct OverlayCandidate {
    /// Grid-operator admission state string.
    #[serde(default)]
    pub(crate) admission_state: Option<String>,

    /// Upstream cluster identifier.
    pub(crate) cluster: String,

    /// Credential reference projected by the operator.
    ///
    /// Deserialized for type compatibility; **not used** by `grid_route`.
    /// The `grid_credential_inject` filter (PR #386) consumes this field.
    #[serde(default)]
    #[expect(
        clippy::allow_attributes,
        reason = "dead_code fires only in lib, not in test; expect would be unfulfilled in test"
    )]
    #[allow(dead_code, reason = "type compatibility with Grid overlay")]
    credential: Option<OverlayCredential>,

    /// Whether this candidate is considered fresh by the Grid operator.
    #[serde(default = "default_fresh")]
    pub(crate) fresh: bool,

    /// Capability kind string (e.g. `"inference_model"`, `"mcp_tool"`).
    pub(crate) kind: String,

    /// Capability name (model name, tool name).
    pub(crate) name: String,

    /// Grid-operator rank within the overlay (lower is better).
    #[serde(default)]
    pub(crate) rank: Option<u32>,

    /// Grid-operator locality tier (e.g. `"same_region"`).
    #[serde(default)]
    pub(crate) selection_tier: Option<String>,

    /// Site that owns this capability.
    pub(crate) site: String,

    /// Deterministic identifier assigned by the Grid operator.
    #[serde(default)]
    pub(crate) stable_id: Option<String>,
}

/// Default freshness for overlay candidates.
fn default_fresh() -> bool {
    true
}

/// Projected credential reference from the Grid overlay.
///
/// Contains only the Secret reference — never the token value.
/// Uses `deny_unknown_fields` to reject token-like fields that
/// should never appear in the overlay.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(dead_code, reason = "type compatibility with Grid overlay")]
struct OverlayCredential {
    /// Authentication strategy (e.g. `"bearer_token"`).
    strategy: String,

    /// Reference to the Secret holding the credential.
    #[serde(rename = "secretRef", alias = "secret_ref")]
    secret_ref: OverlaySecretRef,
}

/// Secret reference within a projected credential.
///
/// Uses `deny_unknown_fields` to reject fields like `value` or
/// `token` that might contain actual secret material.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(dead_code, reason = "type compatibility with Grid overlay")]
struct OverlaySecretRef {
    /// Secret name.
    name: String,

    /// Secret namespace.
    namespace: String,

    /// Key within the Secret data.
    key: String,
}

// -----------------------------------------------------------------------------
// RouteSnapshot
// -----------------------------------------------------------------------------

/// Atomic snapshot of routing state loaded by `grid_route` on each request.
///
/// Stored behind [`ArcSwap`] so the watcher can swap in new state while
/// in-flight requests continue using their loaded snapshot.
///
/// [`ArcSwap`]: arc_swap::ArcSwap
#[derive(Debug)]
pub(crate) struct RouteSnapshot {
    /// Validated route candidates.
    pub(crate) candidates: Vec<RouteCandidate>,

    /// SHA-256 digest of the raw overlay file content that produced
    /// this snapshot.  Used for change detection; `[0; 32]` for
    /// statically configured snapshots.
    pub(crate) content_hash: [u8; 32],

    /// ISO-8601 timestamp when the overlay was generated by Grid.
    #[expect(dead_code, reason = "stored for future freshness/staleness policy")]
    pub(crate) generated_at: Option<Arc<str>>,

    /// Local site identifier.
    pub(crate) local_site: Arc<str>,
}

impl RouteSnapshot {
    /// Build a snapshot from raw overlay file content.
    ///
    /// Computes the content hash, parses JSON, validates the overlay,
    /// and returns a ready-to-swap snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`FilterError`] if the JSON is invalid, a candidate kind
    /// is unrecognised, or validation fails.
    pub(crate) fn from_overlay(content: &[u8]) -> Result<Self, FilterError> {
        let content_hash: [u8; 32] = Sha256::digest(content).into();

        let doc: OverlayDocument = serde_json::from_slice(content)
            .map_err(|e| FilterError::from(format!("grid: overlay parse error: {e}")))?;

        descriptor::validate_local_site(&doc.local_site)?;
        let candidates = overlay_to_candidates(&doc)?;
        let generated_at = doc.generated_at.map(|s| Arc::from(s.as_str()));

        Ok(Self {
            candidates,
            content_hash,
            generated_at,
            local_site: Arc::from(doc.local_site.as_str()),
        })
    }

    /// Build a snapshot from statically configured candidates.
    ///
    /// The content hash is `[0; 32]` (never compared against file content).
    pub(crate) fn from_static(candidates: Vec<RouteCandidate>, local_site: Arc<str>) -> Self {
        Self {
            candidates,
            content_hash: [0; 32],
            generated_at: None,
            local_site,
        }
    }
}

// -----------------------------------------------------------------------------
// Overlay → RouteCandidate conversion
// -----------------------------------------------------------------------------

/// Convert overlay candidates to validated [`RouteCandidate`]s.
fn overlay_to_candidates(doc: &OverlayDocument) -> Result<Vec<RouteCandidate>, FilterError> {
    let raw: Vec<CandidateConfig> = doc
        .candidates
        .iter()
        .map(|oc| {
            let kind = CapabilityKind::from_overlay_str(&oc.kind)?;
            Ok(CandidateConfig {
                cluster: oc.cluster.clone(),
                fresh: oc.fresh,
                kind,
                name: oc.name.clone(),
                site: oc.site.clone(),
            })
        })
        .collect::<Result<Vec<_>, FilterError>>()?;

    let mut candidates = descriptor::validate_candidates(raw)?;
    enrich_from_overlay(&mut candidates, &doc.candidates);
    Ok(candidates)
}

/// Apply Grid-operator metadata to validated candidates.
///
/// Zips the validated candidate list with the original overlay entries
/// and sets `admission_state`, `rank`, `selection_tier`, and `stable_id`.
/// Called after [`validate_candidates`] so `deny_unknown_fields` on
/// [`CandidateConfig`] is never bypassed.
///
/// [`validate_candidates`]: descriptor::validate_candidates
pub(super) fn enrich_from_overlay(candidates: &mut [RouteCandidate], overlay: &[OverlayCandidate]) {
    for (c, oc) in candidates.iter_mut().zip(overlay.iter()) {
        if let Some(s) = &oc.admission_state {
            c.admission_state = AdmissionState::from_overlay_str(s);
        }
        c.rank = oc.rank;
        if let Some(t) = &oc.selection_tier {
            c.selection_tier = Some(Arc::from(t.as_str()));
        }
        if let Some(id) = &oc.stable_id {
            c.stable_id = Arc::from(id.as_str());
        }
    }
}

// -----------------------------------------------------------------------------
// OverlayReloadHandle
// -----------------------------------------------------------------------------

/// Handle to the overlay file watcher thread.
///
/// On [`Drop`], signals shutdown via [`CancellationToken`] and performs a
/// bounded join on the watcher thread (up to [`JOIN_TIMEOUT`]).  If the
/// thread has not exited by the timeout, a warning is logged and the
/// thread is detached — the `CancellationToken` remains signalled so the
/// thread will exit when it next checks.
pub(crate) struct OverlayReloadHandle {
    /// Shutdown signal for the watcher thread.
    shutdown: CancellationToken,

    /// Watcher thread join handle.
    thread: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for OverlayReloadHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OverlayReloadHandle")
            .field("shutdown_requested", &self.shutdown.is_cancelled())
            .finish()
    }
}

impl Drop for OverlayReloadHandle {
    #[expect(
        clippy::disallowed_methods,
        reason = "Drop is sync; tokio::time::sleep cannot be used here"
    )]
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(handle) = self.thread.take() {
            let start = std::time::Instant::now();
            while !handle.is_finished() {
                if start.elapsed() >= JOIN_TIMEOUT {
                    tracing::warn!(
                        timeout_secs = JOIN_TIMEOUT.as_secs(),
                        "grid_route: overlay watcher thread did not exit within timeout"
                    );
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            drop(handle.join());
        }
    }
}

// -----------------------------------------------------------------------------
// Watcher
// -----------------------------------------------------------------------------

/// Spawn a background file watcher for the overlay file.
///
/// Returns a handle that cancels and joins the watcher on drop.
///
/// # Panics
///
/// Panics if the tokio runtime cannot be created on the watcher thread.
#[expect(clippy::expect_used, reason = "fatal if tokio runtime cannot start")]
pub(crate) fn spawn_overlay_watcher(
    path: PathBuf,
    snapshot: Arc<ArcSwap<RouteSnapshot>>,
    debounce_ms: u64,
) -> OverlayReloadHandle {
    let shutdown = CancellationToken::new();
    let token = shutdown.clone();

    let thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("overlay watcher tokio runtime");
        rt.block_on(watch_loop(path, snapshot, debounce_ms, token));
    });

    OverlayReloadHandle {
        shutdown,
        thread: Some(thread),
    }
}

/// Core watch loop: set up the notify watcher, debounce events,
/// and trigger overlay reloads.
async fn watch_loop(
    path: PathBuf,
    snapshot: Arc<ArcSwap<RouteSnapshot>>,
    debounce_ms: u64,
    shutdown: CancellationToken,
) {
    let (tx, mut rx) = mpsc::channel::<()>(16);

    let watch_dir = watch_dir_for_path(&path);

    let _watcher = match setup_watcher(tx, &watch_dir) {
        Ok(w) => w,
        Err(e) => {
            tracing::error!(error = %e, "grid_route: failed to start overlay file watcher");
            return;
        },
    };

    // Authoritative re-read after watcher registration to close the
    // startup race window: any overlay change between the initial read
    // in build_overlay_snapshot and watcher registration is caught here.
    handle_overlay_reload(&path, &snapshot);

    tracing::info!(
        path = %path.display(),
        debounce_ms = debounce_ms,
        "grid_route: overlay file watcher started"
    );

    run_event_loop(&mut rx, &path, &snapshot, debounce_ms, &shutdown).await;
}

/// Process filesystem events until shutdown is requested.
#[expect(
    clippy::cognitive_complexity,
    reason = "complexity is from tokio::select! macro expansion"
)]
async fn run_event_loop(
    rx: &mut mpsc::Receiver<()>,
    path: &Path,
    snapshot: &ArcSwap<RouteSnapshot>,
    debounce_ms: u64,
    shutdown: &CancellationToken,
) {
    loop {
        tokio::select! {
            Some(()) = rx.recv() => {
                tracing::debug!(debounce_ms = debounce_ms, "grid_route: overlay change detected, debouncing");
                if !drain_and_debounce(rx, debounce_ms, shutdown).await {
                    tracing::info!("grid_route: overlay file watcher shutting down");
                    return;
                }
                handle_overlay_reload(path, snapshot);
            }
            () = shutdown.cancelled() => {
                tracing::info!("grid_route: overlay file watcher shutting down");
                return;
            }
        }
    }
}

/// Read, validate, and swap the overlay snapshot.
fn handle_overlay_reload(path: &Path, snapshot: &ArcSwap<RouteSnapshot>) {
    let Some(content) = read_overlay(path) else {
        return;
    };

    if is_unchanged(&content, snapshot) {
        return;
    }

    apply_overlay(path, &content, snapshot);
}

/// Read the overlay file with a bounded read.
///
/// Uses [`read_overlay_bounded`] and logs errors.
fn read_overlay(path: &Path) -> Option<Vec<u8>> {
    match read_overlay_bounded(path) {
        Ok(c) => Some(c),
        Err(e) => {
            tracing::error!(
                path = %path.display(),
                error = %e,
                "grid_route: failed to read overlay file for reload"
            );
            None
        },
    }
}

/// Read at most [`MAX_OVERLAY_SIZE`] bytes from the overlay file.
///
/// Opens the file and reads at most `MAX_OVERLAY_SIZE + 1` bytes.
/// If the extra byte is present, the file exceeds the limit and an
/// error is returned — without ever allocating the full file size.
///
/// # Errors
///
/// Returns [`std::io::Error`] if the file cannot be opened, read,
/// or exceeds [`MAX_OVERLAY_SIZE`].
pub(crate) fn read_overlay_bounded(path: &Path) -> Result<Vec<u8>, std::io::Error> {
    let file = std::fs::File::open(path)?;
    let limit = MAX_OVERLAY_SIZE + 1;
    let mut buf = Vec::new();
    file.take(limit).read_to_end(&mut buf)?;
    if buf.len() as u64 > MAX_OVERLAY_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("overlay file exceeds {MAX_OVERLAY_SIZE} byte limit"),
        ));
    }
    Ok(buf)
}

/// Check whether the content hash matches the current snapshot.
fn is_unchanged(content: &[u8], snapshot: &ArcSwap<RouteSnapshot>) -> bool {
    let new_hash: [u8; 32] = Sha256::digest(content).into();
    let unchanged = new_hash == snapshot.load().content_hash;
    if unchanged {
        tracing::debug!("grid_route: overlay content unchanged (hash match)");
    }
    unchanged
}

/// Parse the overlay and swap the snapshot on success.
fn apply_overlay(path: &Path, content: &[u8], snapshot: &ArcSwap<RouteSnapshot>) {
    match RouteSnapshot::from_overlay(content) {
        Ok(new_snap) => {
            tracing::info!(
                candidate_count = new_snap.candidates.len(),
                local_site = &*new_snap.local_site,
                "grid_route: overlay reloaded"
            );
            snapshot.store(Arc::new(new_snap));
        },
        Err(e) => {
            tracing::error!(
                path = %path.display(),
                error = %e,
                "grid_route: overlay reload failed, retaining previous snapshot"
            );
        },
    }
}

/// Set up a [`RecommendedWatcher`] that sends to the given channel
/// on relevant filesystem events.
fn setup_watcher(tx: mpsc::Sender<()>, watch_dir: &Path) -> Result<RecommendedWatcher, notify::Error> {
    let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| match res {
        Ok(event) if is_relevant_event(event.kind) && tx.try_send(()).is_err() => {
            tracing::trace!("grid_route: overlay watcher channel full, event coalesced by debounce");
        },
        Err(e) => {
            tracing::warn!(error = %e, "grid_route: overlay file watcher error");
        },
        _ => {},
    })?;

    watcher.watch(watch_dir, RecursiveMode::NonRecursive)?;
    Ok(watcher)
}

/// Cancellation-aware debounce: sleep for the debounce window, then
/// drain any queued events.
///
/// Returns `true` to proceed with reload, `false` if shutdown was
/// requested during the debounce.
async fn drain_and_debounce(rx: &mut mpsc::Receiver<()>, debounce_ms: u64, shutdown: &CancellationToken) -> bool {
    tokio::select! {
        () = tokio::time::sleep(Duration::from_millis(debounce_ms)) => {
            while rx.try_recv().is_ok() {}
            true
        }
        () = shutdown.cancelled() => false
    }
}

/// Whether a notify event kind is relevant for overlay reload.
///
/// Accepts Create, Modify (including rename/Name events), and Remove.
/// No path filtering is applied — any relevant event on the watched
/// parent directory triggers a re-read.  Hash comparison handles
/// false positives.
fn is_relevant_event(kind: EventKind) -> bool {
    matches!(kind, EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_))
}

/// Resolve the directory to watch for a given overlay path.
///
/// Falls back to `.` when the path has no non-empty parent.
fn watch_dir_for_path(path: &Path) -> PathBuf {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::cast_possible_truncation,
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // Overlay parsing
    // -------------------------------------------------------------------------

    #[test]
    fn parse_minimal_overlay() {
        let json = r#"{
            "local_site": "site-a",
            "candidates": [{
                "kind": "inference_model",
                "name": "llama-3",
                "site": "site-a",
                "cluster": "local-inference",
                "fresh": true
            }]
        }"#;
        let doc: OverlayDocument = serde_json::from_str(json).unwrap();
        assert_eq!(doc.local_site, "site-a");
        assert_eq!(doc.candidates.len(), 1);
        assert_eq!(doc.candidates[0].kind, "inference_model");
        assert_eq!(doc.candidates[0].name, "llama-3");
        assert!(doc.candidates[0].fresh);
        assert!(doc.candidates[0].credential.is_none());
    }

    #[test]
    fn parse_overlay_with_credential_camel_case() {
        let json = r#"{
            "local_site": "site-a",
            "candidates": [{
                "kind": "inference_model",
                "name": "gpt-4",
                "site": "site-b",
                "cluster": "api-provider",
                "fresh": true,
                "credential": {
                    "strategy": "bearer_token",
                    "secretRef": {
                        "name": "provider-token",
                        "namespace": "grid-system",
                        "key": "token"
                    }
                }
            }]
        }"#;
        let doc: OverlayDocument = serde_json::from_str(json).unwrap();
        assert!(doc.candidates[0].credential.is_some());
    }

    #[test]
    fn parse_overlay_with_credential_snake_case_alias() {
        let json = r#"{
            "local_site": "site-a",
            "candidates": [{
                "kind": "inference_model",
                "name": "gpt-4",
                "site": "site-b",
                "cluster": "api-provider",
                "fresh": true,
                "credential": {
                    "strategy": "bearer_token",
                    "secret_ref": {
                        "name": "openai-key",
                        "namespace": "grid-system",
                        "key": "token"
                    }
                }
            }]
        }"#;
        let doc: OverlayDocument = serde_json::from_str(json).unwrap();
        assert!(doc.candidates[0].credential.is_some());
    }

    #[test]
    fn parse_overlay_with_network_field() {
        let json = r#"{
            "network": "production",
            "local_site": "site-a",
            "candidates": [{
                "kind": "inference_model",
                "name": "llama-3",
                "site": "site-a",
                "cluster": "local",
                "fresh": true
            }]
        }"#;
        let doc: OverlayDocument = serde_json::from_str(json).unwrap();
        assert_eq!(doc.local_site, "site-a");
    }

    #[test]
    fn parse_overlay_unknown_kind_rejected() {
        let json = r#"{
            "local_site": "site-a",
            "candidates": [{
                "kind": "unknown_type",
                "name": "foo",
                "site": "site-a",
                "cluster": "local",
                "fresh": true
            }]
        }"#;
        let result = RouteSnapshot::from_overlay(json.as_bytes());
        assert!(result.is_err(), "unknown kind should be rejected");
    }

    #[test]
    fn parse_overlay_empty_candidates() {
        let json = r#"{
            "local_site": "site-a",
            "candidates": []
        }"#;
        let result = RouteSnapshot::from_overlay(json.as_bytes());
        assert!(result.is_err(), "empty candidates should be rejected");
    }

    #[test]
    fn parse_overlay_missing_required_field() {
        let json = r#"{
            "local_site": "site-a",
            "candidates": [{
                "kind": "inference_model",
                "name": "llama-3",
                "fresh": true
            }]
        }"#;
        let result: Result<OverlayDocument, _> = serde_json::from_str(json);
        assert!(result.is_err(), "missing site/cluster should fail");
    }

    // -------------------------------------------------------------------------
    // Credential safety (deny_unknown_fields)
    // -------------------------------------------------------------------------

    #[test]
    fn credential_rejects_token_field() {
        let json = r#"{
            "local_site": "site-a",
            "candidates": [{
                "kind": "inference_model",
                "name": "gpt-4",
                "site": "site-b",
                "cluster": "api",
                "fresh": true,
                "credential": {
                    "strategy": "bearer_token",
                    "token": "sk-1234567890",
                    "secretRef": { "name": "k", "namespace": "ns", "key": "t" }
                }
            }]
        }"#;
        let result = RouteSnapshot::from_overlay(json.as_bytes());
        assert!(result.is_err(), "token field in credential must be rejected");
    }

    #[test]
    fn secret_ref_rejects_value_field() {
        let json = r#"{
            "local_site": "site-a",
            "candidates": [{
                "kind": "inference_model",
                "name": "gpt-4",
                "site": "site-b",
                "cluster": "api",
                "fresh": true,
                "credential": {
                    "strategy": "bearer_token",
                    "secretRef": {
                        "name": "k",
                        "namespace": "ns",
                        "key": "t",
                        "value": "sk-secret-value"
                    }
                }
            }]
        }"#;
        let result = RouteSnapshot::from_overlay(json.as_bytes());
        assert!(result.is_err(), "value field in secret_ref must be rejected");
    }

    #[test]
    fn snapshot_from_grid_produced_overlay() {
        let json = r#"{
            "local_site": "us-east-1",
            "candidates": [{
                "kind": "inference_model",
                "name": "llama-3-70b",
                "site": "us-east-1",
                "cluster": "gpu-pool-a",
                "fresh": true,
                "stable_id": "cand-abc123",
                "admission_state": "new_and_existing",
                "selection_tier": "same_site",
                "rank": 0,
                "generated_at": "2026-07-24T12:00:00Z",
                "credential": {
                    "strategy": "bearer_token",
                    "secretRef": {
                        "name": "provider-token",
                        "namespace": "grid-system",
                        "key": "token"
                    }
                }
            }]
        }"#;
        let snap = RouteSnapshot::from_overlay(json.as_bytes()).unwrap();
        assert_eq!(snap.candidates.len(), 1);
        assert_eq!(&*snap.candidates[0].name, "llama-3-70b");
        assert_eq!(&*snap.local_site, "us-east-1");
    }

    // -------------------------------------------------------------------------
    // Overlay metadata enrichment
    // -------------------------------------------------------------------------

    #[test]
    fn parse_overlay_with_all_metadata_fields() {
        let json = r#"{
            "local_site": "site-a",
            "generated_at": "2026-07-24T10:00:00Z",
            "candidates": [{
                "kind": "inference_model",
                "name": "llama-3",
                "site": "site-a",
                "cluster": "gpu-pool",
                "fresh": true,
                "stable_id": "inf/llama-3/site-a/gpu-pool",
                "admission_state": "new_and_existing",
                "selection_tier": "same_site",
                "rank": 0
            }]
        }"#;
        let snap = RouteSnapshot::from_overlay(json.as_bytes()).unwrap();
        let c = &snap.candidates[0];
        assert_eq!(&*c.stable_id, "inf/llama-3/site-a/gpu-pool");
        assert_eq!(c.admission_state, AdmissionState::NewAndExisting);
        assert_eq!(c.selection_tier.as_deref(), Some("same_site"));
        assert_eq!(c.rank, Some(0));
    }

    #[test]
    fn parse_overlay_defaults_missing_admission_state() {
        let json = r#"{
            "local_site": "site-a",
            "candidates": [{
                "kind": "inference_model",
                "name": "m",
                "site": "s",
                "cluster": "c",
                "fresh": true
            }]
        }"#;
        let snap = RouteSnapshot::from_overlay(json.as_bytes()).unwrap();
        assert_eq!(snap.candidates[0].admission_state, AdmissionState::NewAndExisting);
    }

    #[test]
    fn parse_overlay_admission_state_none_is_excluded() {
        let json = r#"{
            "local_site": "site-a",
            "candidates": [{
                "kind": "inference_model",
                "name": "m",
                "site": "s",
                "cluster": "c",
                "fresh": true,
                "admission_state": "none"
            }]
        }"#;
        let snap = RouteSnapshot::from_overlay(json.as_bytes()).unwrap();
        assert_eq!(snap.candidates[0].admission_state, AdmissionState::Excluded);
    }

    #[test]
    fn parse_overlay_unknown_admission_state_defaults() {
        let json = r#"{
            "local_site": "site-a",
            "candidates": [{
                "kind": "inference_model",
                "name": "m",
                "site": "s",
                "cluster": "c",
                "fresh": true,
                "admission_state": "future_state_v2"
            }]
        }"#;
        let snap = RouteSnapshot::from_overlay(json.as_bytes()).unwrap();
        assert_eq!(
            snap.candidates[0].admission_state,
            AdmissionState::NewAndExisting,
            "unknown admission state should default to NewAndExisting for forward compatibility"
        );
    }

    #[test]
    fn parse_overlay_stable_id_fallback() {
        let json = r#"{
            "local_site": "site-a",
            "candidates": [{
                "kind": "inference_model",
                "name": "llama",
                "site": "site-a",
                "cluster": "gpu",
                "fresh": true
            }]
        }"#;
        let snap = RouteSnapshot::from_overlay(json.as_bytes()).unwrap();
        assert_eq!(
            &*snap.candidates[0].stable_id, "inference_model/llama/site-a/gpu",
            "absent stable_id should use deterministic default"
        );
    }

    #[test]
    fn parse_overlay_existing_only_admission() {
        let json = r#"{
            "local_site": "site-a",
            "candidates": [{
                "kind": "inference_model",
                "name": "m",
                "site": "s",
                "cluster": "c",
                "fresh": true,
                "admission_state": "existing_only"
            }]
        }"#;
        let snap = RouteSnapshot::from_overlay(json.as_bytes()).unwrap();
        assert_eq!(snap.candidates[0].admission_state, AdmissionState::ExistingOnly);
    }

    #[test]
    fn parse_overlay_unknown_fields_still_accepted() {
        let json = r#"{
            "local_site": "site-a",
            "candidates": [{
                "kind": "inference_model",
                "name": "m",
                "site": "s",
                "cluster": "c",
                "fresh": true,
                "future_field": "anything",
                "another_future": 42
            }]
        }"#;
        let snap = RouteSnapshot::from_overlay(json.as_bytes());
        assert!(snap.is_ok(), "unknown fields on candidates must still be accepted");
    }

    // -------------------------------------------------------------------------
    // RouteSnapshot
    // -------------------------------------------------------------------------

    #[test]
    fn snapshot_from_overlay_valid() {
        let json = r#"{
            "local_site": "site-a",
            "candidates": [{
                "kind": "inference_model",
                "name": "llama-3",
                "site": "site-a",
                "cluster": "local-inference",
                "fresh": true
            }]
        }"#;
        let snap = RouteSnapshot::from_overlay(json.as_bytes()).unwrap();
        assert_eq!(snap.candidates.len(), 1);
        assert_eq!(&*snap.local_site, "site-a");
        assert_ne!(snap.content_hash, [0; 32]);
    }

    #[test]
    fn snapshot_from_overlay_invalid_json() {
        let result = RouteSnapshot::from_overlay(b"not json at all");
        assert!(result.is_err());
    }

    #[test]
    fn snapshot_content_hash_deterministic() {
        let json = br#"{"local_site":"a","candidates":[{"kind":"inference_model","name":"m","site":"s","cluster":"c","fresh":true}]}"#;
        let s1 = RouteSnapshot::from_overlay(json).unwrap();
        let s2 = RouteSnapshot::from_overlay(json).unwrap();
        assert_eq!(s1.content_hash, s2.content_hash);
    }

    #[test]
    fn snapshot_content_hash_differs() {
        let json_a = br#"{"local_site":"a","candidates":[{"kind":"inference_model","name":"m","site":"s","cluster":"c","fresh":true}]}"#;
        let json_b = br#"{"local_site":"b","candidates":[{"kind":"inference_model","name":"m","site":"s","cluster":"c","fresh":true}]}"#;
        let s1 = RouteSnapshot::from_overlay(json_a).unwrap();
        let s2 = RouteSnapshot::from_overlay(json_b).unwrap();
        assert_ne!(s1.content_hash, s2.content_hash);
    }

    #[test]
    fn snapshot_from_static_zero_hash() {
        let snap = RouteSnapshot::from_static(vec![], Arc::from("site-a"));
        assert_eq!(snap.content_hash, [0; 32]);
    }

    // -------------------------------------------------------------------------
    // Bounded read
    // -------------------------------------------------------------------------

    #[test]
    fn read_bounded_rejects_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.json");
        let content = vec![b'x'; (MAX_OVERLAY_SIZE + 1) as usize];
        std::fs::write(&path, &content).unwrap();
        let result = read_overlay_bounded(&path);
        assert!(result.is_err(), "oversized file must be rejected");
        assert!(result.unwrap_err().to_string().contains("exceeds"));
    }

    #[test]
    fn read_bounded_accepts_within_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ok.json");
        let json = make_overlay_json("site-a", "llama-3", "local");
        std::fs::write(&path, &json).unwrap();
        let result = read_overlay_bounded(&path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), json.as_bytes());
    }

    #[test]
    fn read_bounded_missing_file() {
        let result = read_overlay_bounded(Path::new("/nonexistent/overlay.json"));
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------------
    // Last-known-good retention (handle_overlay_reload)
    // -------------------------------------------------------------------------

    fn make_valid_snapshot() -> (Arc<ArcSwap<RouteSnapshot>>, [u8; 32]) {
        let json = make_overlay_json("site-a", "llama-3", "local");
        let snap = RouteSnapshot::from_overlay(json.as_bytes()).unwrap();
        let hash = snap.content_hash;
        (Arc::new(ArcSwap::from_pointee(snap)), hash)
    }

    #[test]
    fn retain_on_read_failure() {
        let (snap, hash) = make_valid_snapshot();
        handle_overlay_reload(Path::new("/nonexistent/overlay.json"), &snap);
        assert_eq!(snap.load().content_hash, hash);
    }

    #[test]
    fn retain_on_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");
        std::fs::write(&path, b"").unwrap();
        let (snap, hash) = make_valid_snapshot();
        handle_overlay_reload(&path, &snap);
        assert_eq!(snap.load().content_hash, hash);
    }

    #[test]
    fn retain_on_malformed_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");
        std::fs::write(&path, "{{not json}}").unwrap();
        let (snap, hash) = make_valid_snapshot();
        handle_overlay_reload(&path, &snap);
        assert_eq!(snap.load().content_hash, hash);
    }

    #[test]
    fn retain_on_blank_local_site() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");
        let json = r#"{"local_site":"","candidates":[{"kind":"inference_model","name":"m","site":"s","cluster":"c","fresh":true}]}"#;
        std::fs::write(&path, json).unwrap();
        let (snap, hash) = make_valid_snapshot();
        handle_overlay_reload(&path, &snap);
        assert_eq!(snap.load().content_hash, hash);
    }

    #[test]
    fn retain_on_empty_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");
        std::fs::write(&path, r#"{"local_site":"a","candidates":[]}"#).unwrap();
        let (snap, hash) = make_valid_snapshot();
        handle_overlay_reload(&path, &snap);
        assert_eq!(snap.load().content_hash, hash);
    }

    #[test]
    fn retain_on_unknown_kind() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");
        let json =
            r#"{"local_site":"a","candidates":[{"kind":"bad_kind","name":"m","site":"s","cluster":"c","fresh":true}]}"#;
        std::fs::write(&path, json).unwrap();
        let (snap, hash) = make_valid_snapshot();
        handle_overlay_reload(&path, &snap);
        assert_eq!(snap.load().content_hash, hash);
    }

    #[test]
    fn retain_on_oversized_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");
        let content = vec![b'x'; (MAX_OVERLAY_SIZE + 1) as usize];
        std::fs::write(&path, &content).unwrap();
        let (snap, hash) = make_valid_snapshot();
        handle_overlay_reload(&path, &snap);
        assert_eq!(snap.load().content_hash, hash);
    }

    #[test]
    fn retain_on_invalid_credential_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");
        let json = r#"{"local_site":"a","candidates":[{"kind":"inference_model","name":"m","site":"s","cluster":"c","fresh":true,"credential":{"strategy":"bearer_token","token":"leaked","secretRef":{"name":"k","namespace":"n","key":"k"}}}]}"#;
        std::fs::write(&path, json).unwrap();
        let (snap, hash) = make_valid_snapshot();
        handle_overlay_reload(&path, &snap);
        assert_eq!(snap.load().content_hash, hash);
    }

    // -------------------------------------------------------------------------
    // Watcher lifecycle
    // -------------------------------------------------------------------------

    /// Test-only startup wait for the background notify watcher.
    const WATCHER_STARTUP_MS: u64 = 750;

    fn make_overlay_json(local_site: &str, model: &str, cluster: &str) -> String {
        format!(
            r#"{{"local_site":"{local_site}","candidates":[{{"kind":"inference_model","name":"{model}","site":"{local_site}","cluster":"{cluster}","fresh":true}}]}}"#,
        )
    }

    #[test]
    fn watcher_starts_and_stops() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");
        let json = make_overlay_json("site-a", "llama-3", "local");
        std::fs::write(&path, &json).unwrap();

        let snap = Arc::new(ArcSwap::from_pointee(
            RouteSnapshot::from_overlay(json.as_bytes()).unwrap(),
        ));
        let handle = spawn_overlay_watcher(path, snap, DEFAULT_DEBOUNCE_MS);

        std::thread::sleep(Duration::from_millis(100));
        assert!(!handle.shutdown.is_cancelled(), "shutdown should not be cancelled yet");
        let start = std::time::Instant::now();
        drop(handle);
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "Drop should complete within bounded join timeout"
        );
    }

    #[test]
    fn watcher_no_thread_accumulation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");
        let json = make_overlay_json("site-a", "llama-3", "local");
        std::fs::write(&path, &json).unwrap();

        for i in 0..10 {
            let snap = Arc::new(ArcSwap::from_pointee(
                RouteSnapshot::from_overlay(json.as_bytes()).unwrap(),
            ));
            let handle = spawn_overlay_watcher(path.clone(), Arc::clone(&snap), DEFAULT_DEBOUNCE_MS);
            std::thread::sleep(Duration::from_millis(50));
            let start = std::time::Instant::now();
            drop(handle);
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "watcher {i} Drop should complete within bounded join timeout"
            );
        }
    }

    // -------------------------------------------------------------------------
    // Startup race
    // -------------------------------------------------------------------------

    #[test]
    fn watcher_catches_change_before_registration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");

        let json_v1 = make_overlay_json("site-a", "llama-3", "cluster-v1");
        std::fs::write(&path, &json_v1).unwrap();

        let initial = RouteSnapshot::from_overlay(json_v1.as_bytes()).unwrap();
        let snap = Arc::new(ArcSwap::from_pointee(initial));

        let json_v2 = make_overlay_json("site-a", "gpt-4", "cluster-v2");
        std::fs::write(&path, &json_v2).unwrap();

        let _handle = spawn_overlay_watcher(path, Arc::clone(&snap), DEFAULT_DEBOUNCE_MS);
        let v2_hash = RouteSnapshot::from_overlay(json_v2.as_bytes()).unwrap().content_hash;

        poll_until(Duration::from_secs(5), || snap.load().content_hash == v2_hash);

        assert_eq!(
            &*snap.load().candidates[0].name,
            "gpt-4",
            "watcher should catch the change that happened before registration"
        );
    }

    // -------------------------------------------------------------------------
    // Watcher reload
    // -------------------------------------------------------------------------

    #[test]
    fn watcher_detects_file_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");
        let json_v1 = make_overlay_json("site-a", "llama-3", "local");
        std::fs::write(&path, &json_v1).unwrap();

        let initial = RouteSnapshot::from_overlay(json_v1.as_bytes()).unwrap();
        let old_hash = initial.content_hash;
        let snap = Arc::new(ArcSwap::from_pointee(initial));
        let _handle = spawn_overlay_watcher(path.clone(), Arc::clone(&snap), DEFAULT_DEBOUNCE_MS);

        std::thread::sleep(Duration::from_millis(WATCHER_STARTUP_MS));

        let json_v2 = make_overlay_json("site-a", "gpt-4", "api-provider");
        std::fs::write(&path, json_v2).unwrap();

        poll_until(Duration::from_secs(5), || snap.load().content_hash != old_hash);

        let loaded = snap.load();
        assert_ne!(
            loaded.content_hash, old_hash,
            "snapshot should be swapped after file change"
        );
        assert_eq!(loaded.candidates.len(), 1);
        assert_eq!(&*loaded.candidates[0].name, "gpt-4");
    }

    #[test]
    fn watcher_skips_unchanged_content() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");
        let json = make_overlay_json("site-a", "llama-3", "local");
        std::fs::write(&path, &json).unwrap();

        let initial = RouteSnapshot::from_overlay(json.as_bytes()).unwrap();
        let snap = Arc::new(ArcSwap::from_pointee(initial));
        let _handle = spawn_overlay_watcher(path.clone(), Arc::clone(&snap), DEFAULT_DEBOUNCE_MS);

        std::thread::sleep(Duration::from_millis(WATCHER_STARTUP_MS));

        let ptr_before = Arc::as_ptr(&snap.load());
        std::fs::write(&path, &json).unwrap();
        std::thread::sleep(Duration::from_millis(DEFAULT_DEBOUNCE_MS + 300));

        let ptr_after = Arc::as_ptr(&snap.load());
        assert_eq!(
            ptr_before, ptr_after,
            "snapshot pointer should be unchanged when content is identical"
        );
    }

    #[test]
    fn watcher_survives_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grid-config.json");
        let json_v1 = make_overlay_json("site-a", "llama-3", "local");
        std::fs::write(&path, &json_v1).unwrap();

        let initial = RouteSnapshot::from_overlay(json_v1.as_bytes()).unwrap();
        let old_hash = initial.content_hash;
        let snap = Arc::new(ArcSwap::from_pointee(initial));
        let _handle = spawn_overlay_watcher(path.clone(), Arc::clone(&snap), DEFAULT_DEBOUNCE_MS);

        std::thread::sleep(Duration::from_millis(WATCHER_STARTUP_MS));

        std::fs::write(&path, "invalid json {{{{").unwrap();
        std::thread::sleep(Duration::from_millis(DEFAULT_DEBOUNCE_MS + 300));

        assert_eq!(
            snap.load().content_hash,
            old_hash,
            "snapshot should be retained after invalid JSON"
        );

        let json_v2 = make_overlay_json("site-a", "gpt-4", "api-provider");
        std::fs::write(&path, json_v2).unwrap();

        poll_until(Duration::from_secs(5), || snap.load().content_hash != old_hash);

        let loaded = snap.load();
        assert_ne!(
            loaded.content_hash, old_hash,
            "snapshot should recover after valid JSON"
        );
        assert_eq!(&*loaded.candidates[0].name, "gpt-4");
    }

    // -------------------------------------------------------------------------
    // Symlink swap (Kubernetes AtomicWriter pattern)
    // -------------------------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn watcher_detects_symlink_swap() {
        let dir = tempfile::tempdir().unwrap();
        let data_v1 = dir.path().join("data_v1");
        let data_v2 = dir.path().join("data_v2");
        std::fs::create_dir_all(&data_v1).unwrap();
        std::fs::create_dir_all(&data_v2).unwrap();

        let json_v1 = make_overlay_json("site-a", "llama-3", "local");
        let json_v2 = make_overlay_json("site-a", "gpt-4", "api-provider");
        std::fs::write(data_v1.join("config.json"), &json_v1).unwrap();
        std::fs::write(data_v2.join("config.json"), &json_v2).unwrap();

        let data_link = dir.path().join("..data");
        std::os::unix::fs::symlink(&data_v1, &data_link).unwrap();
        let overlay_path = dir.path().join("grid-config.json");
        std::os::unix::fs::symlink("..data/config.json", &overlay_path).unwrap();

        let initial = RouteSnapshot::from_overlay(json_v1.as_bytes()).unwrap();
        let old_hash = initial.content_hash;
        let snap = Arc::new(ArcSwap::from_pointee(initial));
        let _handle = spawn_overlay_watcher(overlay_path, Arc::clone(&snap), DEFAULT_DEBOUNCE_MS);

        std::thread::sleep(Duration::from_millis(WATCHER_STARTUP_MS));

        let tmp_link = dir.path().join("..data_tmp");
        std::os::unix::fs::symlink(&data_v2, &tmp_link).unwrap();
        std::fs::rename(&tmp_link, &data_link).unwrap();

        poll_until(Duration::from_secs(5), || snap.load().content_hash != old_hash);
        assert_eq!(&*snap.load().candidates[0].name, "gpt-4");
    }

    // -------------------------------------------------------------------------
    // Event kind helpers
    // -------------------------------------------------------------------------

    #[test]
    fn is_relevant_event_create() {
        assert!(
            is_relevant_event(EventKind::Create(notify::event::CreateKind::File)),
            "Create events should be relevant"
        );
    }

    #[test]
    fn is_relevant_event_modify_name() {
        assert!(
            is_relevant_event(EventKind::Modify(notify::event::ModifyKind::Name(
                notify::event::RenameMode::Any
            ))),
            "Modify(Name) events should be relevant (covers renames)"
        );
    }

    #[test]
    fn is_relevant_event_remove() {
        assert!(
            is_relevant_event(EventKind::Remove(notify::event::RemoveKind::File)),
            "Remove events should be relevant"
        );
    }

    #[test]
    fn is_relevant_event_access_not_relevant() {
        assert!(
            !is_relevant_event(EventKind::Access(notify::event::AccessKind::Read)),
            "Access events should not be relevant"
        );
    }

    // -------------------------------------------------------------------------
    // Watch directory resolution
    // -------------------------------------------------------------------------

    #[test]
    fn watch_dir_for_path_bare_filename() {
        assert_eq!(
            watch_dir_for_path(Path::new("grid-config.json")),
            PathBuf::from("."),
            "bare filename should resolve to current directory"
        );
    }

    #[test]
    fn watch_dir_for_path_with_directory() {
        assert_eq!(
            watch_dir_for_path(Path::new("/etc/grid/grid-config.json")),
            PathBuf::from("/etc/grid"),
            "absolute path should use its parent directory"
        );
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /// Poll `predicate` every 20ms until it returns `true` or `timeout` elapses.
    fn poll_until(timeout: Duration, predicate: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if predicate() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("poll_until timed out after {timeout:?}");
    }
}
