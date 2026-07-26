// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Final-hop credential injection for a Grid-selected route.
//!
//! The provider gateway resolves configured references once at construction
//! and overwrites `Authorization` after `grid_route` or
//! `grid_provider_route` has selected a configured reference. Token values
//! never travel in the Grid overlay or peer headers.

use std::{collections::HashMap, fs::File, io::Read as _};

use async_trait::async_trait;
use http::{HeaderValue, header::AUTHORIZATION};
use praxis_filter::{FilterAction, FilterError, HttpFilter, HttpFilterContext, Rejection, parse_filter_config};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::metadata::{
    CREDENTIAL_KEY, CREDENTIAL_NAME, CREDENTIAL_NAMESPACE, CREDENTIAL_STRATEGY, STRATEGY_BEARER_TOKEN,
};

/// Maximum credential references accepted by one filter instance.
const MAX_CREDENTIALS: usize = 1024;

/// Maximum byte length for a credential reference component.
const MAX_REFERENCE_LEN: usize = 256;

/// Maximum byte length for an environment variable name or file path.
const MAX_SOURCE_LEN: usize = 4096;

/// Maximum raw credential size accepted from any source.
const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// Maximum bytes read to distinguish an exact-limit file from an oversized one.
const MAX_TOKEN_READ_BYTES: u64 = 16 * 1024 + 1;

/// Deserialized configuration for the `grid_credential_inject` filter.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GridCredentialInjectConfig {
    /// Credential entries to resolve at construction time.
    credentials: Vec<CredentialEntryConfig>,
}

/// A single credential entry within the filter configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialEntryConfig {
    /// Secret name.
    name: String,
    /// Secret namespace.
    namespace: String,
    /// Secret data key.
    key: String,
    /// Injection strategy (default: `bearer_token`).
    #[serde(default = "default_strategy")]
    strategy: String,
    /// Development-only inline source. Kubernetes deployments should use
    /// `file` with a Secret volume.
    value: Option<String>,
    /// Development-only environment source.
    env_var: Option<String>,
    /// Secret-volume file, read once when the filter is constructed.
    file: Option<String>,
}

/// Returns the default credential injection strategy.
fn default_strategy() -> String {
    STRATEGY_BEARER_TOKEN.to_owned()
}

/// Locator triple for a Kubernetes Secret data key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct CredentialRef {
    /// Secret name.
    name: String,
    /// Secret namespace.
    namespace: String,
    /// Secret data key.
    key: String,
}

/// A credential resolved at construction time, ready for injection.
struct ResolvedCredential {
    /// Pre-formatted `Bearer <token>` header value.
    header_value: Zeroizing<String>,
}

/// Replaces customer authorization with the selected provider credential.
pub struct GridCredentialInjectFilter {
    /// Resolved credential map keyed by Secret locator.
    credentials: HashMap<CredentialRef, ResolvedCredential>,
}

impl GridCredentialInjectFilter {
    /// Resolve the configured credential map without adding Kubernetes API
    /// access to the request path.
    ///
    /// # Errors
    ///
    /// Returns an error if credentials are empty, duplicated, use an
    /// unsupported strategy, or cannot be resolved from their source.
    pub fn from_config(config: &serde_yaml::Value) -> Result<Box<dyn HttpFilter>, FilterError> {
        let cfg: GridCredentialInjectConfig = parse_filter_config("grid_credential_inject", config)?;
        if cfg.credentials.is_empty() || cfg.credentials.len() > MAX_CREDENTIALS {
            return Err(format!("grid_credential_inject: credentials must contain 1-{MAX_CREDENTIALS} entries").into());
        }

        let mut credentials = HashMap::with_capacity(cfg.credentials.len());
        for entry in &cfg.credentials {
            if entry.strategy != STRATEGY_BEARER_TOKEN {
                return Err("grid_credential_inject: unsupported credential strategy".into());
            }
            validate_ref(entry)?;
            let credential = resolve_credential(entry)?;
            let credential_ref = CredentialRef {
                name: entry.name.clone(),
                namespace: entry.namespace.clone(),
                key: entry.key.clone(),
            };
            if credentials.insert(credential_ref, credential).is_some() {
                return Err("grid_credential_inject: duplicate credential reference".into());
            }
        }
        Ok(Box::new(Self { credentials }))
    }
}

#[async_trait]
impl HttpFilter for GridCredentialInjectFilter {
    fn name(&self) -> &'static str {
        "grid_credential_inject"
    }

    async fn on_request(&self, ctx: &mut HttpFilterContext<'_>) -> Result<FilterAction, FilterError> {
        let Some(name) = ctx.get_metadata(CREDENTIAL_NAME).map(str::to_owned) else {
            return Ok(FilterAction::Continue);
        };
        let namespace = ctx.get_metadata(CREDENTIAL_NAMESPACE).unwrap_or("").to_owned();
        let key = ctx.get_metadata(CREDENTIAL_KEY).unwrap_or("").to_owned();
        let strategy = ctx.get_metadata(CREDENTIAL_STRATEGY).unwrap_or("").to_owned();
        if strategy != STRATEGY_BEARER_TOKEN {
            return Ok(FilterAction::Reject(Rejection::status(503)));
        }

        let credential_ref = CredentialRef { name, namespace, key };
        let Some(credential) = self.credentials.get(&credential_ref) else {
            tracing::warn!(
                name = %credential_ref.name,
                namespace = %credential_ref.namespace,
                key = %credential_ref.key,
                "grid_credential_inject: provider credential reference is not configured"
            );
            return Ok(FilterAction::Reject(Rejection::status(503)));
        };

        let header_value = HeaderValue::from_str(credential.header_value.as_str())
            .map_err(|e| FilterError::from(format!("grid_credential_inject: invalid resolved header: {e}")))?;
        ctx.request_headers_to_remove.push(AUTHORIZATION);
        ctx.request_headers_to_set.push((AUTHORIZATION, header_value));
        Ok(FilterAction::Continue)
    }
}

/// Reject entries with blank locator fields.
fn validate_ref(entry: &CredentialEntryConfig) -> Result<(), FilterError> {
    validate_bounded("name", &entry.name, MAX_REFERENCE_LEN)?;
    validate_bounded("namespace", &entry.namespace, MAX_REFERENCE_LEN)?;
    validate_bounded("key", &entry.key, MAX_REFERENCE_LEN)?;
    Ok(())
}

/// Read the credential token from exactly one of `value`, `env_var`, or `file`.
fn resolve_credential(entry: &CredentialEntryConfig) -> Result<ResolvedCredential, FilterError> {
    let token = match (&entry.value, &entry.env_var, &entry.file) {
        (Some(value), None, None) => {
            validate_token(value)?;
            Zeroizing::new(value.clone())
        },
        (None, Some(variable), None) => {
            validate_bounded("env_var", variable, MAX_SOURCE_LEN)?;
            Zeroizing::new(std::env::var(variable).map_err(|e| -> FilterError {
                format!("grid_credential_inject: environment source {variable} is unavailable: {e}").into()
            })?)
        },
        (None, None, Some(path)) => {
            validate_bounded("file", path, MAX_SOURCE_LEN)?;
            read_token_file(path)?
        },
        _ => {
            return Err(
                "grid_credential_inject: configure exactly one of value, env_var, or file per credential".into(),
            );
        },
    };
    validate_token(&token)?;
    let header_value = Zeroizing::new(format!("Bearer {}", token.as_str()));
    HeaderValue::from_str(header_value.as_str())
        .map_err(|e| -> FilterError { format!("grid_credential_inject: invalid bearer credential: {e}").into() })?;
    Ok(ResolvedCredential { header_value })
}

/// Read a credential file with a hard allocation bound.
fn read_token_file(path: &str) -> Result<Zeroizing<String>, FilterError> {
    let file = File::open(path).map_err(|e| -> FilterError {
        format!("grid_credential_inject: cannot open credential file {path}: {e}").into()
    })?;
    let mut value = Zeroizing::new(String::new());
    file.take(MAX_TOKEN_READ_BYTES)
        .read_to_string(&mut value)
        .map_err(|e| -> FilterError {
            format!("grid_credential_inject: cannot read credential file {path}: {e}").into()
        })?;
    if value.len() > MAX_TOKEN_BYTES {
        return Err(format!("grid_credential_inject: credential file {path} exceeds {MAX_TOKEN_BYTES} bytes").into());
    }
    Ok(Zeroizing::new(value.trim().to_owned()))
}

/// Validate a non-blank bounded configuration value.
fn validate_bounded(field: &str, value: &str, maximum: usize) -> Result<(), FilterError> {
    if value.trim().is_empty() || value.len() > maximum {
        return Err(format!("grid_credential_inject: {field} must be non-blank and at most {maximum} bytes").into());
    }
    Ok(())
}

/// Validate a resolved token before constructing an HTTP header.
fn validate_token(token: &str) -> Result<(), FilterError> {
    if token.trim().is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(
            format!("grid_credential_inject: resolved credential must contain 1-{MAX_TOKEN_BYTES} bytes").into(),
        );
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "tests"
)]
mod tests {
    use http::Method;

    use super::*;
    use crate::test_utils;

    fn credential_yaml(name: &str, namespace: &str, key: &str, value: &str) -> String {
        format!("credentials:\n  - name: {name}\n    namespace: {namespace}\n    key: {key}\n    value: \"{value}\"\n")
    }

    fn make_inject_filter(name: &str, namespace: &str, key: &str, value: &str) -> Box<dyn HttpFilter> {
        let yaml = credential_yaml(name, namespace, key, value);
        let val: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        GridCredentialInjectFilter::from_config(&val).unwrap()
    }

    fn set_cred_metadata(ctx: &mut HttpFilterContext<'_>, name: &str, ns: &str, key: &str) {
        ctx.set_metadata(CREDENTIAL_STRATEGY, STRATEGY_BEARER_TOKEN);
        ctx.set_metadata(CREDENTIAL_NAME, name);
        ctx.set_metadata(CREDENTIAL_NAMESPACE, ns);
        ctx.set_metadata(CREDENTIAL_KEY, key);
    }

    // ---- Construction validation ----

    #[test]
    fn empty_credentials_rejected() {
        let yaml = "credentials: []\n";
        let val: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        assert!(GridCredentialInjectFilter::from_config(&val).is_err());
    }

    #[test]
    fn too_many_credentials_rejected() {
        let entries = (0..=MAX_CREDENTIALS)
            .map(|i| format!("  - name: s{i}\n    namespace: ns\n    key: k\n    value: tok\n"))
            .collect::<String>();
        let val: serde_yaml::Value = serde_yaml::from_str(&format!("credentials:\n{entries}")).unwrap();
        assert!(GridCredentialInjectFilter::from_config(&val).is_err());
    }

    #[test]
    fn duplicate_credential_ref_rejected() {
        let yaml = concat!(
            "credentials:\n",
            "  - name: s1\n    namespace: ns\n    key: k\n    value: tok1\n",
            "  - name: s1\n    namespace: ns\n    key: k\n    value: tok2\n",
        );
        let val: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let result = GridCredentialInjectFilter::from_config(&val);
        assert!(result.is_err(), "duplicate credential ref must be rejected");
    }

    #[test]
    fn unsupported_strategy_rejected_at_construction() {
        let yaml = "credentials:\n  - name: s1\n    namespace: ns\n    key: k\n    strategy: api_key\n    value: tok\n";
        let val: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let result = GridCredentialInjectFilter::from_config(&val);
        assert!(result.is_err(), "unsupported strategy must be rejected");
    }

    #[test]
    fn blank_name_rejected() {
        let yaml = "credentials:\n  - name: ''\n    namespace: ns\n    key: k\n    value: tok\n";
        let val: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        assert!(GridCredentialInjectFilter::from_config(&val).is_err());
    }

    #[test]
    fn blank_namespace_rejected() {
        let yaml = "credentials:\n  - name: s1\n    namespace: ''\n    key: k\n    value: tok\n";
        let val: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        assert!(GridCredentialInjectFilter::from_config(&val).is_err());
    }

    #[test]
    fn blank_key_rejected() {
        let yaml = "credentials:\n  - name: s1\n    namespace: ns\n    key: ''\n    value: tok\n";
        let val: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        assert!(GridCredentialInjectFilter::from_config(&val).is_err());
    }

    #[test]
    fn oversized_reference_rejected() {
        let name = "n".repeat(MAX_REFERENCE_LEN + 1);
        let yaml = credential_yaml(&name, "ns", "k", "tok");
        let val: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert!(GridCredentialInjectFilter::from_config(&val).is_err());
    }

    #[test]
    fn empty_value_rejected() {
        let yaml = "credentials:\n  - name: s1\n    namespace: ns\n    key: k\n    value: ''\n";
        let val: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        assert!(GridCredentialInjectFilter::from_config(&val).is_err());
    }

    #[test]
    fn oversized_value_rejected() {
        let token = "t".repeat(MAX_TOKEN_BYTES + 1);
        let yaml = credential_yaml("s1", "ns", "k", &token);
        let val: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert!(GridCredentialInjectFilter::from_config(&val).is_err());
    }

    #[test]
    fn multiple_sources_rejected() {
        let yaml = "credentials:\n  - name: s1\n    namespace: ns\n    key: k\n    value: tok\n    env_var: FOO\n";
        let val: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let result = GridCredentialInjectFilter::from_config(&val);
        assert!(result.is_err(), "multiple sources must be rejected");
    }

    #[test]
    fn no_source_rejected() {
        let yaml = "credentials:\n  - name: s1\n    namespace: ns\n    key: k\n";
        let val: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        assert!(GridCredentialInjectFilter::from_config(&val).is_err());
    }

    #[test]
    fn valid_value_source_accepted() {
        let f = make_inject_filter("s1", "ns", "k", "my-secret-token");
        assert_eq!(f.name(), "grid_credential_inject");
    }

    #[test]
    fn file_source_resolved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "  file-token  \n").unwrap();
        let yaml = format!(
            "credentials:\n  - name: s1\n    namespace: ns\n    key: k\n    file: \"{}\"\n",
            path.display()
        );
        let val: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let f = GridCredentialInjectFilter::from_config(&val).unwrap();
        assert_eq!(f.name(), "grid_credential_inject");
    }

    #[test]
    fn oversized_file_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, vec![b't'; MAX_TOKEN_BYTES + 1]).unwrap();
        let yaml = format!(
            "credentials:\n  - name: s1\n    namespace: ns\n    key: k\n    file: \"{}\"\n",
            path.display()
        );
        let val: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert!(GridCredentialInjectFilter::from_config(&val).is_err());
    }

    #[test]
    fn missing_env_var_rejected_without_mutating_process_environment() {
        let yaml = concat!(
            "credentials:\n",
            "  - name: s1\n",
            "    namespace: ns\n",
            "    key: k\n",
            "    env_var: PRAXIS_GRID_TEST_INTENTIONALLY_UNDEFINED_7E9D09E4\n",
        );
        let val: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        assert!(GridCredentialInjectFilter::from_config(&val).is_err());
    }

    // ---- Runtime behavior ----

    #[tokio::test]
    async fn no_credential_metadata_continues_without_modification() {
        let f = make_inject_filter("s1", "ns", "k", "tok");
        let req = test_utils::make_request(Method::POST, "/v1/chat/completions");
        let mut ctx = test_utils::make_filter_context(&req);
        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
        assert!(
            ctx.request_headers_to_set.is_empty(),
            "no credential metadata means no Authorization modification"
        );
    }

    #[tokio::test]
    async fn valid_credential_replaces_authorization() {
        let f = make_inject_filter("s1", "ns", "k", "my-secret");
        let mut req = test_utils::make_request(Method::POST, "/v1/chat/completions");
        req.headers
            .insert(AUTHORIZATION, HeaderValue::from_static("Bearer customer-token"));
        let mut ctx = test_utils::make_filter_context(&req);
        set_cred_metadata(&mut ctx, "s1", "ns", "k");
        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(matches!(action, FilterAction::Continue));
        assert!(
            ctx.request_headers_to_remove.contains(&AUTHORIZATION),
            "must remove old Authorization"
        );
        let new_auth = ctx.request_headers_to_set.iter().find(|(h, _)| h == AUTHORIZATION);
        assert!(new_auth.is_some(), "must set new Authorization");
        assert_eq!(
            new_auth.unwrap().1.to_str().unwrap(),
            "Bearer my-secret",
            "must set resolved provider credential"
        );
    }

    #[tokio::test]
    async fn unknown_credential_ref_rejected_503() {
        let f = make_inject_filter("s1", "ns", "k", "tok");
        let req = test_utils::make_request(Method::POST, "/v1/chat/completions");
        let mut ctx = test_utils::make_filter_context(&req);
        set_cred_metadata(&mut ctx, "other-secret", "ns", "k");
        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 503),
            "unknown credential ref must be rejected 503"
        );
    }

    #[tokio::test]
    async fn unsupported_strategy_at_runtime_rejected_503() {
        let f = make_inject_filter("s1", "ns", "k", "tok");
        let req = test_utils::make_request(Method::POST, "/v1/chat/completions");
        let mut ctx = test_utils::make_filter_context(&req);
        ctx.set_metadata(CREDENTIAL_STRATEGY, "api_key");
        ctx.set_metadata(CREDENTIAL_NAME, "s1");
        ctx.set_metadata(CREDENTIAL_NAMESPACE, "ns");
        ctx.set_metadata(CREDENTIAL_KEY, "k");
        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 503),
            "unsupported strategy at runtime must be rejected 503"
        );
    }

    #[tokio::test]
    async fn incomplete_credential_metadata_rejected_503() {
        let f = make_inject_filter("s1", "ns", "k", "tok");
        let req = test_utils::make_request(Method::POST, "/v1/chat/completions");
        let mut ctx = test_utils::make_filter_context(&req);
        ctx.set_metadata(CREDENTIAL_STRATEGY, STRATEGY_BEARER_TOKEN);
        ctx.set_metadata(CREDENTIAL_NAME, "s1");
        let action = f.on_request(&mut ctx).await.unwrap();
        assert!(
            matches!(action, FilterAction::Reject(r) if r.status == 503),
            "partial credential metadata must fail closed"
        );
    }
}
