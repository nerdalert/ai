// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Server bootstrap for Praxis AI.

pub(crate) mod pipelines;
pub(crate) mod reload;
mod server;
pub(crate) mod watcher;
pub use pipelines::resolve_pipelines;
pub use praxis_core::{config::load_config, logging::init_tracing};
pub use server::{check_root_privilege, fatal, resolve_config_path, run_server, run_server_with_registry};

// -----------------------------------------------------------------------------
// External Filter Discovery
// -----------------------------------------------------------------------------

// Provides: fn register_external_filters(&mut FilterRegistry)
include!(concat!(env!("OUT_DIR"), "/external_filters.rs"));

/// Build a [`FilterRegistry`] with core builtins, AI filters, and
/// auto-discovered external filters.
///
/// [`FilterRegistry`]: praxis_filter::FilterRegistry
#[must_use]
pub fn build_full_registry() -> praxis_filter::FilterRegistry {
    let mut registry = praxis_filter::FilterRegistry::with_builtins();
    register_ai_filters(&mut registry);
    register_external_filters(&mut registry);
    registry
}

/// Register all AI filters into the registry.
fn register_ai_filters(registry: &mut praxis_filter::FilterRegistry) {
    register_agentic_filters(registry);
    register_general_ai_filters(registry);
    register_anthropic_filters(registry);
    register_openai_filters(registry);
    register_grid_filters(registry);
}

/// Register Grid edge and provider-hop filters.
///
/// These belong in the AI proxy (not Praxis core) because they encode
/// AI/Grid-specific selection, provider-local policy, and credential-reference
/// semantics.
fn register_grid_filters(registry: &mut praxis_filter::FilterRegistry) {
    praxis_filter::register_filters!(
        @register registry,
        http "grid_route" => praxis_ai_filters::GridRouteFilter::from_config
    );
    register_grid_security_filter(
        registry,
        "grid_provider_route",
        praxis_ai_filters::GridProviderRouteFilter::from_config,
    );
    register_grid_security_filter(
        registry,
        "grid_credential_inject",
        praxis_ai_filters::GridCredentialInjectFilter::from_config,
    );
}

/// Register a Grid HTTP filter as security-critical.
#[expect(
    clippy::type_complexity,
    reason = "single-use registration helper; a type alias adds indirection"
)]
#[expect(clippy::panic, reason = "duplicate filter registration is a fatal configuration bug")]
fn register_grid_security_filter(
    registry: &mut praxis_filter::FilterRegistry,
    name: &'static str,
    factory: fn(&serde_yaml::Value) -> Result<Box<dyn praxis_filter::HttpFilter>, praxis_filter::FilterError>,
) {
    registry
        .register_with_class(
            name,
            praxis_filter::FilterFactory::Http(std::sync::Arc::new(factory)),
            praxis_filter::SecurityClass::Security,
        )
        .unwrap_or_else(|_| panic!("duplicate filter name: '{name}'"));
}

/// Register agentic protocol filters (A2A, MCP).
fn register_agentic_filters(registry: &mut praxis_filter::FilterRegistry) {
    praxis_filter::register_filters!(
        @register registry,
        http "a2a" => praxis_ai_filters::A2aFilter::from_config
    );
    praxis_filter::register_filters!(
        @register registry,
        http "mcp" => praxis_ai_filters::McpFilter::from_config
    );
}

/// Register general-purpose AI filters.
fn register_general_ai_filters(registry: &mut praxis_filter::FilterRegistry) {
    praxis_filter::register_filters!(
        @register registry,
        http "ai_guardrails" => praxis_ai_filters::AiGuardrailsFilter::from_config
    );
    praxis_filter::register_filters!(
        @register registry,
        http "model_to_header" => praxis_ai_filters::ModelToHeaderFilter::from_config
    );
    praxis_filter::register_filters!(
        @register registry,
        http "prompt_enrich" => praxis_ai_filters::PromptEnrichFilter::from_config
    );
    praxis_filter::register_filters!(
        @register registry,
        http "token_count" => praxis_ai_filters::TokenCountFilter::from_config
    );
    praxis_filter::register_filters!(
        @register registry,
        http "token_usage_headers" => praxis_ai_filters::TokenUsageHeadersFilter::from_config
    );
}

/// Register Anthropic-specific filters.
fn register_anthropic_filters(registry: &mut praxis_filter::FilterRegistry) {
    praxis_filter::register_filters!(
        @register registry,
        http "anthropic_messages_format" => praxis_ai_apis::anthropic::AnthropicMessagesFormatFilter::from_config
    );
    praxis_filter::register_filters!(
        @register registry,
        http "anthropic_messages_protocol" => praxis_ai_apis::anthropic::AnthropicMessagesProtocolFilter::from_config
    );
    praxis_filter::register_filters!(
        @register registry,
        http "anthropic_stream_events" => praxis_ai_apis::anthropic::AnthropicStreamEventsFilter::from_config
    );
    praxis_filter::register_filters!(
        @register registry,
        http "anthropic_to_openai" => praxis_ai_apis::anthropic::AnthropicToOpenaiFilter::from_config
    );
    praxis_filter::register_filters!(
        @register registry,
        http "anthropic_validate" => praxis_ai_apis::anthropic::AnthropicValidateFilter::from_config
    );
}

/// Register OpenAI Responses API request-path filters.
fn register_openai_filters(registry: &mut praxis_filter::FilterRegistry) {
    register_openai_responses_filters(registry);
    praxis_filter::register_filters!(
        @register registry,
        http "openai_conversations" => praxis_ai_apis::openai::OpenaiConversationsFilter::from_config
    );
}

/// Register OpenAI Responses API filters.
fn register_openai_responses_filters(registry: &mut praxis_filter::FilterRegistry) {
    praxis_filter::register_filters!(
        @register registry,
        http "openai_doc_extract" => praxis_ai_apis::openai::DocExtractFilter::from_config
    );
    praxis_filter::register_filters!(
        @register registry,
        http "openai_file_resolve" => praxis_ai_apis::openai::FileResolveFilter::from_config
    );
    praxis_filter::register_filters!(
        @register registry,
        http "openai_responses_format" => praxis_ai_apis::openai::ResponsesFormatFilter::from_config
    );
    praxis_filter::register_filters!(
        @register registry,
        http "openai_responses_model_rewrite" => praxis_ai_apis::openai::ModelRewriteFilter::from_config
    );
    praxis_filter::register_filters!(
        @register registry,
        http "openai_responses_validate" => praxis_ai_apis::openai::OpenaiResponsesValidateFilter::from_config
    );
    praxis_filter::register_filters!(
        @register registry,
        http "openai_responses_rehydrate" => praxis_ai_apis::openai::RehydrateFilter::from_config
    );
    register_openai_response_filters(registry);
}

/// Register OpenAI Responses API response-path and persistence filters.
fn register_openai_response_filters(registry: &mut praxis_filter::FilterRegistry) {
    praxis_filter::register_filters!(
        @register registry,
        http "openai_response_store" => praxis_ai_apis::openai::ResponseStoreFilter::from_config
    );
    praxis_filter::register_filters!(
        @register registry,
        http "openai_stream_events" => praxis_ai_apis::openai::OpenaiStreamEventsFilter::from_config
    );
    praxis_filter::register_filters!(
        @register registry,
        http "openai_responses_proxy" => praxis_ai_apis::openai::ResponsesProxyFilter::from_config
    );
    praxis_filter::register_filters!(
        @register registry,
        http "openai_mcp_tool_resolve" => praxis_ai_apis::openai::McpToolResolveFilter::from_config
    );
    praxis_filter::register_filters!(
        @register registry,
        http "openai_tool_parse" => praxis_ai_apis::openai::ToolParseFilter::from_config
    );
    praxis_filter::register_filters!(
        @register registry,
        http "openai_web_search" => praxis_ai_apis::openai::WebSearchFilter::from_config
    );
    praxis_filter::register_filters!(
        @register registry,
        http "openai_mcp_dispatch" => praxis_ai_apis::openai::McpDispatchFilter::from_config
    );
}

#[cfg(test)]
#[expect(clippy::allow_attributes, reason = "blanket test suppressions")]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines,
    clippy::unwrap_used,
    reason = "tests"
)]
mod tests {
    use super::*;

    #[test]
    fn grid_filters_are_registered_exactly_once() {
        let registry = build_full_registry();
        let names = registry.available_filters();
        for expected in ["grid_route", "grid_provider_route", "grid_credential_inject"] {
            assert_eq!(
                names.iter().filter(|name| **name == expected).count(),
                1,
                "{expected} must be registered exactly once"
            );
        }
        assert!(!registry.is_security_filter("grid_route"));
        assert!(registry.is_security_filter("grid_provider_route"));
        assert!(registry.is_security_filter("grid_credential_inject"));
    }

    #[test]
    fn provider_pipeline_filters_construct_from_registry() {
        let registry = build_full_registry();
        let peer_config = serde_yaml::from_str(
            "trusted_peers:\n\
             \x20 - cert_digest: 0000000000000000000000000000000000000000000000000000000000000000\n\
             \x20   organization: ai-grid\n",
        )
        .expect("peer config");
        let provider_route_config = serde_yaml::from_str(
            "provider_id: site-a\n\
             routes:\n\
             \x20 - candidate_id: candidate-a\n\
             \x20   cluster: backend\n\
             \x20   model: model-a\n\
             \x20   paths: [/v1/chat/completions]\n",
        )
        .expect("provider route config");
        let credential_config = serde_yaml::from_str(
            "credentials:\n\
             \x20 - name: provider-token\n\
             \x20   namespace: grid-system\n\
             \x20   key: token\n\
             \x20   value: test-only-token\n",
        )
        .expect("credential config");

        for (name, config) in [
            ("peer_identity_trust", &peer_config),
            ("grid_provider_route", &provider_route_config),
            ("grid_credential_inject", &credential_config),
        ] {
            registry
                .create(name, config)
                .unwrap_or_else(|error| panic!("{name} must construct from the full registry: {error}"));
        }
    }
}
