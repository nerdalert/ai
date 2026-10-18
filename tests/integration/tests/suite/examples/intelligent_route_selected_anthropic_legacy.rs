// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Praxis Contributors

//! Functional coverage for the selected-provider OpenAI-client legacy path.

use std::path::Path;

use openssl::hash::{MessageDigest, hash};
use praxis_core::config::Config;
use praxis_test_utils::{
    CapturedRequest, StatefulCapturingBackend, example_config_path, free_port, http_send, parse_body, parse_status,
    start_proxy,
};
use serde_json::{Value, json};

const EXAMPLE: &str = "openai-selected-provider-legacy-translation.yaml";
const OVERLAY_PATH: &str = "/etc/praxis/routing/routing-overlay.json";
const CREDENTIALS_PATH: &str = "/run/secrets/provider-credentials";
const ANTHROPIC_EVENTS: &str = concat!(
    "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_live\",\"usage\":{\"input_tokens\":3}}}\n\n",
    "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
    "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"progressive answer\"}}\n\n",
    "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":4}}\n\n",
    "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
);

const ANTHROPIC_JSON: &str = r#"{"type":"message","id":"msg_selected","role":"assistant","model":"claude-target","content":[{"type":"text","text":"anthropic selected"}],"stop_reason":"end_turn","usage":{"input_tokens":3,"output_tokens":2}}"#;
const OPENAI_JSON: &str = r#"{"id":"chatcmpl-openai","object":"chat.completion","model":"gpt-target","choices":[{"index":0,"message":{"role":"assistant","content":"openai passthrough"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}"#;

#[test]
fn selected_anthropic_and_openai_candidates_keep_distinct_request_profiles() {
    let anthropic = StatefulCapturingBackend::new(vec![(200, ANTHROPIC_JSON.to_owned())]).start_with_shutdown();
    let openai = StatefulCapturingBackend::new(vec![(200, OPENAI_JSON.to_owned())]).start_with_shutdown();
    let temp = tempfile::tempdir().expect("create temporary overlay and credentials");
    let overlay_path = temp.path().join("routing-overlay.json");
    std::fs::write(&overlay_path, provider_overlay(false)).expect("write content-addressed selected provider overlay");
    mount_secret(
        temp.path(),
        "grid-demo",
        "anthropic-secret",
        "api-key",
        "anthropic-test-key",
    );
    mount_secret(temp.path(), "grid-demo", "openai-secret", "token", "openai-test-token");

    let config = Config::from_yaml(&example_yaml(
        free_port(),
        &overlay_path,
        temp.path(),
        anthropic.port(),
        openai.port(),
    ))
    .expect("example pipeline must parse with a trusted provider profile");
    let proxy = start_proxy(&config);
    let request = chat_request(false);
    let first = http_send(proxy.addr(), &request);
    let second = http_send(proxy.addr(), &request);
    assert_eq!(parse_status(&first), 200, "first selected provider request: {first}");
    assert_eq!(parse_status(&second), 200, "second selected provider request: {second}");

    let first_body = parse_body(&first);
    let second_body = parse_body(&second);
    assert!(first_body.contains("anthropic selected") || second_body.contains("anthropic selected"));
    assert!(first_body.contains("openai passthrough") || second_body.contains("openai passthrough"));

    let messages_request = post_request(&anthropic.requests());
    assert_eq!(messages_request.uri, "/v1/messages");
    let messages_body: Value = serde_json::from_str(&messages_request.body).expect("translated Messages JSON");
    assert_eq!(messages_body["model"], "claude-target");
    assert_eq!(messages_body["messages"][0]["content"][0]["text"], "hi");
    assert!(
        messages_request
            .headers
            .to_ascii_lowercase()
            .contains("x-api-key: anthropic-test-key")
    );
    assert!(
        !messages_request
            .headers
            .to_ascii_lowercase()
            .contains("authorization: bearer caller-key")
    );
    assert!(
        !messages_request
            .headers
            .to_ascii_lowercase()
            .contains("x-api-key: caller-key")
    );

    let openai_request = post_request(&openai.requests());
    assert_eq!(openai_request.uri, "/v1/chat/completions");
    let openai_body: Value = serde_json::from_str(&openai_request.body).expect("pass-through Chat Completions JSON");
    assert_eq!(openai_body["model"], "gpt-target");
    assert_eq!(openai_body["messages"][0]["content"], "hi");
    assert!(
        openai_request
            .headers
            .to_ascii_lowercase()
            .contains("authorization: bearer openai-test-token")
    );
    assert!(!openai_request.body.contains("openai-test-token"));
}

#[test]
fn selected_anthropic_sse_is_converted_incrementally_to_openai_sse() {
    let backend = StatefulCapturingBackend::new(vec![(200, ANTHROPIC_EVENTS.to_owned())]).start_with_shutdown();
    let temp = tempfile::tempdir().expect("create temporary overlay and credentials");
    let overlay_path = temp.path().join("routing-overlay.json");
    std::fs::write(&overlay_path, provider_overlay(true)).expect("write content-addressed selected provider overlay");
    mount_secret(
        temp.path(),
        "grid-demo",
        "anthropic-secret",
        "api-key",
        "anthropic-test-key",
    );
    let config = Config::from_yaml(&example_yaml(
        free_port(),
        &overlay_path,
        temp.path(),
        backend.port(),
        backend.port(),
    ))
    .expect("example pipeline must parse");
    let proxy = start_proxy(&config);

    let response = http_send(proxy.addr(), &chat_request(true));
    assert_eq!(parse_status(&response), 200, "streaming provider request: {response}");
    assert!(
        response
            .to_ascii_lowercase()
            .contains("content-type: text/event-stream")
    );
    let body = parse_body(&response);
    assert!(
        body.contains("progressive answer"),
        "translated stream must carry text: {body}"
    );
    assert!(
        body.contains("chat.completion.chunk"),
        "translated stream must use Chat Completions events: {body}"
    );
    assert!(
        body.contains("data: [DONE]"),
        "translated stream must terminate: {body}"
    );
    let upstream = post_request(&backend.requests());
    assert_eq!(upstream.uri, "/v1/messages");
    let upstream_body: Value = serde_json::from_str(&upstream.body).expect("Anthropic streaming request JSON");
    assert_eq!(upstream_body["stream"], true);
}

fn example_yaml(
    listener_port: u16,
    overlay_path: &Path,
    credentials_path: &Path,
    anthropic_port: u16,
    openai_port: u16,
) -> String {
    let example = example_config_path(EXAMPLE);
    let yaml = std::fs::read_to_string(&example).unwrap_or_else(|error| panic!("read {example}: {error}"));
    yaml.replace("0.0.0.0:8080", &format!("127.0.0.1:{listener_port}"))
        .replace("127.0.0.1:9901", &format!("127.0.0.1:{}", free_port()))
        .replace(OVERLAY_PATH, overlay_path.to_str().expect("overlay path is UTF-8"))
        .replace(
            CREDENTIALS_PATH,
            credentials_path.to_str().expect("credentials path is UTF-8"),
        )
        .replace("127.0.0.1:8001", &format!("127.0.0.1:{anthropic_port}"))
        .replace("127.0.0.1:8002", &format!("127.0.0.1:{openai_port}"))
}

fn provider_overlay(anthropic_only: bool) -> String {
    let mut candidates = vec![json!({
        "kind":"inference_model", "name":"client-model", "site":"site-a", "cluster":"anthropic-backend",
        "fresh":true, "selection_group":0, "stable_id":"model/provider-anthropic",
        "api_format":"messages", "path":"/v1/messages", "target_model":"claude-target",
        "credential":{"strategy":"apikey","secretRef":{"name":"anthropic-secret","namespace":"grid-demo","key":"api-key"}}
    })];
    if !anthropic_only {
        candidates.push(json!({
            "kind":"inference_model", "name":"client-model", "site":"site-a", "cluster":"openai-backend",
            "fresh":true, "selection_group":0, "stable_id":"model/provider-openai",
            "api_format":"openai-chat", "path":"/v1/chat/completions", "target_model":"gpt-target",
            "credential":{"strategy":"bearer_token","secretRef":{"name":"openai-secret","namespace":"grid-demo","key":"token"}}
        }));
    }
    let overlay = provider_overlay_body(&candidates);
    let digest = provider_overlay_digest(&overlay);
    provider_overlay_envelope(&overlay, &digest)
}

fn provider_overlay_body(candidates: &[Value]) -> Value {
    json!({
        "network":"grid-demo", "local_site":"site-a", "selection_policy":{"mode":"roundRobin"}, "candidates":candidates
    })
}

fn provider_overlay_digest(overlay: &Value) -> String {
    let semantic = json!({
        "network":overlay["network"], "local_site":overlay["local_site"],
        "selection_policy":overlay["selection_policy"], "candidates":overlay["candidates"]
    });
    let canonical = serde_json_canonicalizer::to_vec(&semantic).expect("canonicalize semantic overlay");
    let digest = hash(MessageDigest::sha256(), &canonical).expect("hash canonical overlay");
    digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
}

fn provider_overlay_envelope(overlay: &Value, digest: &str) -> String {
    let envelope = json!({
        "schema_version":"1.0.0",
        "revision":{"kind":"content_addressed","algorithm":"sha256","value":digest},
        "content_digest":{"algorithm":"sha256","value":digest},
        "scope":{"network":"grid-demo","gateway":"test-gateway","namespace":"grid-demo","local_site":"site-a"},
        "provenance":{"producer":"integration-test","producer_version":"0.1","source_name":"grid-demo","source_uid":"fixture-1","source_generation":1,"rendered_at":"2026-10-17T00:00:00Z"},
        "overlay":overlay
    });
    serde_json::to_string(&envelope).expect("serialize overlay envelope")
}

fn mount_secret(base: &Path, namespace: &str, name: &str, key: &str, token: &str) {
    let directory = base.join(namespace).join(name);
    std::fs::create_dir_all(&directory).expect("create projected Secret directory");
    std::fs::write(directory.join(key), token).expect("write synthetic projected Secret");
}

fn chat_request(stream: bool) -> String {
    let body = json!({
        "model":"client-model", "messages":[{"role":"user","content":"hi"}],
        "max_tokens":32, "stream":stream
    })
    .to_string();
    format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAuthorization: Bearer caller-key\r\nX-Api-Key: caller-key\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn post_request(requests: &[CapturedRequest]) -> CapturedRequest {
    let Some(request) = requests.iter().find(|request| request.method == "POST") else {
        let methods = requests
            .iter()
            .map(|request| request.method.as_str())
            .collect::<Vec<_>>();
        panic!("no POST request observed upstream, observed methods: {methods:?}");
    };
    CapturedRequest {
        method: request.method.clone(),
        uri: request.uri.clone(),
        headers: request.headers.clone(),
        body: request.body.clone(),
    }
}
