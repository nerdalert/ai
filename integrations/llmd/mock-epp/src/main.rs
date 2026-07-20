// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Deterministic mock `llm-d` Endpoint Picker Provider.
//!
//! This binary is intentionally small and test-only. It implements enough of
//! Envoy's `ext_proc` gRPC service for Praxis AI Kind tests: read an OpenAI
//! request body, extract `model`, and set `x-gateway-destination-endpoint` to a
//! deterministic backend endpoint configured by `--route model=endpoint`.

use std::{collections::BTreeMap, net::SocketAddr, pin::Pin, sync::Arc};

use async_trait::async_trait;
use clap::Parser;
use praxis_ai_llmd_ext_proc::proto::envoy::service::{
    common::v3::{HeaderValue, HeaderValueOption, header_value_option::HeaderAppendAction},
    ext_proc::v3::{
        BodyResponse, CommonResponse, HeaderMutation, HeadersResponse, ProcessingRequest, ProcessingResponse,
        external_processor_server::{ExternalProcessor, ExternalProcessorServer},
        processing_request, processing_response,
    },
};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tonic::transport::Server;
use tracing::{info, warn};

/// Header consumed by Praxis `endpoint_selector`.
const DESTINATION_HEADER: &str = "x-gateway-destination-endpoint";

/// CLI arguments for the mock Endpoint Picker Provider.
#[derive(Debug, Parser)]
#[command(name = "mock-epp", about = "Deterministic mock llm-d EPP")]
struct Args {
    /// gRPC listen port.
    #[arg(long, default_value_t = 50051)]
    port: u16,

    /// Model-to-endpoint route mappings (`model=endpoint`).
    #[arg(long = "route", value_parser = parse_route)]
    routes: Vec<(String, String)>,
}

/// Deterministic `ext_proc` processor.
#[derive(Debug)]
struct MockEpp {
    /// Configured model-to-endpoint routes.
    routes: Arc<BTreeMap<String, String>>,
}

#[async_trait]
impl ExternalProcessor for MockEpp {
    type ProcessStream = Pin<Box<dyn futures::Stream<Item = Result<ProcessingResponse, tonic::Status>> + Send>>;

    async fn process(
        &self,
        request: tonic::Request<tonic::Streaming<ProcessingRequest>>,
    ) -> Result<tonic::Response<Self::ProcessStream>, tonic::Status> {
        let routes = Arc::clone(&self.routes);
        let rx = spawn_processor_task(request.into_inner(), routes);

        Ok(tonic::Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }
}

/// Entrypoint.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let routes = Arc::new(args.routes.into_iter().collect::<BTreeMap<_, _>>());
    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    let processor = MockEpp {
        routes: Arc::clone(&routes),
    };

    info!(%addr, routes = routes.len(), "starting mock EPP");

    Server::builder()
        .add_service(ExternalProcessorServer::new(processor))
        .serve(addr)
        .await?;

    Ok(())
}

/// Parse one `model=endpoint` route.
fn parse_route(raw: &str) -> Result<(String, String), String> {
    let Some((model, endpoint)) = raw.split_once('=') else {
        return Err(format!("expected model=endpoint, got: {raw}"));
    };
    if model.is_empty() || endpoint.is_empty() {
        return Err(format!("model and endpoint must be non-empty: {raw}"));
    }
    Ok((model.to_owned(), endpoint.to_owned()))
}

/// Spawn one `ext_proc` stream handler.
fn spawn_processor_task(
    mut stream: tonic::Streaming<ProcessingRequest>,
    routes: Arc<BTreeMap<String, String>>,
) -> Receiver<Result<ProcessingResponse, tonic::Status>> {
    let (tx, rx) = mpsc::channel(8);

    tokio::spawn(async move {
        let Some(body) = read_request_body(&mut stream).await else {
            return;
        };
        send_route_responses(tx, &body, &routes).await;
    });

    rx
}

/// Read request headers and body until the end-of-stream body frame.
async fn read_request_body(stream: &mut tonic::Streaming<ProcessingRequest>) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    let mut saw_headers = false;

    loop {
        let msg = receive_message(stream).await?;
        match msg.request {
            Some(processing_request::Request::RequestHeaders(_)) => {
                saw_headers = true;
                info!("received request headers");
            },
            Some(processing_request::Request::RequestBody(chunk)) => {
                body.extend_from_slice(&chunk.body);
                if chunk.end_of_stream {
                    break;
                }
            },
            Some(other) => warn!(request = ?other, "ignoring unsupported ext_proc request message"),
            None => {},
        }
    }

    if !saw_headers {
        warn!("expected request headers first");
    }

    Some(body)
}

/// Receive one message from the processor stream.
async fn receive_message(stream: &mut tonic::Streaming<ProcessingRequest>) -> Option<ProcessingRequest> {
    match stream.message().await {
        Ok(Some(msg)) => Some(msg),
        Ok(None) => None,
        Err(error) => {
            warn!(%error, "mock-epp stream receive failed");
            None
        },
    }
}

/// Send the route mutation followed by the request-body continuation.
async fn send_route_responses(
    tx: Sender<Result<ProcessingResponse, tonic::Status>>,
    body: &[u8],
    routes: &BTreeMap<String, String>,
) {
    if tx.send(Ok(route_response(body, routes))).await.is_err() {
        return;
    }
    let _ignored = tx.send(Ok(body_continue_response())).await;
}

/// Build the header response for the request body.
fn route_response(body: &[u8], routes: &BTreeMap<String, String>) -> ProcessingResponse {
    let Some(model) = request_model(body) else {
        warn!(body_len = body.len(), "request body has no model");
        return headers_response(None);
    };
    let Some(endpoint) = routes.get(&model) else {
        warn!(%model, "no matching route");
        return headers_response(None);
    };

    info!(%model, %endpoint, "routing to endpoint");
    headers_response(Some(endpoint.as_str()))
}

/// Extract the OpenAI request model from a JSON body.
fn request_model(body: &[u8]) -> Option<String> {
    let value = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    value.get("model")?.as_str().map(str::to_owned)
}

/// Build an `ext_proc` request-headers response, optionally mutating destination.
fn headers_response(destination: Option<&str>) -> ProcessingResponse {
    let header_mutation = destination.map(|dest| HeaderMutation {
        set_headers: vec![HeaderValueOption {
            header: Some(HeaderValue {
                key: DESTINATION_HEADER.to_owned(),
                raw_value: dest.as_bytes().to_vec(),
                ..HeaderValue::default()
            }),
            append_action: HeaderAppendAction::OverwriteIfExistsOrAdd.into(),
            ..HeaderValueOption::default()
        }],
        ..HeaderMutation::default()
    });

    ProcessingResponse {
        response: Some(processing_response::Response::RequestHeaders(HeadersResponse {
            response: Some(CommonResponse {
                header_mutation,
                ..CommonResponse::default()
            }),
        })),
        ..ProcessingResponse::default()
    }
}

/// Continue after the final request body chunk.
fn body_continue_response() -> ProcessingResponse {
    ProcessingResponse {
        response: Some(processing_response::Response::RequestBody(BodyResponse {
            response: None,
        })),
        ..ProcessingResponse::default()
    }
}
