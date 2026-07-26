// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Praxis Contributors

//! Grid gateway-to-gateway routing filters.
//!
//! Provides the edge `grid_route` filter and the provider-side
//! `grid_provider_route` and `grid_credential_inject` filters. These belong in
//! the AI proxy because they encode Grid and inference-specific contracts, not
//! generic Praxis proxy mechanics.

mod credential_inject;
pub(crate) mod descriptor;
pub(crate) mod metadata;
pub(crate) mod overlay;
mod provider_route;
mod route;

pub use credential_inject::GridCredentialInjectFilter;
pub use provider_route::GridProviderRouteFilter;
pub use route::GridRouteFilter;
