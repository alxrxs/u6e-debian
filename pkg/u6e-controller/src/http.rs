//! The web listener (`listen_http`), which the web UI and its API are served
//! from. It has no routes yet, so every path answers 404.

use axum::Router;

use crate::state::Shared;

/// The web listener's routes.
pub fn router(state: Shared) -> Router {
    Router::new().with_state(state)
}
