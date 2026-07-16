//! Consensus data types, split by concern:
//!
//! - [`headers`] — beacon / fork-aware light-client headers + execution payloads.
//! - [`committee`] — sync committee and sync aggregate.
//! - [`messages`] — light client update / bootstrap messages.
//!
//! The engine's internal verified state (`LightClientStore`) lives in
//! `crate::consensus::store`, not here — it is processing state, not a wire type.

mod committee;
mod headers;
mod messages;

pub use committee::*;
pub use headers::*;
pub use messages::*;
