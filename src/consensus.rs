//! This private module is the verification engine behind the `LightClient`
//! facade. It contains BLS aggregate signature verification, Merkle proofs,
//! and the update state machine. The public surface is `crate::light_client`.

pub(crate) mod bls;
pub(crate) mod merkle;
pub(crate) mod processor;
pub(crate) mod signing;
pub(crate) mod store;
