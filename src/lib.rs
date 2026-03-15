#![allow(clippy::too_many_arguments)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::field_reassign_with_default)]

// Public modules
pub mod config;
pub mod error;
pub mod light_client;
pub mod types;

// Private implementation modules
mod consensus;

// Test utilities (unstable, not part of public API)
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
