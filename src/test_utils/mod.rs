//! # Test Utilities (Unstable)
//!
//! **Warning:** This module is not part of the stable public API.
//! It may change or be removed without notice in any version.
//!
//! Provides helpers for loading Ethereum consensus-spec test fixtures,
//! useful for integration testing and downstream library testing.
//!
//! Enable with the `test-utils` feature:
//! ```toml
//! [dev-dependencies]
//! eth-light-client = { version = "0.1", features = ["test-utils"] }
//! ```

mod fork;
mod loader;
mod raw_ssz;
mod steps;

pub use loader::{BootstrapData, SpecTestLoader};
pub use steps::{
    hex_to_root, ForceUpdateStep, HeaderCheck, ProcessUpdateStep, StateChecks, TestMeta, TestStep,
};

pub(crate) use fork::MinimalPresetFork;
