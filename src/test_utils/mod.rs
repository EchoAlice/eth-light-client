#![doc = include_str!("README.md")]

mod fork;
mod loader;
mod raw_ssz;
mod steps;

use crate::types::primitives::Root;

pub use loader::SpecTestLoader;
pub use steps::{beacon_header_matches, HeaderCheck, ProcessUpdateStep, StateChecks, TestStep};

pub(crate) use fork::MinimalPresetFork;

/// Box<dyn Error>, not `crate::error::Result`: test glue stays decoupled from the production error enum.
pub(crate) type TestUtilsResult<T> = Result<T, Box<dyn std::error::Error>>;

/// Convert a hex string (with or without 0x prefix) to a 32-byte root.
pub(crate) fn hex_to_root(hex: &str) -> TestUtilsResult<Root> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex::decode(hex)?;
    if bytes.len() != 32 {
        return Err(format!("Expected 32 bytes, got {}", bytes.len()).into());
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes);
    Ok(root)
}

#[cfg(test)]
pub(crate) use loader::load_altair_bootstrap;
