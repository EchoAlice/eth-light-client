#![doc = include_str!("README.md")]

mod fork;
mod loader;
mod raw_ssz;
mod steps;

pub use loader::LightClientSyncTest;
pub use steps::{beacon_header_matches, HeaderCheck, ProcessUpdateStep, StateChecks, TestStep};

pub(crate) use fork::MinimalPresetFork;
pub(crate) use steps::hex_to_root;

/// Box<dyn Error>, not `crate::error::Result`: test glue stays decoupled from the production error enum.
pub(crate) type TestUtilsResult<T> = Result<T, Box<dyn std::error::Error>>;

#[cfg(test)]
pub(crate) use loader::load_altair_bootstrap;
