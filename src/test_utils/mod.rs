#![doc = include_str!("README.md")]

mod fork;
mod loader;
mod raw_ssz;
mod steps;

pub use loader::{BootstrapData, SpecTestLoader};
pub use steps::{beacon_header_matches, HeaderCheck, ProcessUpdateStep, StateChecks, TestStep};

pub(crate) use fork::MinimalPresetFork;
pub(crate) use steps::hex_to_root;

#[cfg(test)]
pub(crate) use loader::load_altair_bootstrap;
