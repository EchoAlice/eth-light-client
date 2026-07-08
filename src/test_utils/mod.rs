#![doc = include_str!("README.md")]

mod fork;
mod loader;
mod raw_ssz;
mod steps;

pub use loader::{BootstrapData, SpecTestLoader};
pub use steps::{
    beacon_header_matches, hex_to_root, ForceUpdateStep, HeaderCheck, ProcessUpdateStep,
    StateChecks, TestMeta, TestStep,
};

pub(crate) use fork::MinimalPresetFork;

#[cfg(test)]
pub(crate) use loader::load_altair_bootstrap;
