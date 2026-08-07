#![doc = include_str!("README.md")]

mod fork;
mod loader;
mod steps;

pub use loader::SyncTestCase;
pub use steps::{HeaderCheck, ProcessUpdateStep, StateChecks, TestStep};

/// Box<dyn Error>, not `crate::error::Result`: test glue stays decoupled from the production error enum.
pub(crate) type TestUtilsResult<T> = Result<T, Box<dyn std::error::Error>>;

#[cfg(test)]
pub(crate) use loader::load_altair_bootstrap;
