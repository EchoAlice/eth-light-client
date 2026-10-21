// Each integration test binary compiles this module on its own, so anything
// one binary doesn't use is dead code there.
#![allow(dead_code, unused_imports)]

mod fork;
mod loader;
mod steps;

pub use loader::SyncTestCase;
pub use steps::{ProcessUpdateStep, StateChecks, TestStep};

/// Box<dyn Error>, not `crate::error::Result`: test glue stays decoupled from the production error enum.
pub type TestUtilsResult<T> = Result<T, Box<dyn std::error::Error>>;
