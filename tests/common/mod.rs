mod fork;
mod loader;
mod steps;

pub use loader::SyncTestCase;
pub use steps::{ProcessUpdateStep, StateChecks, TestStep};

/// Box<dyn Error>, not `crate::error::Result`: test glue stays decoupled from the production error enum.
pub type TestUtilsResult<T> = Result<T, Box<dyn std::error::Error>>;
