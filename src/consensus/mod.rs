pub mod beacon;
pub mod bls;
pub mod light_client;
pub mod merkle;
pub mod sync_committee;

#[cfg(test)]
mod bls_spec_tests;
#[cfg(test)]
pub(crate) mod light_client_spec_tests;

// Re-export the main entry point for internal use
pub(crate) use beacon::BeaconConsensus;
