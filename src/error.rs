use crate::types::primitives::{Root, Slot};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Serialization(String),
    InvalidConfig(String),
    TrustedRootMismatch {
        expected: Root,
        got: Root,
    },
    InvalidUpdate(String),
    InvalidProof(String),
    StaleTrustedRoot {
        header_slot: Slot,
        current_slot: Slot,
        ws_period_as_slots: Slot,
    },
    Internal(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Serialization(msg) => write!(f, "Serialization error: {msg}"),
            Error::InvalidConfig(msg) => write!(f, "Invalid config: {msg}"),
            Error::TrustedRootMismatch { expected, got } => write!(
                f,
                "Bootstrap doesn't match the trusted block root: expected 0x{}, got 0x{}",
                hex(expected),
                hex(got)
            ),
            Error::InvalidUpdate(msg) => write!(f, "Invalid update: {msg}"),
            Error::InvalidProof(msg) => write!(f, "Invalid proof: {msg}"),
            Error::StaleTrustedRoot {
                header_slot,
                current_slot,
                ws_period_as_slots,
            } => write!(f, "Trusted root too old: header slot = {header_slot}, current slot = {current_slot}, weak subjectivity period as slots = {ws_period_as_slots}"),
            Error::Internal(msg) => write!(f, "Internal error: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

fn hex(root: &Root) -> String {
    root.iter().map(|b| format!("{b:02x}")).collect()
}
