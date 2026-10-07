use crate::types::primitives::Slot;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Serialization(String),
    InvalidInput(String),
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
            Error::InvalidInput(msg) => write!(f, "Invalid input: {msg}"),
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
