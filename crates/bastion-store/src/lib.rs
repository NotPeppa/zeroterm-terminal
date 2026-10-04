//! PostgreSQL authority for identity, policy, credentials, tickets and audit.
mod postgres;
pub use postgres::*;
#[cfg(feature = "dev-prototype")]
mod memory;
#[cfg(feature = "dev-prototype")]
pub use memory::PrototypeStore;

mod pages;
pub use pages::{Collection, PageRequest};
