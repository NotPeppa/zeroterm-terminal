//! PostgreSQL authority for cookie identity, browser sessions, policy and audit.
mod postgres;
pub use postgres::*;
mod inputs;
pub use inputs::*;
mod targets;
pub use targets::*;
mod groups;
pub use groups::*;
mod pages;
mod recordings;
mod sessions;
pub use pages::{Collection, ListFilter, PageRequest};
mod lifecycle;
pub use lifecycle::RecordingRead;
mod maintenance;
mod rewrap;
pub use bastion_domain::{DeviceSessionView, RecordingCreate, RecordingView};
mod audit_partitions;
pub use audit_partitions::{
    audit_partition_upgrade, maintain_audit_partitions, AuditPartitionMaintenance,
};
