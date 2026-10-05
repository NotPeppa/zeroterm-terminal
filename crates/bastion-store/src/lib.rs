//! PostgreSQL authority for identity, policy, credentials, tickets and audit.
mod postgres;
pub use postgres::*;
#[cfg(feature = "dev-prototype")]
mod memory;
#[cfg(feature = "dev-prototype")]
pub use memory::PrototypeStore;

mod pages;
pub use pages::{Collection, ListFilter, PageRequest};
mod lifecycle;
pub use lifecycle::RecordingRead;
mod jobs;
mod maintenance;
mod rewrap;
pub use bastion_domain::{
    ChannelView, CopyJobCreate, CopyJobView, DeviceSessionView, RecordingCreate, RecordingView,
};
mod audit_partitions;
pub use audit_partitions::{
    audit_partition_upgrade, maintain_audit_partitions, AuditPartitionMaintenance,
};
