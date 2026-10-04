mod protocol;
pub use protocol::{
    run_backend, test_target, GatewayBackend, NetworkPolicy, Target, TargetAuth, TargetEndpoint,
};
#[cfg(feature = "dev-prototype")]
mod prototype;
#[cfg(feature = "dev-prototype")]
pub use prototype::run;
