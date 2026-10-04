use anyhow::{bail, Result};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};

fn argon() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(64 * 1024, 3, 1, None).expect("fixed Argon2 parameters"),
    )
}
pub fn hash_password(password: &str) -> Result<String> {
    if password.len() < 12 || password.len() > 1024 {
        bail!("password must be 12–1024 UTF-8 bytes");
    }
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    argon()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| anyhow::anyhow!("password hashing failed"))
}
pub fn verify_password(password: &str, phc: &str) -> bool {
    if password.len() > 1024 {
        return false;
    }
    PasswordHash::new(phc)
        .is_ok_and(|hash| argon().verify_password(password.as_bytes(), &hash).is_ok())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn passwords_are_salted_and_verified_without_trimming() {
        let a = hash_password(" test password 123 ").unwrap();
        let b = hash_password(" test password 123 ").unwrap();
        assert_ne!(a, b);
        assert!(a.starts_with("$argon2id$"));
        assert!(verify_password(" test password 123 ", &a));
        assert!(!verify_password("test password 123", &a));
        assert!(!verify_password("incorrect password", &a));
    }
}
