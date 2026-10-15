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
/// Parses `BASTION_PASSWORD_MIN_LENGTH`: unset or empty means 12. The floor of 8 keeps it from being
/// configured away; the ceiling of 32 stays below generated passwords (43 characters).
fn parse_min_length(value: Option<&str>) -> Result<usize> {
    match value.map(str::trim).filter(|v| !v.is_empty()) {
        None => Ok(12),
        Some(v) => match v.parse::<usize>() {
            Ok(n) if (8..=32).contains(&n) => Ok(n),
            _ => {
                bail!("BASTION_PASSWORD_MIN_LENGTH must be a whole number from 8 to 32, got {v:?}")
            }
        },
    }
}
/// Minimum password length in UTF-8 bytes for every password set anywhere, read once per process.
/// Call it at startup so a bad value stops the process instead of failing each password change.
pub fn password_min_length() -> Result<usize> {
    static MIN: std::sync::OnceLock<Result<usize, String>> = std::sync::OnceLock::new();
    MIN.get_or_init(|| {
        parse_min_length(std::env::var("BASTION_PASSWORD_MIN_LENGTH").ok().as_deref())
            .map_err(|error| error.to_string())
    })
    .clone()
    .map_err(anyhow::Error::msg)
}
pub fn hash_password(password: &str) -> Result<String> {
    let min = password_min_length()?;
    if password.len() < min || password.len() > 1024 {
        bail!("password must be {min}–1024 UTF-8 bytes");
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
    #[test]
    fn minimum_length_defaults_to_12_and_stays_within_8_to_32() {
        assert_eq!(parse_min_length(None).unwrap(), 12);
        assert_eq!(parse_min_length(Some("")).unwrap(), 12);
        assert_eq!(parse_min_length(Some(" 16 ")).unwrap(), 16);
        assert_eq!(parse_min_length(Some("8")).unwrap(), 8);
        assert_eq!(parse_min_length(Some("32")).unwrap(), 32);
        for bad in ["7", "33", "0", "-1", "twelve", "12.5"] {
            assert!(
                parse_min_length(Some(bad)).is_err(),
                "{bad} must be rejected"
            );
        }
    }
}
