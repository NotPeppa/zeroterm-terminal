use crate::{bounded, PgStore, StoreResult};
use bastion_domain::ErrorCode;
use bastion_secrets::Envelope;
use uuid::Uuid;
fn valid(e: &Envelope) -> bool {
    e.ciphertext.len() >= 17
        && e.nonce.len() == 24
        && e.wrapped_dek.len() == 48
        && e.wrap_nonce.len() == 24
        && e.key_version > 0
}
impl PgStore {
    /// Compare-and-swap KEK wrapping metadata. Ciphertext and credential AAD stay unchanged.
    pub async fn rewrap_credential(
        &self,
        id: Uuid,
        expected_key_version: i64,
        envelope: &Envelope,
    ) -> StoreResult<bool> {
        if expected_key_version <= 0 || !valid(envelope) {
            return Err(ErrorCode::InvalidArgument);
        }
        bounded(async {let result=sqlx::query("UPDATE credentials SET wrapped_dek=$4,wrap_nonce=$5,key_version=$6 WHERE id=$1 AND key_version=$2 AND $3::boolean AND ciphertext=$7 AND nonce=$8").bind(id).bind(expected_key_version).bind(envelope.key_version>expected_key_version).bind(&envelope.wrapped_dek).bind(&envelope.wrap_nonce).bind(envelope.key_version).bind(&envelope.ciphertext).bind(&envelope.nonce).execute(&self.pool).await.map_err(crate::postgres::db)?;Ok(result.rows_affected()==1)}).await
    }
    /// Compare-and-swap KEK wrapping metadata for a recording. Ciphertext/AAD unchanged.
    pub async fn rewrap_recording(
        &self,
        id: Uuid,
        expected_key_version: i64,
        wrapped_dek: &[u8],
        wrap_nonce: &[u8],
        new_key_version: i64,
    ) -> StoreResult<bool> {
        if expected_key_version <= 0
            || new_key_version <= expected_key_version
            || wrapped_dek.len() != 48
            || wrap_nonce.len() != 24
        {
            return Err(ErrorCode::InvalidArgument);
        }
        bounded(async {let result=sqlx::query("UPDATE recordings SET wrapped_dek=$4,wrap_nonce=$5,key_version=$6 WHERE id=$1 AND key_version=$2 AND state<>'expired' AND $3::boolean").bind(id).bind(expected_key_version).bind(new_key_version>expected_key_version).bind(wrapped_dek).bind(wrap_nonce).bind(new_key_version).execute(&self.pool).await.map_err(crate::postgres::db)?;Ok(result.rows_affected()==1)}).await
    }
}
