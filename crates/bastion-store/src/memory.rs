use bastion_domain::*;
use bastion_secrets::{matches_hash, Secret};
use chrono::Utc;
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};
use uuid::Uuid;

struct Entry {
    hash: [u8; 32],
    deadline: Instant,
    connection: Connection,
}
pub struct PrototypeStore {
    entries: Mutex<HashMap<Uuid, Entry>>,
    ttl: Duration,
}

impl PrototypeStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            ttl,
        }
    }
    pub fn issue(
        &self,
        request: TicketRequest,
        gateway: GatewayAddress,
    ) -> Result<TicketResponse, ErrorCode> {
        let mut entries = self.entries.lock().expect("store poisoned");
        let now = Instant::now();
        Self::expire(&mut entries, now);
        // Bound history as well as pending tickets; this prototype is ephemeral.
        entries.retain(|_, e| {
            !e.connection.state.is_terminal()
                || now.saturating_duration_since(e.deadline) < Duration::from_secs(300)
        });
        if entries.len() >= 1024
            || entries
                .values()
                .filter(|e| e.connection.state == ConnectionState::Pending)
                .count()
                >= 20
        {
            return Err(ErrorCode::ConnectionLimit);
        }
        let secret = Secret::random();
        let ticket_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let expires_at = Utc::now() + chrono::Duration::from_std(self.ttl).unwrap();
        let connection = Connection {
            id: connection_id,
            ticket_id,
            asset_id: request.asset_id,
            account_id: request.account_id,
            capabilities: request.capabilities.clone(),
            purpose: request.purpose,
            transport: TicketTransport::Ssh,
            protocol_version: 1,
            state: ConnectionState::Pending,
            created_at: Utc::now(),
            failure: None,
            user_id: None,
            login_session_id: None,
        };
        entries.insert(
            ticket_id,
            Entry {
                hash: secret.hash(),
                deadline: now + self.ttl,
                connection,
            },
        );
        Ok(TicketResponse {
            protocol_version: 1,
            ticket_id,
            ticket_secret: secret.expose().to_owned(),
            connection_id,
            expires_at,
            gateway: GatewayAddress {
                username: format!("zt1:{ticket_id}"),
                ..gateway
            },
            capabilities: request.capabilities,
        })
    }
    pub fn consume(&self, id: Uuid, secret: &str) -> Result<Connection, ErrorCode> {
        let mut entries = self.entries.lock().expect("store poisoned");
        Self::expire(&mut entries, Instant::now());
        // Prototype models one explicit development identity, at most ten sockets.
        if entries
            .values()
            .filter(|e| {
                matches!(
                    e.connection.state,
                    ConnectionState::Connecting
                        | ConnectionState::Active
                        | ConnectionState::Closing
                )
            })
            .count()
            >= 10
        {
            return Err(ErrorCode::ConnectionLimit);
        }
        let entry = entries.get_mut(&id).ok_or(ErrorCode::TicketInvalid)?;
        if !matches_hash(&entry.hash, secret) {
            return Err(ErrorCode::TicketInvalid);
        }
        match entry.connection.state {
            ConnectionState::Pending => {
                entry.connection.state = ConnectionState::Connecting;
                Ok(entry.connection.clone())
            }
            ConnectionState::Expired => Err(ErrorCode::TicketExpired),
            _ => Err(ErrorCode::TicketUsed),
        }
    }
    pub fn get(&self, connection_id: Uuid) -> Option<Connection> {
        let mut entries = self.entries.lock().expect("store poisoned");
        Self::expire(&mut entries, Instant::now());
        entries
            .values()
            .find(|e| e.connection.id == connection_id)
            .map(|e| e.connection.clone())
    }
    pub fn transition(
        &self,
        connection_id: Uuid,
        state: ConnectionState,
        failure: Option<ErrorCode>,
    ) {
        let mut entries = self.entries.lock().expect("store poisoned");
        if let Some(entry) = entries
            .values_mut()
            .find(|e| e.connection.id == connection_id)
        {
            if entry.connection.state.permits(state) {
                entry.connection.state = state;
                entry.connection.failure = failure.map(|code| Failure { code });
            }
        }
    }
    fn expire(entries: &mut HashMap<Uuid, Entry>, now: Instant) {
        for entry in entries.values_mut() {
            if entry.connection.state == ConnectionState::Pending && now >= entry.deadline {
                entry.connection.state = ConnectionState::Expired;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    fn issue(store: &PrototypeStore) -> TicketResponse {
        store
            .issue(
                TicketRequest {
                    asset_id: Uuid::new_v4(),
                    account_id: Uuid::new_v4(),
                    capabilities: vec![Capability::Exec],
                    purpose: Purpose::Metrics,
                },
                GatewayAddress {
                    id: "test".into(),
                    host: "127.0.0.1".into(),
                    port: 2222,
                    username: String::new(),
                },
            )
            .unwrap()
    }
    #[tokio::test]
    async fn twenty_consumers_only_one_wins() {
        let store = Arc::new(PrototypeStore::new(Duration::from_secs(30)));
        let ticket = issue(&store);
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..20 {
            let store = store.clone();
            let secret = ticket.ticket_secret.clone();
            let id = ticket.ticket_id;
            tasks.spawn(async move { store.consume(id, &secret).is_ok() });
        }
        let mut wins = 0;
        while let Some(result) = tasks.join_next().await {
            wins += usize::from(result.unwrap());
        }
        assert_eq!(wins, 1);
    }
    #[test]
    fn wrong_secret_does_not_consume_and_closed_is_not_reusable() {
        let store = PrototypeStore::new(Duration::from_secs(30));
        let ticket = issue(&store);
        assert_eq!(
            store.consume(ticket.ticket_id, "wrong").unwrap_err(),
            ErrorCode::TicketInvalid
        );
        assert!(store
            .consume(ticket.ticket_id, &ticket.ticket_secret)
            .is_ok());
        store.transition(ticket.connection_id, ConnectionState::Closing, None);
        store.transition(ticket.connection_id, ConnectionState::Closed, None);
        assert_eq!(
            store
                .consume(ticket.ticket_id, &ticket.ticket_secret)
                .unwrap_err(),
            ErrorCode::TicketUsed
        );
    }
    #[test]
    fn expired_ticket_cannot_authenticate() {
        let store = PrototypeStore::new(Duration::ZERO);
        let ticket = issue(&store);
        assert_eq!(
            store
                .consume(ticket.ticket_id, &ticket.ticket_secret)
                .unwrap_err(),
            ErrorCode::TicketExpired
        );
    }
}
