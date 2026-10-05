use super::*;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex as StdMutex,
};

#[derive(Default)]
struct MetadataBackend {
    checkpoints: StdMutex<Vec<(i64, i64, i64)>>,
    finishes: StdMutex<Vec<RecordingState>>,
    registry: Arc<RuntimeRegistry>,
    streaming: AtomicUsize,
}
#[async_trait]
impl GatewayBackend for MetadataBackend {
    fn registry(&self) -> Arc<RuntimeRegistry> {
        self.registry.clone()
    }
    async fn consume(&self, _: Uuid, _: &str) -> Result<(Connection, Target), ErrorCode> {
        Err(ErrorCode::TicketInvalid)
    }
    async fn authorize(&self, _: &Connection) -> Result<(), ErrorCode> {
        Ok(())
    }
    async fn transition(
        &self,
        _: Uuid,
        _: ConnectionState,
        _: Option<ErrorCode>,
    ) -> Result<(), ErrorCode> {
        Ok(())
    }
    async fn channel_audit(
        &self,
        _: &Connection,
        _: &str,
        _: Option<String>,
        _: Option<usize>,
    ) -> Result<(), ErrorCode> {
        Ok(())
    }
    async fn checkpoint_recording(&self, _: Uuid, w: i64, s: i64, b: i64) -> Result<(), ErrorCode> {
        self.checkpoints.lock().unwrap().push((w, s, b));
        Ok(())
    }
    async fn finish_shell(
        &self,
        _: Uuid,
        _: Uuid,
        state: RecordingState,
        _: i64,
        _: Option<String>,
        _: Option<u32>,
        _: Option<String>,
        _: Option<ErrorCode>,
    ) -> Result<(), ErrorCode> {
        self.finishes.lock().unwrap().push(state);
        Ok(())
    }
    async fn mark_streaming(&self, _: Uuid) -> Result<(), ErrorCode> {
        self.streaming.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[tokio::test]
async fn recorder_finish_state_is_explicit_and_ack_requires_writer() {
    let backend = Arc::new(MetadataBackend::default());
    let (tx, mut rx) = mpsc::channel(8);
    let recording = ShellRecording {
        inner: Arc::new(RecorderSender {
            tx,
            sequence: Mutex::new(()),
            bytes: Arc::new(Semaphore::new(256 * 1024)),
            channel_id: Uuid::new_v4(),
            backend: backend.clone(),
        }),
    };
    let writer = async {
        let request = rx.recv().await.unwrap();
        assert_eq!(
            request.finish,
            Some((RecordingState::Partial, Some(ErrorCode::TargetTimeout)))
        );
        assert_eq!(request.event["reason"], "channel_closed");
        let _ = request.ack.send(Err(ErrorCode::RecordingUnavailable));
    };
    let (finished, ()) = tokio::join!(
        recording.finish(
            "channel_closed",
            RecordingState::Partial,
            Some(ErrorCode::TargetTimeout)
        ),
        writer
    );
    assert_eq!(finished, Err(ErrorCode::RecordingUnavailable));
    assert!(backend.finishes.lock().unwrap().is_empty());
    recording.streaming().await.unwrap();
    assert_eq!(backend.streaming.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn closed_recorder_never_acknowledges_unwritten_output() {
    let (tx, rx) = mpsc::channel(8);
    drop(rx);
    let recording = ShellRecording {
        inner: Arc::new(RecorderSender {
            tx,
            sequence: Mutex::new(()),
            bytes: Arc::new(Semaphore::new(256 * 1024)),
            channel_id: Uuid::new_v4(),
            backend: Arc::new(MetadataBackend::default()),
        }),
    };
    assert_eq!(
        recording.output(false, b"not persisted").await,
        Err(ErrorCode::RecordingUnavailable)
    );
}
