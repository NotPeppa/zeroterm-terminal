//! Conservative shared file-response credits and preallocation framing limits.
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn complete_response_and_payload_credit_is_bounded() {
    assert_eq!(BULK_WINDOW, 2);
    const {
        assert!(2 * BULK_CREDIT <= IO_BUDGET);
        assert!(2 * BULK_CREDIT + META_CREDIT > IO_BUDGET);
        // One metadata decoder's bounded packet scratch remains accounted separately.
        assert!(BULK_CREDIT + META_CREDIT + MAX_PACKET <= IO_BUDGET);
    }
}

#[tokio::test]
async fn completed_read_credit_is_held_until_consumer_and_metadata_cannot_overcommit() {
    let bytes = Arc::new(Semaphore::new(IO_BUDGET));
    let first = bytes
        .clone()
        .acquire_many_owned(BULK_CREDIT as u32)
        .await
        .unwrap();
    let second = bytes
        .clone()
        .acquire_many_owned(BULK_CREDIT as u32)
        .await
        .unwrap();
    assert!(bytes
        .clone()
        .try_acquire_many_owned(META_CREDIT as u32)
        .is_err());
    let reply = ReadReply {
        data: Some(vec![0; MAX_CHUNK]),
        credit: first,
    };
    assert!(bytes
        .clone()
        .try_acquire_many_owned(BULK_CREDIT as u32)
        .is_err());
    drop(reply);
    let metadata = bytes
        .clone()
        .try_acquire_many_owned(META_CREDIT as u32)
        .unwrap();
    assert!(bytes
        .clone()
        .try_acquire_many_owned(BULK_CREDIT as u32)
        .is_err());
    drop(second);
    drop(metadata);
    assert_eq!(bytes.available_permits(), IO_BUDGET);
}

#[test]
fn short_reads_fill_tail_without_skipping_offsets_and_empty_is_not_eof() {
    assert_eq!(read_tail(0, 32768, 3).unwrap(), Some((3, 32765)));
    assert_eq!(read_tail(3, 32765, 32764).unwrap(), Some((32767, 1)));
    assert_eq!(read_tail(32767, 1, 1).unwrap(), None);
    assert_eq!(
        read_tail(0, 32768, 0),
        Err(ErrorCode::TargetRequestRejected)
    );
    assert_eq!(
        read_tail(0, 32768, 32769),
        Err(ErrorCode::TargetRequestRejected)
    );
    assert_eq!(
        read_tail(u64::MAX - 1, 2, 2),
        Err(ErrorCode::InvalidArgument)
    );
}

fn status(code: StatusCode) -> SftpError {
    SftpError::Status(russh_sftp::protocol::Status {
        id: 1,
        status_code: code,
        error_message: String::new(),
        language_tag: String::new(),
    })
}
#[test]
fn only_status_eof_is_terminal_and_other_errors_propagate() {
    assert!(read_result(Err(status(StatusCode::Eof))).unwrap().is_none());
    assert_eq!(
        map_error(read_result(Err(status(StatusCode::NoSuchFile))).unwrap_err()),
        ErrorCode::ResourceNotFound
    );
    assert_eq!(
        map_error(read_result(Err(status(StatusCode::PermissionDenied))).unwrap_err()),
        ErrorCode::PermissionDenied
    );
    assert_eq!(map_error(SftpError::Timeout), ErrorCode::TargetTimeout);
}
#[tokio::test]
async fn out_of_order_results_are_consumed_by_offset_and_canceled_wait_keeps_ownership() {
    let bytes = Arc::new(Semaphore::new(IO_BUDGET));
    let first = bytes
        .clone()
        .acquire_many_owned(BULK_CREDIT as u32)
        .await
        .unwrap();
    let second = bytes
        .clone()
        .acquire_many_owned(BULK_CREDIT as u32)
        .await
        .unwrap();
    let release = Arc::new(Semaphore::new(0));
    let wait = release.clone();
    let (second_ready, second_observed) = tokio::sync::oneshot::channel();
    let mut pending = VecDeque::from([
        PendingRead {
            offset: 0,
            len: MAX_CHUNK as u32,
            task: tokio::spawn(async move {
                wait.acquire().await.unwrap().forget();
                Ok(ReadReply {
                    data: Some(vec![1]),
                    credit: first,
                })
            }),
        },
        PendingRead {
            offset: MAX_CHUNK as u64,
            len: MAX_CHUNK as u32,
            task: tokio::spawn(async move {
                let _ = second_ready.send(());
                Ok(ReadReply {
                    data: Some(vec![2]),
                    credit: second,
                })
            }),
        },
    ]);
    second_observed.await.unwrap();
    let mut waiting = Box::pin(receive_read(&mut pending));
    assert!(
        std::future::poll_fn(|cx| Poll::Ready(
            std::future::Future::poll(waiting.as_mut(), cx).is_pending()
        ))
        .await
    );
    drop(waiting);
    assert_eq!(pending.len(), 2);
    release.add_permits(1);
    let (offset, _, reply) = receive_read(&mut pending).await.unwrap();
    assert_eq!(offset, 0);
    assert_eq!(reply.data, Some(vec![1]));
    drop(reply);
    let (offset, _, reply) = receive_read(&mut pending).await.unwrap();
    assert_eq!(offset, MAX_CHUNK as u64);
    assert_eq!(reply.data, Some(vec![2]));
    drop(reply);
    assert_eq!(bytes.available_permits(), IO_BUDGET);
}
#[tokio::test]
async fn abort_and_join_releases_every_owned_response_credit() {
    let bytes = Arc::new(Semaphore::new(IO_BUDGET));
    let mut tasks = Vec::new();
    for _ in 0..BULK_WINDOW {
        let credit = bytes
            .clone()
            .acquire_many_owned(BULK_CREDIT as u32)
            .await
            .unwrap();
        tasks.push(tokio::spawn(async move {
            let _credit = credit;
            std::future::pending::<()>().await;
        }));
    }
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        assert!(task.await.unwrap_err().is_cancelled());
    }
    assert_eq!(bytes.available_permits(), IO_BUDGET);
}
fn data_packet(declared: u32, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    packet.extend_from_slice(&(9 + payload.len() as u32).to_be_bytes());
    packet.push(103);
    packet.extend_from_slice(&1u32.to_be_bytes());
    packet.extend_from_slice(&declared.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}
async fn rejected(packet: &[u8]) {
    let (mut sender, receiver) = tokio::io::duplex(MAX_PACKET + 16);
    sender.write_all(packet).await.unwrap();
    drop(sender);
    let mut stream = BoundedSftpStream::new(receiver);
    let mut prefix = [0; 4];
    assert!(stream.read_exact(&mut prefix).await.is_err());
    assert_eq!(prefix, [0; 4]);
}
#[tokio::test]
async fn forged_data_length_is_rejected_before_length_is_exposed() {
    rejected(&data_packet(u32::MAX, &[])).await;
    rejected(&data_packet(3, b"ab")).await;
    rejected(&data_packet(
        (MAX_CHUNK + 1) as u32,
        &vec![0; MAX_CHUNK + 1],
    ))
    .await;
    let mut name = Vec::from(9u32.to_be_bytes());
    name.push(104);
    name.extend_from_slice(&1u32.to_be_bytes());
    name.extend_from_slice(&u32::MAX.to_be_bytes());
    rejected(&name).await;
    let mut handle = data_packet(4097, &vec![0; 4097]);
    handle[4] = 102;
    rejected(&handle).await;
    let mut handle = data_packet(u32::MAX, &[]);
    handle[4] = 102;
    rejected(&handle).await;
}
#[tokio::test]
async fn fragmented_valid_data_and_next_packet_keep_exact_framing() {
    let (mut sender, receiver) = tokio::io::duplex(2);
    let mut expected = data_packet(3, b"abc");
    expected.extend_from_slice(&data_packet(0, &[]));
    let sent = expected.clone();
    let writer = tokio::spawn(async move {
        for byte in sent {
            sender.write_all(&[byte]).await.unwrap();
            tokio::task::yield_now().await;
        }
    });
    let mut stream = BoundedSftpStream::new(receiver);
    let mut actual = Vec::new();
    stream.read_to_end(&mut actual).await.unwrap();
    writer.await.unwrap();
    assert_eq!(actual, expected);
}
