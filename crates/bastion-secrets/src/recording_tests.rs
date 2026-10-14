use super::*;
use std::io::Cursor;
const ID: Uuid = Uuid::from_u128(0x00112233445566778899aabbccddeeff);
const KEY: [u8; 32] = [0x42; 32];
const PREFIX: [u8; 16] = [0x10; 16];
const META:&[u8]=b"{\"type\":\"meta\",\"seq\":0,\"elapsed_us\":0,\"format_version\":2,\"connection_id\":\"00112233-4455-6677-8899-aabbccddeeff\",\"target_protocol\":\"ssh\",\"width\":1280,\"height\":720,\"dpi\":96}\n";
const END: &[u8] = b"{\"type\":\"end\",\"seq\":1,\"elapsed_us\":1,\"reason\":\"closed\"}\n";
fn key() -> RecordingKey {
    RecordingKey(Zeroizing::new(KEY))
}
fn header() -> RecordingHeader {
    RecordingHeader {
        recording_id: ID,
        connection_id: ID,
        target_protocol: TargetProtocol::Ssh,
        stream_protocol: STREAM_PROTOCOL.into(),
        nonce_prefix: PREFIX,
    }
}
fn recording() -> Vec<u8> {
    let mut w = RecordingWriter::new(Vec::new(), header(), key()).unwrap();
    let ack = w.append_ndjson(META).unwrap();
    assert_eq!(ack.chunk_seq, 0);
    assert_eq!(
        ack.bytes_written as usize,
        header_bytes(&header()).unwrap().len() + 12 + META.len() + 16
    );
    w.append_ndjson(END).unwrap();
    w.finish().unwrap()
}
fn verify(bytes: &[u8]) -> Result<()> {
    let mut r = RecordingReader::new(Cursor::new(bytes), &header(), key())?;
    while r.next_chunk()?.is_some() {}
    Ok(())
}
fn line(value: serde_json::Value) -> Vec<u8> {
    let mut v = serde_json::to_vec(&value).unwrap();
    v.push(b'\n');
    v
}
#[test]
fn golden_header_and_roundtrip() {
    let bytes = recording();
    let expected=b"{\"format_version\":2,\"recording_id\":\"00112233-4455-6677-8899-aabbccddeeff\",\"connection_id\":\"00112233-4455-6677-8899-aabbccddeeff\",\"target_protocol\":\"ssh\",\"algorithm\":\"XChaCha20-Poly1305\",\"nonce_prefix\":\"EBAQEBAQEBAQEBAQEBAQEA\"}";
    assert_eq!(&bytes[..8], b"ZTREC002");
    assert_eq!(&bytes[8..12], &(expected.len() as u32).to_be_bytes());
    assert_eq!(&bytes[12..12 + expected.len()], expected);
    assert_eq!(
        &frame_nonce(&PREFIX, 0x0102030405060708)[16..],
        &[1, 2, 3, 4, 5, 6, 7, 8]
    );
    let hash = Sha256::digest(&bytes[..12 + expected.len()]).into();
    let aad = frame_aad(&hash, ID, 1);
    assert_eq!(&aad[..12], b"zt-record-v2");
    assert_eq!(&aad[12..44], &hash);
    verify(&bytes).unwrap();
}
#[test]
fn terminal_recording_binds_renderer_and_preserves_raw_output_and_resize() {
    let mut terminal = header();
    terminal.stream_protocol = SSH_STREAM_PROTOCOL.into();
    let mut meta: serde_json::Value = serde_json::from_slice(META).unwrap();
    meta["stream_protocol"] = SSH_STREAM_PROTOCOL.into();
    let mut writer = RecordingWriter::new(Vec::new(), terminal.clone(), key()).unwrap();
    writer.append_ndjson(&line(meta.clone())).unwrap();
    for (index, bytes) in [
        bastion_domain::terminal_size_frame(120, 40).unwrap(),
        vec![1, 0xe4, 0xb8],
        vec![1, 0xad, 0xff, 27, b'[', b'm'],
    ]
    .iter()
    .enumerate()
    {
        writer.append_ndjson(&line(serde_json::json!({"type":"output","seq":index+1,"elapsed_us":index+1,"data_base64":STANDARD.encode(bytes)}))).unwrap();
    }
    writer
        .append_ndjson(&line(
            serde_json::json!({"type":"end","seq":4,"elapsed_us":4,"reason":"closed"}),
        ))
        .unwrap();
    let bytes = writer.finish().unwrap();
    assert!(RecordingReader::new(Cursor::new(&bytes), &header(), key()).is_err());
    let mut reader = RecordingReader::detect_stream(Cursor::new(&bytes), &header(), key()).unwrap();
    assert_eq!(reader.header().stream_protocol, SSH_STREAM_PROTOCOL);
    while reader.next_chunk().unwrap().is_some() {}
    let mut wrong = header();
    wrong.connection_id = Uuid::new_v4();
    assert!(RecordingReader::detect_stream(Cursor::new(&bytes), &wrong, key()).is_err());
    let mut writer = RecordingWriter::new(Vec::new(), terminal.clone(), key()).unwrap();
    meta["stream_protocol"] = STREAM_PROTOCOL.into();
    assert!(writer.append_ndjson(&line(meta)).is_err());
    for frame in [vec![3], vec![4, 0, 0, 0, 1], vec![2, 0, 0, 0, 24]] {
        let mut writer = RecordingWriter::new(Vec::new(), terminal.clone(), key()).unwrap();
        let mut meta: serde_json::Value = serde_json::from_slice(META).unwrap();
        meta["stream_protocol"] = SSH_STREAM_PROTOCOL.into();
        writer.append_ndjson(&line(meta)).unwrap();
        assert!(writer.append_ndjson(&line(serde_json::json!({"type":"output","seq":1,"elapsed_us":1,"data_base64":STANDARD.encode(frame)}))).is_err());
    }
}
#[test]
fn output_unicode_may_cross_events() {
    let output = bastion_domain::guac_encode(&["name", "中😀"]);
    let split = output.iter().position(|b| *b == 0xe4).unwrap() + 1;
    let mut w = RecordingWriter::new(Vec::new(), header(), key()).unwrap();
    w.append_ndjson(META).unwrap();
    for (i, bytes) in [&output[..split], &output[split..]].into_iter().enumerate() {
        w.append_ndjson(&line(serde_json::json!({"type":"output","seq":i+1,"elapsed_us":i+1,"data_base64":STANDARD.encode(bytes)}))).unwrap();
    }
    w.append_ndjson(&line(
        serde_json::json!({"type":"end","seq":3,"elapsed_us":3,"reason":"closed"}),
    ))
    .unwrap();
    verify(&w.finish().unwrap()).unwrap();
}
#[test]
fn every_corrupted_byte_and_truncated_prefix_rejected() {
    let bytes = recording();
    for n in 0..bytes.len() {
        assert!(verify(&bytes[..n]).is_err(), "prefix {n}");
        let mut corrupt = bytes.clone();
        corrupt[n] ^= 1;
        assert!(verify(&corrupt).is_err(), "corrupt {n}");
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(verify(&trailing).is_err());
}
#[test]
fn metadata_aad_and_previous_container_are_rejected() {
    let bytes = recording();
    for field in 0..4 {
        let mut wrong = header();
        match field {
            0 => wrong.recording_id = Uuid::new_v4(),
            1 => wrong.connection_id = Uuid::new_v4(),
            2 => wrong.target_protocol = TargetProtocol::Rdp,
            _ => wrong.nonce_prefix[0] ^= 1,
        };
        assert!(RecordingReader::new(Cursor::new(&bytes), &wrong, key()).is_err());
    }
    let mut old = bytes.clone();
    old[..8].copy_from_slice(b"ZTREC001");
    assert!(verify(&old).is_err());
    let mut oversize = bytes;
    oversize[8..12].copy_from_slice(&(MAX_HEADER_LENGTH as u32 + 1).to_be_bytes());
    assert!(verify(&oversize).is_err());
}
#[test]
fn invalid_sequence_event_shape_and_incomplete_guac_rejected() {
    for bad in [
        serde_json::json!({"type":"end","seq":2,"elapsed_us":1,"reason":"closed"}),
        serde_json::json!({"type":"input","seq":1,"elapsed_us":1,"data_base64":"eA=="}),
        serde_json::json!({"type":"output","seq":1,"elapsed_us":1,"stream":"stdout","data_base64":"eA=="}),
        serde_json::json!({"type":"resize","seq":1,"elapsed_us":1,"cols":80,"rows":24}),
        serde_json::json!({"type":"output","seq":1,"elapsed_us":1,"data_base64":"not base64"}),
        serde_json::json!({"type":"output","seq":1,"elapsed_us":1,"data_base64":STANDARD.encode(vec![0;MAX_OUTPUT_BYTES+1])}),
    ] {
        let mut w = RecordingWriter::new(Vec::new(), header(), key()).unwrap();
        w.append_ndjson(META).unwrap();
        assert!(w.append_ndjson(&line(bad)).is_err());
        assert!(w.append_ndjson(END).is_err());
    }
    let mut w = RecordingWriter::new(Vec::new(), header(), key()).unwrap();
    w.append_ndjson(META).unwrap();
    w.append_ndjson(&line(serde_json::json!({"type":"output","seq":1,"elapsed_us":1,"data_base64":STANDARD.encode(b"4.name,1.\xe4")}))).unwrap();
    assert!(w
        .append_ndjson(&line(
            serde_json::json!({"type":"end","seq":2,"elapsed_us":2,"reason":"closed"})
        ))
        .is_err());
}
#[test]
fn maximum_chunk_output_and_sequence_overflow() {
    let mut meta = META[..META.len() - 1].to_vec();
    meta.resize(MAX_CHUNK_PLAINTEXT - 1, b' ');
    meta.push(b'\n');
    let mut w = RecordingWriter::new(Vec::new(), header(), key()).unwrap();
    w.append_ndjson(&meta).unwrap();
    let output = bastion_domain::guac_encode(&["name", &"a".repeat(32754)]);
    assert_eq!(output.len(), MAX_OUTPUT_BYTES);
    w.append_ndjson(&line(serde_json::json!({"type":"output","seq":1,"elapsed_us":1,"data_base64":STANDARD.encode(output)}))).unwrap();
    w.append_ndjson(&line(
        serde_json::json!({"type":"end","seq":2,"elapsed_us":2,"reason":"closed"}),
    ))
    .unwrap();
    verify(&w.finish().unwrap()).unwrap();
    let mut w = RecordingWriter::new(Vec::new(), header(), key()).unwrap();
    w.append_ndjson(META).unwrap();
    w.next_seq = u64::MAX;
    assert!(w.append_ndjson(END).is_err());
}
#[test]
fn write_or_flush_failure_never_acknowledges() {
    struct Failing {
        calls: usize,
        flush: bool,
    }
    impl Write for Failing {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls == 1 || self.flush {
                Ok(b.len())
            } else if self.calls == 2 {
                Ok(1)
            } else {
                Err(io::Error::other("injected write failure"))
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.flush && self.calls > 1 {
                Err(io::Error::other("injected flush failure"))
            } else {
                Ok(())
            }
        }
    }
    for flush in [false, true] {
        let mut w = RecordingWriter::new(Failing { calls: 0, flush }, header(), key()).unwrap();
        assert!(w.append_ndjson(META).is_err());
        assert!(w.append_ndjson(META).is_err());
        assert!(w.finish().is_err());
    }
}
#[test]
fn final_flush_failure_cannot_finish_an_acknowledged_recording() {
    struct FinalFlushFails {
        bytes: Vec<u8>,
        flushes: usize,
    }
    impl Write for FinalFlushFails {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            if self.flushes == 4 {
                Err(io::Error::other("injected final flush failure"))
            } else {
                Ok(())
            }
        }
    }
    let mut writer = RecordingWriter::new(
        FinalFlushFails {
            bytes: Vec::new(),
            flushes: 0,
        },
        header(),
        key(),
    )
    .unwrap();
    writer.append_ndjson(META).unwrap();
    writer.append_ndjson(END).unwrap();
    assert!(writer.finish().is_err());
}
#[test]
fn reader_poisoned_after_integrity_failure() {
    let mut bytes = recording();
    *bytes.last_mut().unwrap() ^= 1;
    let mut r = RecordingReader::new(Cursor::new(bytes), &header(), key()).unwrap();
    assert!(r.next_chunk().unwrap().is_some());
    assert!(matches!(
        r.next_chunk().unwrap_err().downcast_ref::<RecordingError>(),
        Some(RecordingError::Integrity)
    ));
    assert!(matches!(
        r.next_chunk().unwrap_err().downcast_ref::<RecordingError>(),
        Some(RecordingError::Poisoned)
    ));
}
