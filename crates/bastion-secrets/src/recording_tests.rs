use super::*;
use std::io::Cursor;

const ID: Uuid = Uuid::from_u128(0x00112233445566778899aabbccddeeff);
const KEY: [u8; 32] = [0x42; 32];
const PREFIX: [u8; 16] = [0x10; 16];
const META: &[u8] = b"{\"seq\":0,\"elapsed_us\":0,\"type\":\"meta\",\"format_version\":1,\"term\":\"xterm\",\"cols\":80,\"rows\":24}\n";
const END: &[u8] = b"{\"seq\":1,\"elapsed_us\":1,\"type\":\"end\",\"reason\":\"closed\"}\n";

fn key() -> RecordingKey {
    RecordingKey(Zeroizing::new(KEY))
}
fn header() -> RecordingHeader {
    RecordingHeader {
        recording_id: ID,
        nonce_prefix: PREFIX,
    }
}
fn recording() -> Vec<u8> {
    let mut writer = RecordingWriter::new(Vec::new(), header(), key()).unwrap();
    let ack = writer.append_ndjson(META).unwrap();
    assert_eq!(ack.chunk_seq, 0);
    assert_eq!(
        ack.bytes_written as usize,
        header_bytes(&header()).unwrap().len() + 12 + META.len() + 16
    );
    let ack = writer.append_ndjson(END).unwrap();
    assert_eq!(ack.chunk_seq, 1);
    let bytes = writer.finish().unwrap();
    assert_eq!(ack.bytes_written, bytes.len() as u64);
    bytes
}
fn reader(bytes: Vec<u8>) -> RecordingReader<Cursor<Vec<u8>>> {
    RecordingReader::new(Cursor::new(bytes), &header(), key()).unwrap()
}
fn verify(bytes: Vec<u8>) -> Result<()> {
    let mut reader = RecordingReader::new(Cursor::new(bytes), &header(), key())?;
    while reader.next_chunk()?.is_some() {}
    Ok(())
}

#[test]
fn golden_codec_vector() {
    let bytes = recording();
    let expected_header = b"{\"format_version\":1,\"recording_id\":\"00112233-4455-6677-8899-aabbccddeeff\",\"algorithm\":\"XChaCha20-Poly1305\",\"nonce_prefix\":\"EBAQEBAQEBAQEBAQEBAQEA\"}";
    assert_eq!(&bytes[..8], b"ZTREC001");
    assert_eq!(&bytes[8..12], &(expected_header.len() as u32).to_be_bytes());
    assert_eq!(&bytes[12..12 + expected_header.len()], expected_header);
    assert_eq!(
        frame_nonce(&PREFIX, 0x0102030405060708)[16..],
        [1, 2, 3, 4, 5, 6, 7, 8]
    );
    let hash: [u8; 32] = Sha256::digest(&bytes[..12 + expected_header.len()]).into();
    let aad = frame_aad(&hash, ID, 0x0102030405060708);
    assert_eq!(&aad[..12], b"zt-record-v1");
    assert_eq!(&aad[12..44], &hash);
    assert_eq!(&aad[44..60], ID.as_bytes());
    assert_eq!(&aad[60..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    let expected_file = "WlRSRUMwMDEAAACTeyJmb3JtYXRfdmVyc2lvbiI6MSwicmVjb3JkaW5nX2lkIjoiMDAxMTIyMzMtNDQ1NS02Njc3LTg4OTktYWFiYmNjZGRlZWZmIiwiYWxnb3JpdGhtIjoiWENoYUNoYTIwLVBvbHkxMzA1Iiwibm9uY2VfcHJlZml4IjoiRUJBUUVCQVFFQkFRRUJBUUVCQVFFQSJ9AAAAAAAAAAAAAABtK2gnM7Ps9b+mWSkoKCzyCSSgK+UyCklQkR2mkSQBd5efSnamPo335vEBM9DtGxBomOR9SoHV/QvYAV4KzufSMCOVL8xkMHE3PNh1H4pL9mIXPCvTkXXWQQ0jj/sZBZ9b7DMeGNJluNyaM4mC4wAAAAAAAAABAAAASL/T8EmKSr6OFkdfcGUJbQWVhMLEfqLflOT10KfbHcD/LJlEK5+O5qn0HXG5md11CVVH1OhzMD1my+2VzBNjH6vpt8484CKi/A==";
    assert_eq!(STANDARD.encode(&bytes), expected_file);
    let mut reader = reader(bytes);
    assert_eq!(&*reader.next_chunk().unwrap().unwrap().plaintext, META);
    assert_eq!(&*reader.next_chunk().unwrap().unwrap().plaintext, END);
    assert!(reader.next_chunk().unwrap().is_none());
    assert!(reader.next_chunk().unwrap().is_none());
}

#[test]
fn arbitrary_output_bytes_resize_exit_and_multiple_events_round_trip() {
    // Includes invalid UTF-8, NUL and half of a multi-byte UTF-8 sequence.
    let output = vec![0xff, 0, 0xe2, 0x82, b'\r', b'\n'];
    let mut events = META.to_vec();
    let lines = [
        serde_json::json!({"seq":1,"elapsed_us":2,"type":"output","stream":"stdout","data_base64":STANDARD.encode(&output)}),
        serde_json::json!({"seq":2,"elapsed_us":3,"type":"output","stream":"stderr","data_base64":STANDARD.encode([0xac])}),
        serde_json::json!({"seq":3,"elapsed_us":4,"type":"resize","cols":100,"rows":40}),
        serde_json::json!({"seq":4,"elapsed_us":5,"type":"exit","exit_signal":"TERM"}),
        serde_json::json!({"seq":5,"elapsed_us":6,"type":"end","reason":"closed"}),
    ];
    for event in lines {
        events.extend_from_slice(&serde_json::to_vec(&event).unwrap());
        events.push(b'\n');
    }
    let mut writer = RecordingWriter::new(Vec::new(), header(), key()).unwrap();
    writer.append_ndjson(&events).unwrap();
    let bytes = writer.finish().unwrap();
    assert!(!bytes.windows(6).any(|part| part == b"stdout"));
    let mut reader = reader(bytes);
    let chunk = reader.next_chunk().unwrap().unwrap();
    assert_eq!(*chunk.plaintext, events);
    let decoded: serde_json::Value =
        serde_json::from_slice(events.split(|b| *b == b'\n').nth(1).unwrap()).unwrap();
    assert_eq!(
        STANDARD
            .decode(decoded["data_base64"].as_str().unwrap())
            .unwrap(),
        output
    );
    assert!(reader.next_chunk().unwrap().is_none());
}

#[test]
fn detects_every_truncated_prefix_and_corrupt_bytes() {
    let bytes = recording();
    for length in 0..bytes.len() {
        assert!(
            verify(bytes[..length].to_vec()).is_err(),
            "accepted prefix length {length}"
        );
    }
    for index in 0..bytes.len() {
        let mut corrupted = bytes.clone();
        corrupted[index] ^= 1;
        assert!(verify(corrupted).is_err(), "accepted corrupt byte {index}");
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(verify(trailing).is_err());
}

#[test]
fn rejects_metadata_mismatch_unknown_header_and_oversized_lengths() {
    let bytes = recording();
    let mut expected = header();
    expected.recording_id = Uuid::new_v4();
    assert!(RecordingReader::new(Cursor::new(&bytes), &expected, key()).is_err());
    expected = header();
    expected.nonce_prefix[0] ^= 1;
    assert!(RecordingReader::new(Cursor::new(&bytes), &expected, key()).is_err());
    let mut oversized = bytes.clone();
    oversized[8..12].copy_from_slice(&(MAX_HEADER_LENGTH as u32 + 1).to_be_bytes());
    assert!(verify(oversized).is_err());
    let frame = header_bytes(&header()).unwrap().len();
    let mut oversized = bytes.clone();
    oversized[frame + 8..frame + 12]
        .copy_from_slice(&(MAX_CHUNK_CIPHERTEXT as u32 + 1).to_be_bytes());
    assert!(verify(oversized).is_err());
    let mut skipped = bytes.clone();
    skipped[frame..frame + 8].copy_from_slice(&1u64.to_be_bytes());
    assert!(verify(skipped).is_err());
    let length = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let mut unknown_header = bytes[..12 + length - 1].to_vec();
    unknown_header.extend_from_slice(b",\"unexpected\":true}");
    let unknown_length = (unknown_header.len() - 12) as u32;
    unknown_header[8..12].copy_from_slice(&unknown_length.to_be_bytes());
    unknown_header.extend_from_slice(&bytes[12 + length..]);
    assert!(verify(unknown_header).is_err());
}

#[test]
fn reader_stays_poisoned_after_failure_and_wrong_dek_fails_authentication() {
    let mut bytes = recording();
    *bytes.last_mut().unwrap() ^= 1;
    let mut reader = reader(bytes);
    assert!(reader.next_chunk().unwrap().is_some());
    assert!(matches!(
        reader
            .next_chunk()
            .unwrap_err()
            .downcast_ref::<RecordingError>(),
        Some(RecordingError::Integrity)
    ));
    assert!(matches!(
        reader
            .next_chunk()
            .unwrap_err()
            .downcast_ref::<RecordingError>(),
        Some(RecordingError::Poisoned)
    ));
    let mut wrong = RecordingReader::new(
        Cursor::new(recording()),
        &header(),
        RecordingKey(Zeroizing::new([0; 32])),
    )
    .unwrap();
    assert!(matches!(
        wrong
            .next_chunk()
            .unwrap_err()
            .downcast_ref::<RecordingError>(),
        Some(RecordingError::Integrity)
    ));
}

#[test]
fn strict_event_sequence_shape_end_and_size_limits() {
    for invalid in [
        b"{}\n".as_slice(),
        b"\n".as_slice(),
        b"{\"seq\":0,\"elapsed_us\":0,\"type\":\"end\",\"reason\":\"closed\"}\n".as_slice(),
        &META[..META.len() - 1],
    ] {
        let mut writer = RecordingWriter::new(Vec::new(), header(), key()).unwrap();
        assert!(writer.append_ndjson(invalid).is_err());
        assert!(matches!(
            writer
                .append_ndjson(META)
                .unwrap_err()
                .downcast_ref::<RecordingError>(),
            Some(RecordingError::Poisoned)
        ));
    }
    let mut writer = RecordingWriter::new(Vec::new(), header(), key()).unwrap();
    writer.append_ndjson(META).unwrap();
    assert!(writer.finish().is_err());
    for bad in [
        serde_json::json!({"seq":2,"elapsed_us":1,"type":"end","reason":"closed"}),
        serde_json::json!({"seq":1,"elapsed_us":1,"type":"input","data_base64":"eA=="}),
        serde_json::json!({"seq":1,"elapsed_us":1,"type":"resize","cols":0,"rows":40}),
        serde_json::json!({"seq":1,"elapsed_us":1,"type":"output","stream":"stdout","data_base64":"not base64"}),
        serde_json::json!({"seq":1,"elapsed_us":1,"type":"output","stream":"stdout","data_base64":STANDARD.encode(vec![0; MAX_OUTPUT_BYTES+1])}),
    ] {
        let mut writer = RecordingWriter::new(Vec::new(), header(), key()).unwrap();
        writer.append_ndjson(META).unwrap();
        let mut line = serde_json::to_vec(&bad).unwrap();
        line.push(b'\n');
        assert!(writer.append_ndjson(&line).is_err());
    }
    let mut writer = RecordingWriter::new(Vec::new(), header(), key()).unwrap();
    writer.append_ndjson(META).unwrap();
    writer.append_ndjson(END).unwrap();
    assert!(writer.append_ndjson(END).is_err());
    let mut state = EventState::default();
    assert!(state
        .validate(&vec![b' '; MAX_CHUNK_PLAINTEXT + 1])
        .is_err());
}

fn unchecked_file(mut bytes: Vec<u8>, frames: &[&[u8]]) -> Vec<u8> {
    let hash: [u8; 32] = Sha256::digest(&bytes).into();
    let cipher = XChaCha20Poly1305::new_from_slice(&KEY).unwrap();
    for (seq, plaintext) in frames.iter().enumerate() {
        let seq = seq as u64;
        let ciphertext = cipher
            .encrypt(
                (&frame_nonce(&PREFIX, seq)).into(),
                Payload {
                    msg: plaintext,
                    aad: &frame_aad(&hash, ID, seq),
                },
            )
            .unwrap();
        bytes.extend_from_slice(&seq.to_be_bytes());
        bytes.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&ciphertext);
    }
    bytes
}

#[test]
fn authenticated_invalid_events_are_never_released() {
    for bad in [
        b"{}\n".as_slice(),
        b"\n".as_slice(),
        b"{\"seq\":2,\"elapsed_us\":1,\"type\":\"end\",\"reason\":\"closed\"}\n".as_slice(),
        b"{\"seq\":1,\"seq\":1,\"elapsed_us\":1,\"type\":\"end\",\"reason\":\"closed\"}\n"
            .as_slice(),
        b"{\"seq\":1,\"elapsed_us\":1,\"type\":\"end\",\"reason\":\"closed\",\"extra\":1}\n"
            .as_slice(),
    ] {
        let bytes = unchecked_file(header_bytes(&header()).unwrap(), &[META, bad]);
        let mut reader = reader(bytes);
        assert!(reader.next_chunk().unwrap().is_some());
        assert!(matches!(
            reader
                .next_chunk()
                .unwrap_err()
                .downcast_ref::<RecordingError>(),
            Some(RecordingError::Invalid(_))
        ));
        assert!(matches!(
            reader
                .next_chunk()
                .unwrap_err()
                .downcast_ref::<RecordingError>(),
            Some(RecordingError::Poisoned)
        ));
    }
}

#[test]
fn maximum_header_uses_original_bytes_in_aad_not_canonical_json() {
    let canonical = header_bytes(&header()).unwrap();
    let mut json = canonical[12..].to_vec();
    let first_padding = json.len();
    json.resize(MAX_HEADER_LENGTH, b' ');
    let mut encoded = RECORDING_MAGIC.to_vec();
    encoded.extend_from_slice(&(json.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&json);
    let mut bytes = unchecked_file(encoded, &[META, END]);
    verify(bytes.clone()).unwrap();
    // Space and tab are both valid JSON whitespace: parsing still succeeds,
    // but changing the original header bytes must invalidate frame AEAD.
    bytes[12 + first_padding] = b'\t';
    let mut reader = reader(bytes);
    assert!(matches!(
        reader
            .next_chunk()
            .unwrap_err()
            .downcast_ref::<RecordingError>(),
        Some(RecordingError::Integrity)
    ));
}

#[test]
fn exact_maximum_plaintext_and_output_and_sequence_overflow() {
    let mut meta = META[..META.len() - 1].to_vec();
    meta.resize(MAX_CHUNK_PLAINTEXT - 1, b' ');
    meta.push(b'\n');
    let mut writer = RecordingWriter::new(Vec::new(), header(), key()).unwrap();
    writer.append_ndjson(&meta).unwrap();
    let output = serde_json::json!({"seq":1,"elapsed_us":1,"type":"output","stream":"stdout","data_base64":STANDARD.encode(vec![0xff; MAX_OUTPUT_BYTES])});
    let mut output = serde_json::to_vec(&output).unwrap();
    output.push(b'\n');
    writer.append_ndjson(&output).unwrap();
    writer
        .append_ndjson(b"{\"seq\":2,\"elapsed_us\":2,\"type\":\"end\",\"reason\":\"closed\"}\n")
        .unwrap();
    let mut reader = reader(writer.finish().unwrap());
    assert_eq!(
        reader.next_chunk().unwrap().unwrap().plaintext.len(),
        MAX_CHUNK_PLAINTEXT
    );
    assert_eq!(*reader.next_chunk().unwrap().unwrap().plaintext, output);
    assert!(reader.next_chunk().unwrap().is_some());
    assert!(reader.next_chunk().unwrap().is_none());
    let mut writer = RecordingWriter::new(Vec::new(), header(), key()).unwrap();
    writer.append_ndjson(META).unwrap();
    let before = writer.bytes_written();
    writer.next_seq = u64::MAX;
    assert!(writer.append_ndjson(END).is_err());
    assert_eq!(writer.bytes_written(), before);
    assert!(matches!(
        writer
            .append_ndjson(END)
            .unwrap_err()
            .downcast_ref::<RecordingError>(),
        Some(RecordingError::Poisoned)
    ));
}

#[test]
fn failed_write_or_flush_never_acknowledges_and_prevents_retry() {
    struct Failing {
        calls: usize,
        fail_flush: bool,
    }
    impl Write for Failing {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls == 1 || self.fail_flush {
                Ok(bytes.len())
            } else if self.calls == 2 {
                Ok(1)
            } else {
                Err(io::Error::other("injected write failure"))
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush && self.calls > 1 {
                Err(io::Error::other("injected flush failure"))
            } else {
                Ok(())
            }
        }
    }
    for fail_flush in [false, true] {
        let mut writer = RecordingWriter::new(
            Failing {
                calls: 0,
                fail_flush,
            },
            header(),
            key(),
        )
        .unwrap();
        assert!(matches!(
            writer
                .append_ndjson(META)
                .unwrap_err()
                .downcast_ref::<RecordingError>(),
            Some(RecordingError::Io(_))
        ));
        assert!(matches!(
            writer
                .append_ndjson(META)
                .unwrap_err()
                .downcast_ref::<RecordingError>(),
            Some(RecordingError::Poisoned)
        ));
        assert!(writer.finish().is_err());
    }
}
