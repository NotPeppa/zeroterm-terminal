use crate::ErrorCode;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const WEBSOCKET_VERSION: u8 = 1;
pub const MAX_DATA_BYTES: usize = 32_768;
pub const MAX_CONTROL_BYTES: usize = 8_192;
pub const BINARY_HEADER_BYTES: usize = 6;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientControl {
    Open {
        v: u8,
        channel_id: u32,
    },
    Pty {
        v: u8,
        channel_id: u32,
        term: String,
        cols: u32,
        rows: u32,
    },
    Shell {
        v: u8,
        channel_id: u32,
    },
    Resize {
        v: u8,
        channel_id: u32,
        cols: u32,
        rows: u32,
    },
    Eof {
        v: u8,
        channel_id: u32,
    },
    Close {
        v: u8,
        channel_id: u32,
    },
    Ping {
        v: u8,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerControl {
    SessionReady {
        v: u8,
        connection_id: Uuid,
    },
    Opened {
        v: u8,
        channel_id: u32,
    },
    PtyReady {
        v: u8,
        channel_id: u32,
    },
    Ready {
        v: u8,
        channel_id: u32,
    },
    Exit {
        v: u8,
        channel_id: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        exit_code: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        exit_signal: Option<String>,
    },
    Closed {
        v: u8,
        channel_id: u32,
    },
    Error {
        v: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        channel_id: Option<u32>,
        code: ErrorCode,
    },
    Pong {
        v: u8,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataStream {
    Output,
    Stderr,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientFrame {
    Control(ClientControl),
    Data { channel_id: u32, data: Vec<u8> },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerFrame {
    Control(ServerControl),
    Data {
        channel_id: u32,
        stream: DataStream,
        data: Vec<u8>,
    },
}

fn version(v: u8) -> Result<(), ErrorCode> {
    if v == WEBSOCKET_VERSION {
        Ok(())
    } else {
        Err(ErrorCode::ClientProtocolUnsupported)
    }
}
fn channel(channel_id: u32) -> Result<(), ErrorCode> {
    if channel_id != 0 {
        Ok(())
    } else {
        Err(ErrorCode::InvalidArgument)
    }
}
fn dimensions(cols: u32, rows: u32) -> Result<(), ErrorCode> {
    if (1..=4096).contains(&cols) && (1..=4096).contains(&rows) {
        Ok(())
    } else {
        Err(ErrorCode::InvalidArgument)
    }
}
impl ClientControl {
    pub fn validate(&self) -> Result<(), ErrorCode> {
        match self {
            Self::Ping { v } => version(*v),
            Self::Open { v, channel_id }
            | Self::Shell { v, channel_id }
            | Self::Eof { v, channel_id }
            | Self::Close { v, channel_id } => {
                version(*v)?;
                channel(*channel_id)
            }
            Self::Pty {
                v,
                channel_id,
                term,
                cols,
                rows,
            } => {
                version(*v)?;
                channel(*channel_id)?;
                dimensions(*cols, *rows)?;
                if term.is_empty() || term.len() > 128 || term.chars().any(char::is_control) {
                    return Err(ErrorCode::InvalidArgument);
                }
                Ok(())
            }
            Self::Resize {
                v,
                channel_id,
                cols,
                rows,
            } => {
                version(*v)?;
                channel(*channel_id)?;
                dimensions(*cols, *rows)
            }
        }
    }
}
impl ServerControl {
    pub fn validate(&self) -> Result<(), ErrorCode> {
        match self {
            Self::SessionReady { v, .. } | Self::Pong { v } => version(*v),
            Self::Opened { v, channel_id }
            | Self::PtyReady { v, channel_id }
            | Self::Ready { v, channel_id }
            | Self::Closed { v, channel_id }
            | Self::Exit { v, channel_id, .. } => {
                version(*v)?;
                channel(*channel_id)
            }
            Self::Error { v, channel_id, .. } => {
                version(*v)?;
                if let Some(id) = channel_id {
                    channel(*id)?;
                }
                Ok(())
            }
        }
    }
}
fn decode_header(bytes: &[u8]) -> Result<(u8, u32), ErrorCode> {
    if !(BINARY_HEADER_BYTES..=BINARY_HEADER_BYTES + MAX_DATA_BYTES).contains(&bytes.len()) {
        return Err(ErrorCode::InvalidArgument);
    }
    version(bytes[0])?;
    let id = u32::from_be_bytes(bytes[2..6].try_into().unwrap());
    channel(id)?;
    Ok((bytes[1], id))
}
fn encode_data(kind: u8, channel_id: u32, data: &[u8]) -> Result<Vec<u8>, ErrorCode> {
    channel(channel_id)?;
    if data.len() > MAX_DATA_BYTES {
        return Err(ErrorCode::InvalidArgument);
    }
    let mut bytes = Vec::with_capacity(BINARY_HEADER_BYTES + data.len());
    bytes.extend_from_slice(&[WEBSOCKET_VERSION, kind]);
    bytes.extend_from_slice(&channel_id.to_be_bytes());
    bytes.extend_from_slice(data);
    Ok(bytes)
}
fn decode_control<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, ErrorCode> {
    if text.len() > MAX_CONTROL_BYTES {
        return Err(ErrorCode::InvalidArgument);
    }
    serde_json::from_str(text).map_err(|_| ErrorCode::InvalidArgument)
}
fn encode_control(control: &impl Serialize) -> Result<String, ErrorCode> {
    let text = serde_json::to_string(control).map_err(|_| ErrorCode::InvalidArgument)?;
    if text.len() > MAX_CONTROL_BYTES {
        return Err(ErrorCode::InvalidArgument);
    }
    Ok(text)
}
impl ClientFrame {
    pub fn decode_text(text: &str) -> Result<Self, ErrorCode> {
        let control: ClientControl = decode_control(text)?;
        control.validate()?;
        Ok(Self::Control(control))
    }
    pub fn decode_binary(bytes: &[u8]) -> Result<Self, ErrorCode> {
        let (kind, channel_id) = decode_header(bytes)?;
        if kind != 1 {
            return Err(ErrorCode::InvalidArgument);
        }
        Ok(Self::Data {
            channel_id,
            data: bytes[6..].to_vec(),
        })
    }
    pub fn encode_binary(&self) -> Result<Vec<u8>, ErrorCode> {
        match self {
            Self::Data { channel_id, data } => encode_data(1, *channel_id, data),
            Self::Control(_) => Err(ErrorCode::InvalidArgument),
        }
    }
    pub fn encode_text(&self) -> Result<String, ErrorCode> {
        match self {
            Self::Control(control) => {
                control.validate()?;
                encode_control(control)
            }
            Self::Data { .. } => Err(ErrorCode::InvalidArgument),
        }
    }
}
impl ServerFrame {
    pub fn decode_text(text: &str) -> Result<Self, ErrorCode> {
        let control: ServerControl = decode_control(text)?;
        control.validate()?;
        Ok(Self::Control(control))
    }
    pub fn decode_binary(bytes: &[u8]) -> Result<Self, ErrorCode> {
        let (kind, channel_id) = decode_header(bytes)?;
        let stream = match kind {
            2 => DataStream::Output,
            3 => DataStream::Stderr,
            _ => return Err(ErrorCode::InvalidArgument),
        };
        Ok(Self::Data {
            channel_id,
            stream,
            data: bytes[6..].to_vec(),
        })
    }
    pub fn encode_binary(&self) -> Result<Vec<u8>, ErrorCode> {
        match self {
            Self::Data {
                channel_id,
                stream,
                data,
            } => encode_data(
                match stream {
                    DataStream::Output => 2,
                    DataStream::Stderr => 3,
                },
                *channel_id,
                data,
            ),
            Self::Control(_) => Err(ErrorCode::InvalidArgument),
        }
    }
    pub fn encode_text(&self) -> Result<String, ErrorCode> {
        match self {
            Self::Control(control) => {
                control.validate()?;
                encode_control(control)
            }
            Self::Data { .. } => Err(ErrorCode::InvalidArgument),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binary_roundtrip_preserves_raw_bytes_and_direction() {
        let input = ClientFrame::Data {
            channel_id: 0x01020304,
            data: vec![0, 255, 0xe4, 0xb8],
        };
        let bytes = input.encode_binary().unwrap();
        assert_eq!(&bytes[..6], &[1, 1, 1, 2, 3, 4]);
        assert_eq!(ClientFrame::decode_binary(&bytes).unwrap(), input);
        assert!(ServerFrame::decode_binary(&bytes).is_err());
        for stream in [DataStream::Output, DataStream::Stderr] {
            let output = ServerFrame::Data {
                channel_id: 7,
                stream,
                data: vec![255; MAX_DATA_BYTES],
            };
            let bytes = output.encode_binary().unwrap();
            assert_eq!(ServerFrame::decode_binary(&bytes).unwrap(), output);
            assert!(ClientFrame::decode_binary(&bytes).is_err());
        }
    }
    #[test]
    fn malformed_binary_is_rejected() {
        for bytes in [
            vec![],
            vec![1; 5],
            vec![1, 1, 0, 0, 0, 0],
            vec![1, 4, 0, 0, 0, 1],
            vec![1; MAX_DATA_BYTES + 7],
        ] {
            assert!(ClientFrame::decode_binary(&bytes).is_err());
        }
        assert_eq!(
            ClientFrame::decode_binary(&[2, 1, 0, 0, 0, 1]),
            Err(ErrorCode::ClientProtocolUnsupported)
        );
        assert!(ClientFrame::Data {
            channel_id: 1,
            data: vec![0; MAX_DATA_BYTES + 1]
        }
        .encode_binary()
        .is_err());
    }
    #[test]
    fn controls_validate_versions_channels_sizes_and_optional_exit() {
        let text =
            r#"{"v":1,"type":"pty","channel_id":1,"term":"xterm-256color","cols":80,"rows":24}"#;
        let frame = ClientFrame::decode_text(text).unwrap();
        assert_eq!(
            ClientFrame::decode_text(&frame.encode_text().unwrap()).unwrap(),
            frame
        );
        for text in [
            r#"{"type":"ping"}"#,
            r#"{"v":1,"type":"open","channel_id":0}"#,
            r#"{"v":1,"type":"resize","channel_id":1,"cols":0,"rows":24}"#,
            r#"{"v":1,"type":"exec","channel_id":1}"#,
        ] {
            assert!(ClientFrame::decode_text(text).is_err());
        }
        assert_eq!(
            ClientFrame::decode_text(r#"{"v":2,"type":"ping"}"#),
            Err(ErrorCode::ClientProtocolUnsupported)
        );
        assert!(ClientFrame::decode_text(&" ".repeat(MAX_CONTROL_BYTES + 1)).is_err());
        let exit = ServerFrame::Control(ServerControl::Exit {
            v: 1,
            channel_id: 1,
            exit_code: Some(7),
            exit_signal: None,
        });
        let encoded = exit.encode_text().unwrap();
        assert!(!encoded.contains("exit_signal"));
        assert_eq!(ServerFrame::decode_text(&encoded).unwrap(), exit);
    }
}
