//! Binary SSH PTY frames. Each WebSocket message carries exactly one frame.
use crate::{ErrorCode, MAX_DATA_BYTES};

pub const TERMINAL_DATA: u8 = 1;
pub const TERMINAL_SIZE: u8 = 2;
pub const TERMINAL_READY: u8 = 3;
pub const TERMINAL_ACK: u8 = 4;
pub const TERMINAL_ACTIVITY: u8 = 5;

pub fn terminal_size(bytes: &[u8]) -> Result<(u32, u32), ErrorCode> {
    if bytes.len() != 5 || bytes[0] != TERMINAL_SIZE {
        return Err(ErrorCode::InvalidArgument);
    }
    let cols = u16::from_be_bytes([bytes[1], bytes[2]]) as u32;
    let rows = u16::from_be_bytes([bytes[3], bytes[4]]) as u32;
    if !(2..=500).contains(&cols) || !(1..=200).contains(&rows) {
        return Err(ErrorCode::InvalidArgument);
    }
    Ok((cols, rows))
}
pub fn terminal_size_frame(cols: u32, rows: u32) -> Result<Vec<u8>, ErrorCode> {
    if cols > u16::MAX as u32 || rows > u16::MAX as u32 {
        return Err(ErrorCode::InvalidArgument);
    }
    let c = (cols as u16).to_be_bytes();
    let r = (rows as u16).to_be_bytes();
    let bytes = vec![TERMINAL_SIZE, c[0], c[1], r[0], r[1]];
    terminal_size(&bytes)?;
    Ok(bytes)
}
pub fn validate_terminal_output(bytes: &[u8]) -> Result<(), ErrorCode> {
    match bytes.first() {
        Some(&TERMINAL_DATA) if (2..=MAX_DATA_BYTES).contains(&bytes.len()) => Ok(()),
        Some(&TERMINAL_SIZE) => terminal_size(bytes).map(|_| ()),
        _ => Err(ErrorCode::InvalidArgument),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frames_reject_unknown_empty_and_unbounded_sizes() {
        assert_eq!(
            terminal_size(&terminal_size_frame(120, 40).unwrap()),
            Ok((120, 40))
        );
        for (c, r) in [(0, 24), (501, 24), (80, 201), (65536, 24)] {
            assert!(terminal_size_frame(c, r).is_err());
        }
        for bytes in [
            vec![],
            vec![1],
            vec![3],
            vec![4, 0, 0, 0, 1],
            vec![2, 0, 80],
        ] {
            assert!(validate_terminal_output(&bytes).is_err());
        }
        assert!(validate_terminal_output(&vec![1; MAX_DATA_BYTES + 1]).is_err());
        assert!(validate_terminal_output(&[1, 0xff, 0xe4]).is_ok()); // PTY output is bytes, not Guacamole.
    }
}
