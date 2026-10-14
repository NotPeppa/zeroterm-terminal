//! Bounded, incremental Guacamole decoding. Lengths count Unicode scalar values.
use crate::{ErrorCode, MAX_DATA_BYTES};
pub const MAX_INSTRUCTION_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_INPUT_INSTRUCTION_BYTES: usize = 8192;
pub const MAX_INSTRUCTION_ELEMENTS: usize = 256;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuacInstruction {
    pub elements: Vec<String>,
    pub bytes: Vec<u8>,
}
impl GuacInstruction {
    pub fn opcode(&self) -> &str {
        self.elements.first().map(String::as_str).unwrap_or("")
    }
    pub fn args(&self) -> &[String] {
        &self.elements[1..]
    }
}
#[derive(Clone)]
pub struct GuacParser {
    limit: usize,
    raw: Vec<u8>,
    elements: Vec<String>,
    value: String,
    length: usize,
    digits: usize,
    remaining: Option<usize>,
    utf8: [u8; 4],
    utf8_len: usize,
    utf8_need: usize,
    poisoned: bool,
}
impl GuacParser {
    pub fn new(limit: usize) -> Self {
        Self {
            limit: limit.min(MAX_INSTRUCTION_BYTES),
            raw: Vec::new(),
            elements: Vec::new(),
            value: String::new(),
            length: 0,
            digits: 0,
            remaining: None,
            utf8: [0; 4],
            utf8_len: 0,
            utf8_need: 0,
            poisoned: false,
        }
    }
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<GuacInstruction>, ErrorCode> {
        if self.poisoned || chunk.len() > MAX_DATA_BYTES {
            return Err(ErrorCode::InvalidArgument);
        }
        self.poisoned = true;
        let mut completed = Vec::new();
        for &byte in chunk {
            if self.raw.len() >= self.limit {
                return Err(ErrorCode::InvalidArgument);
            }
            self.raw.push(byte);
            if self.utf8_len == 0 {
                self.utf8_need = match byte {
                    0..=0x7f => 1,
                    0xc2..=0xdf => 2,
                    0xe0..=0xef => 3,
                    0xf0..=0xf4 => 4,
                    _ => return Err(ErrorCode::InvalidArgument),
                };
            } else if !(0x80..=0xbf).contains(&byte) {
                return Err(ErrorCode::InvalidArgument);
            }
            self.utf8[self.utf8_len] = byte;
            self.utf8_len += 1;
            if self.utf8_len != self.utf8_need {
                continue;
            }
            let scalar = std::str::from_utf8(&self.utf8[..self.utf8_len])
                .map_err(|_| ErrorCode::InvalidArgument)?
                .chars()
                .next()
                .unwrap();
            self.utf8_len = 0;
            match self.remaining {
                None => {
                    if scalar.is_ascii_digit() {
                        self.digits += 1;
                        if self.digits > 8 {
                            return Err(ErrorCode::InvalidArgument);
                        }
                        self.length = self
                            .length
                            .checked_mul(10)
                            .and_then(|n| n.checked_add(scalar as usize - '0' as usize))
                            .ok_or(ErrorCode::InvalidArgument)?;
                        if self.length > self.limit {
                            return Err(ErrorCode::InvalidArgument);
                        }
                    } else if scalar == '.' && self.digits > 0 {
                        self.remaining = Some(self.length);
                    } else {
                        return Err(ErrorCode::InvalidArgument);
                    }
                }
                Some(n) if n > 0 => {
                    self.value.push(scalar);
                    self.remaining = Some(n - 1);
                }
                Some(_) => {
                    if scalar != ',' && scalar != ';' {
                        return Err(ErrorCode::InvalidArgument);
                    }
                    if self.elements.len() >= MAX_INSTRUCTION_ELEMENTS {
                        return Err(ErrorCode::InvalidArgument);
                    }
                    self.elements.push(std::mem::take(&mut self.value));
                    self.remaining = None;
                    self.length = 0;
                    self.digits = 0;
                    if scalar == ';' {
                        if self.elements[0].is_empty() {
                            return Err(ErrorCode::InvalidArgument);
                        }
                        completed.push(GuacInstruction {
                            elements: std::mem::take(&mut self.elements),
                            bytes: std::mem::take(&mut self.raw),
                        });
                    }
                }
            }
        }
        self.poisoned = false;
        Ok(completed)
    }
    pub fn finish(&self) -> Result<(), ErrorCode> {
        if self.poisoned || !self.raw.is_empty() || self.utf8_len != 0 {
            Err(ErrorCode::InvalidArgument)
        } else {
            Ok(())
        }
    }
}
pub fn guac_encode(elements: &[&str]) -> Vec<u8> {
    let mut text = String::new();
    for (i, element) in elements.iter().enumerate() {
        if i != 0 {
            text.push(',');
        }
        text.push_str(&element.chars().count().to_string());
        text.push('.');
        text.push_str(element);
    }
    text.push(';');
    text.into_bytes()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unicode_fragmentation_and_cumulative_limits() {
        let bytes = guac_encode(&["name", "中😀e\u{301}"]);
        let mut parser = GuacParser::new(1024);
        let mut result = Vec::new();
        for byte in &bytes {
            result.extend(parser.push(&[*byte]).unwrap());
        }
        assert_eq!(result[0].elements, ["name", "中😀e\u{301}"]);
        assert_eq!(result[0].bytes, bytes);
        assert!(parser.finish().is_ok());
        for bad in [
            b"4.name,1.\xff;".as_slice(),
            b"4.name,1.\xc0\x80;",
            b"4.name,1.\xed\xa0\x80;",
            b"0.;",
            b"99999999.x;",
        ] {
            assert!(GuacParser::new(1024).push(bad).is_err());
        }
        let mut parser = GuacParser::new(16);
        assert!(parser.push(b"4.name,20.").is_err());
        let mut parser = GuacParser::new(16);
        assert!(parser.push(b"4.name,8.123456").is_ok());
        assert!(parser.push(b"789;").is_err());
    }
    #[test]
    fn rejects_incomplete_eof_and_accepts_multiple_instructions() {
        let mut p = GuacParser::new(1024);
        assert_eq!(p.push(b"4.sync,1.1;4.sync,1.2;").unwrap().len(), 2);
        assert!(p.finish().is_ok());
        p.push(b"4.sync,").unwrap();
        assert!(p.finish().is_err());
    }
}
