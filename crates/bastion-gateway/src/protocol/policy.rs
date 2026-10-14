use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::VecDeque;
use zeroize::Zeroizing;
const MAX_CLIPBOARD_BYTES: usize = 256 * 1024;
#[derive(Default)]
struct ClipboardStreams(HashMap<u32, (bool, Zeroizing<Vec<u8>>)>);
impl ClipboardStreams {
    fn start(&mut self, id: u32) -> Result<(), ErrorCode> {
        if self.0.get(&id).is_some_and(|s| s.0)
            || self.0.values().filter(|s| s.0).count() >= 4
            || (!self.0.contains_key(&id) && self.0.len() >= 256)
        {
            return Err(ErrorCode::TargetRequestRejected);
        }
        self.0.insert(id, (true, Zeroizing::new(Vec::new())));
        Ok(())
    }
    fn blob(&mut self, id: u32, encoded: &str) -> Result<(), ErrorCode> {
        let state = self
            .0
            .get_mut(&id)
            .filter(|s| s.0)
            .ok_or(ErrorCode::TargetRequestRejected)?;
        if encoded.len() > MAX_DATA_BYTES.div_ceil(3) * 4 {
            return Err(ErrorCode::TargetRequestRejected);
        }
        let bytes = Zeroizing::new(
            STANDARD
                .decode(encoded)
                .map_err(|_| ErrorCode::InvalidArgument)?,
        );
        if state.1.len() + bytes.len() > MAX_CLIPBOARD_BYTES {
            return Err(ErrorCode::TargetRequestRejected);
        }
        state.1.extend_from_slice(&bytes);
        Ok(())
    }
    fn end(&mut self, id: u32, latin1: bool) -> Result<Zeroizing<Vec<u8>>, ErrorCode> {
        let state = self
            .0
            .get_mut(&id)
            .filter(|s| s.0)
            .ok_or(ErrorCode::TargetRequestRejected)?;
        let text = std::str::from_utf8(&state.1).map_err(|_| ErrorCode::InvalidArgument)?;
        if text.contains('\0') || latin1 && text.chars().any(|c| u32::from(c) > 255) {
            return Err(ErrorCode::TargetRequestRejected);
        }
        state.0 = false;
        Ok(std::mem::take(&mut state.1))
    }
    fn contains(&self, id: u32) -> bool {
        self.0.contains_key(&id)
    }
    fn open(&self, id: u32) -> bool {
        self.0.get(&id).is_some_and(|s| s.0)
    }
}
pub(crate) struct InstructionPolicy {
    display_streams: HashMap<u32, bool>,
    clipboard_output: ClipboardStreams,
    clipboard_input: ClipboardStreams,
    completed_clipboard: Option<(u32, Zeroizing<Vec<u8>>)>,
    syncs: VecDeque<u64>,
    startup_acks: VecDeque<u64>,
    layers: HashMap<i32, (u32, u32)>,
    target_ready: bool,
    protocol: TargetProtocol,
}
impl Default for InstructionPolicy {
    fn default() -> Self {
        Self {
            display_streams: HashMap::new(),
            clipboard_output: ClipboardStreams::default(),
            clipboard_input: ClipboardStreams::default(),
            completed_clipboard: None,
            syncs: VecDeque::new(),
            startup_acks: VecDeque::new(),
            layers: HashMap::new(),
            target_ready: false,
            protocol: TargetProtocol::Ssh,
        }
    }
}
fn number(value: &str, max: u32) -> Result<u32, ErrorCode> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ErrorCode::InvalidArgument);
    }
    let n = value
        .parse::<u32>()
        .map_err(|_| ErrorCode::InvalidArgument)?;
    if n > max {
        Err(ErrorCode::InvalidArgument)
    } else {
        Ok(n)
    }
}
fn stream(value: &str) -> Result<u32, ErrorCode> {
    number(value, i32::MAX as u32)
}
fn timestamp(value: &str) -> Result<u64, ErrorCode> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ErrorCode::InvalidArgument);
    }
    value.parse().map_err(|_| ErrorCode::InvalidArgument)
}
fn layer(value: &str) -> Result<i32, ErrorCode> {
    let id = value
        .parse::<i32>()
        .map_err(|_| ErrorCode::InvalidArgument)?;
    if (-4096..=4096).contains(&id) {
        Ok(id)
    } else {
        Err(ErrorCode::TargetRequestRejected)
    }
}
impl InstructionPolicy {
    pub(crate) fn for_protocol(protocol: TargetProtocol) -> Self {
        Self {
            protocol,
            ..Self::default()
        }
    }
    pub(crate) fn finish(&self) -> Result<(), ErrorCode> {
        if self.display_streams.values().any(|open| *open) {
            Err(ErrorCode::TargetRequestRejected)
        } else {
            Ok(())
        }
    }
    pub(crate) fn startup(&mut self, instruction: &GuacInstruction) -> Result<bool, ErrorCode> {
        if instruction.opcode() == "zt-target-ready" {
            if self.target_ready || !instruction.args().is_empty() {
                return Err(ErrorCode::TargetProtocolUnavailable);
            }
            self.target_ready = true;
            Ok(true)
        } else {
            self.server(instruction)?;
            Ok(false)
        }
    }
    fn acknowledge_sync(&mut self, stamp: u64) -> Result<(), ErrorCode> {
        let index = self
            .syncs
            .iter()
            .position(|value| *value == stamp)
            .ok_or(ErrorCode::TargetRequestRejected)?;
        self.syncs.drain(..=index);
        Ok(())
    }
    pub(crate) fn startup_sync(&mut self, instruction: &GuacInstruction) -> Result<(), ErrorCode> {
        if self.target_ready || instruction.opcode() != "sync" || self.startup_acks.len() >= 64 {
            return Err(ErrorCode::TargetRequestRejected);
        }
        let stamp = timestamp(&instruction.args()[0])?;
        self.acknowledge_sync(stamp)?;
        self.startup_acks.push_back(stamp);
        Ok(())
    }
    /// These exact timestamps were already ACKed by the gateway while output was gated.
    pub(crate) fn replayed_sync(&self, instruction: &GuacInstruction) -> bool {
        instruction.opcode() == "sync"
            && instruction
                .args()
                .first()
                .and_then(|value| timestamp(value).ok())
                .is_some_and(|stamp| self.startup_acks.contains(&stamp))
    }
    pub(crate) fn server(&mut self, instruction: &GuacInstruction) -> Result<(), ErrorCode> {
        let a = instruction.args();
        if instruction.elements.iter().any(|s| s.contains('\0')) {
            return Err(ErrorCode::InvalidArgument);
        }
        match instruction.opcode() {
            "clipboard" => {
                if a.len() != 2 || a[1] != "text/plain" {
                    return Err(ErrorCode::TargetRequestRejected);
                }
                let id = stream(&a[0])?;
                if self.display_streams.get(&id) == Some(&true) {
                    return Err(ErrorCode::TargetRequestRejected);
                }
                self.clipboard_output.start(id)?;
                self.display_streams.remove(&id);
            }
            "img" => {
                if a.len() != 6
                    || !matches!(a[3].as_str(), "image/png" | "image/jpeg" | "image/webp")
                {
                    return Err(ErrorCode::TargetRequestRejected);
                }
                let id = stream(&a[0])?;
                if self.clipboard_output.open(id) {
                    return Err(ErrorCode::TargetRequestRejected);
                }
                if self.display_streams.get(&id) == Some(&true)
                    || (!self.display_streams.contains_key(&id)
                        && self.display_streams.len() >= 256)
                {
                    return Err(ErrorCode::TargetRequestRejected);
                }
                self.display_streams.insert(id, true);
                self.clipboard_output.0.remove(&id);
            }
            "blob" => {
                if a.len() == 2 && self.clipboard_output.contains(stream(&a[0])?) {
                    return self.clipboard_output.blob(stream(&a[0])?, &a[1]);
                }
                if a.len() != 2 || self.display_streams.get(&stream(&a[0])?) != Some(&true) {
                    return Err(ErrorCode::TargetRequestRejected);
                }
            }
            "end" => {
                if a.len() == 1 && self.clipboard_output.contains(stream(&a[0])?) {
                    return self.clipboard_output.end(stream(&a[0])?, false).map(|_| ());
                }
                if a.len() != 1 || self.display_streams.get(&stream(&a[0])?) != Some(&true) {
                    return Err(ErrorCode::TargetRequestRejected);
                }
                self.display_streams.insert(stream(&a[0])?, false);
            }
            "ack" => {
                if a.len() != 3
                    || !self.clipboard_input.contains(stream(&a[0])?)
                    || a[1].len() > 128
                    || a[1].chars().any(char::is_control)
                {
                    return Err(ErrorCode::TargetRequestRejected);
                }
                number(&a[2], 65535)?;
            }
            "sync" => {
                if !(1..=2).contains(&a.len()) || self.syncs.len() >= 64 {
                    return Err(ErrorCode::TargetRequestRejected);
                }
                let stamp = timestamp(&a[0])?;
                if self.syncs.back().is_some_and(|last| stamp < *last) {
                    return Err(ErrorCode::InvalidArgument);
                }
                if a.len() == 2 {
                    number(&a[1], u32::MAX)?;
                }
                self.syncs.push_back(stamp);
            }
            "size" => {
                if a.len() != 3 {
                    return Err(ErrorCode::InvalidArgument);
                }
                let id = layer(&a[0])?;
                let width = number(&a[1], 3840)?;
                let height = number(&a[2], 2160)?;
                if (id == 0 && (width == 0 || height == 0))
                    || (self.layers.len() >= 64 && !self.layers.contains_key(&id))
                {
                    return Err(ErrorCode::TargetRequestRejected);
                }
                let pixels: u64 = self
                    .layers
                    .iter()
                    .filter(|(key, _)| **key != id)
                    .map(|(_, (w, h))| u64::from(*w) * u64::from(*h))
                    .sum();
                if pixels + u64::from(width) * u64::from(height) > 32 * 1024 * 1024 {
                    return Err(ErrorCode::TargetRequestRejected);
                }
                self.layers.insert(id, (width, height));
            }
            "dispose" => {
                if a.len() != 1 {
                    return Err(ErrorCode::InvalidArgument);
                }
                let id = layer(&a[0])?;
                if id == 0 {
                    return Err(ErrorCode::TargetRequestRejected);
                }
                self.layers.remove(&id);
            }
            "name" => {
                if a.len() != 1 || a[0].len() > 1024 {
                    return Err(ErrorCode::InvalidArgument);
                }
            }
            "mouse" => {
                if !matches!(a.len(), 2 | 4) {
                    return Err(ErrorCode::InvalidArgument);
                }
                for (value, bound) in [(&a[0], 3840), (&a[1], 2160)] {
                    let coordinate = value
                        .parse::<i32>()
                        .map_err(|_| ErrorCode::InvalidArgument)?;
                    if !(-bound..=bound).contains(&coordinate) {
                        return Err(ErrorCode::TargetRequestRejected);
                    }
                }
                if a.len() == 4 {
                    number(&a[2], 31)?;
                    timestamp(&a[3])?;
                }
            }
            "error" => {
                if self.protocol == TargetProtocol::Ssh
                    && a.first().is_some_and(|message| {
                        message.starts_with("Host key did not match")
                            || message.starts_with("Host key does not match")
                    })
                {
                    return Err(ErrorCode::TargetHostKeyChanged);
                }
                return Err(ErrorCode::TargetAuthFailed);
            }
            "disconnect" => {
                if !a.is_empty() {
                    return Err(ErrorCode::InvalidArgument);
                }
            }
            "nop" => {
                if !a.is_empty() {
                    return Err(ErrorCode::InvalidArgument);
                }
            }
            // Drawing-only closed set. No nested instructions or arbitrary stream creation.
            "arc" | "cfill" | "clip" | "close" | "copy" | "cstroke" | "cursor" | "distort"
            | "identity" | "jpeg" | "lfill" | "line" | "lstroke" | "move" | "png" | "pop"
            | "push" | "rect" | "reset" | "set" | "shade" | "start" | "transfer" | "transform" => {
                if a.is_empty() || a.len() > 16 {
                    return Err(ErrorCode::InvalidArgument);
                }
            }
            _ => return Err(ErrorCode::TargetRequestRejected),
        }
        Ok(())
    }
    pub(crate) fn client(&mut self, instruction: &GuacInstruction) -> Result<bool, ErrorCode> {
        let a = instruction.args();
        match instruction.opcode() {
            "clipboard" if a.len() == 2 && a[1] == "text/plain" => {
                self.clipboard_input.start(stream(&a[0])?)?;
                Ok(false)
            }
            "blob" if a.len() == 2 => {
                self.clipboard_input.blob(stream(&a[0])?, &a[1])?;
                Ok(true)
            }
            "end" if a.len() == 1 => {
                let id = stream(&a[0])?;
                let text = self
                    .clipboard_input
                    .end(id, self.protocol == TargetProtocol::Vnc)?;
                self.completed_clipboard = Some((id, text));
                Ok(false)
            }
            "key" if a.len() == 2 => {
                let key = number(&a[0], 0x1fffffff)?;
                if (0x0100d800..=0x0100dfff).contains(&key) {
                    return Err(ErrorCode::InvalidArgument);
                }
                if (0x01010000..=0x0110ffff).contains(&key) && self.protocol != TargetProtocol::Vnc
                {
                    return Err(ErrorCode::TargetRequestRejected);
                }
                number(&a[1], 1)?;
                Ok(true)
            }
            "mouse" if a.len() == 3 => {
                // Resize output and input cross in flight; bound by the display ceiling,
                // not the newest server dimensions which the browser may not have received.
                number(&a[0], 3839)?;
                number(&a[1], 2159)?;
                number(&a[2], 31)?;
                Ok(true)
            }
            "size" if (2..=3).contains(&a.len()) => {
                let width = number(&a[0], 3840)?;
                let height = number(&a[1], 2160)?;
                let dpi = if a.len() == 3 {
                    number(&a[2], 192)?
                } else {
                    96
                };
                Display { width, height, dpi }.validate()?;
                Ok(false)
            }
            "sync" if (1..=2).contains(&a.len()) => {
                let stamp = timestamp(&a[0])?;
                if a.len() == 2 {
                    number(&a[1], u32::MAX)?;
                }
                if let Some(index) = self.startup_acks.iter().position(|value| *value == stamp) {
                    self.startup_acks.drain(..=index);
                } else {
                    self.acknowledge_sync(stamp)?;
                }
                Ok(false)
            }
            // Late image ACKs after end are legal, but only for bounded known drawing ids.
            "ack" if a.len() == 3 => {
                let id = stream(&a[0])?;
                if !(self.display_streams.contains_key(&id) || self.clipboard_output.contains(id))
                    || a[1].len() > 128
                    || a[1].chars().any(char::is_control)
                {
                    return Err(ErrorCode::TargetRequestRejected);
                }
                number(&a[2], 65535)?;
                Ok(false)
            }
            "nop" | "disconnect" if a.is_empty() => Ok(false),
            _ => Err(ErrorCode::TargetRequestRejected),
        }
    }
    pub(crate) fn recordable(&self, instruction: &GuacInstruction) -> bool {
        match instruction.opcode() {
            "clipboard" | "ack" => false,
            "blob" | "end" => instruction
                .args()
                .first()
                .and_then(|v| v.parse::<u32>().ok())
                .is_some_and(|id| !self.clipboard_output.contains(id)),
            _ => true,
        }
    }
    pub(crate) fn take_clipboard(&mut self) -> Option<(u32, Zeroizing<Vec<u8>>)> {
        self.completed_clipboard.take()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn i(e: &[&str]) -> GuacInstruction {
        GuacInstruction {
            elements: e.iter().map(|s| s.to_string()).collect(),
            bytes: guac_encode(e),
        }
    }
    #[test]
    fn ssh_pin_mismatch_is_distinct_from_bad_credentials() {
        let mut ssh = InstructionPolicy::for_protocol(TargetProtocol::Ssh);
        assert_eq!(
            ssh.server(&i(&[
                "error",
                "Host key did not match any provided known host keys.",
                "512"
            ])),
            Err(ErrorCode::TargetHostKeyChanged)
        );
        assert_eq!(
            ssh.server(&i(&["error", "Password authentication failed", "512"])),
            Err(ErrorCode::TargetAuthFailed)
        );
    }
    #[test]
    fn drawing_streams_are_allowed_and_owned_without_blanket_block() {
        let mut p = InstructionPolicy::default();
        assert!(p.server(&i(&["blob", "7", "aA=="])).is_err());
        assert!(p
            .server(&i(&["img", "7", "14", "0", "image/png", "0", "0"]))
            .is_ok());
        assert!(p.server(&i(&["blob", "7", "aA=="])).is_ok());
        assert!(p.finish().is_err());
        assert!(p.client(&i(&["ack", "7", "OK", "0"])).is_ok());
        assert!(p.client(&i(&["ack", "8", "OK", "0"])).is_err());
        assert!(p.server(&i(&["end", "7"])).is_ok());
        p.finish().unwrap();
        assert!(p.server(&i(&["blob", "7", "aA=="])).is_err());
        assert!(p.client(&i(&["ack", "7", "OK", "0"])).is_ok());
        for op in [
            "audio",
            "video",
            "file",
            "pipe",
            "filesystem",
            "argv",
            "nest",
            "zt-target-ready",
        ] {
            assert!(p.server(&i(&[op, "1"])).is_err());
            assert!(p.client(&i(&[op, "1"])).is_err());
        }
        for op in ["select", "args", "connect", "join"] {
            assert!(p.client(&i(&[op, "ssh"])).is_err());
        }
    }
    #[test]
    fn clipboard_is_text_only_bounded_owned_and_not_recorded() {
        let mut p = InstructionPolicy::default();
        assert!(p.client(&i(&["blob", "0", "eA=="])).is_err());
        assert!(p.server(&i(&["ack", "0", "OK", "0"])).is_err());
        assert!(p.client(&i(&["clipboard", "0", "image/png"])).is_err());
        assert!(p.server(&i(&["clipboard", "0", "text/html"])).is_err());
        p.client(&i(&["clipboard", "0", "text/plain"])).unwrap();
        p.server(&i(&["ack", "0", "OK", "0"])).unwrap();
        for data in [STANDARD.encode([0xe4]), STANDARD.encode([0xb8, 0xad])] {
            p.client(&i(&["blob", "0", &data])).unwrap();
        }
        p.client(&i(&["end", "0"])).unwrap();
        assert_eq!(p.take_clipboard().unwrap().1.as_slice(), "中".as_bytes());
        assert!(p.client(&i(&["blob", "0", "eA=="])).is_err());
        p.server(&i(&["clipboard", "0", "text/plain"])).unwrap();
        assert!(p
            .server(&i(&["img", "0", "14", "0", "image/png", "0", "0"]))
            .is_err());
        for instruction in [
            i(&["clipboard", "0", "text/plain"]),
            i(&["blob", "0", "eA=="]),
            i(&["end", "0"]),
        ] {
            assert!(!p.recordable(&instruction));
        }
        p.server(&i(&["blob", "0", "eA=="])).unwrap();
        p.client(&i(&["ack", "0", "OK", "0"])).unwrap();
        p.server(&i(&["end", "0"])).unwrap();
        p.server(&i(&["img", "0", "14", "0", "image/png", "0", "0"]))
            .unwrap();
        assert!(p.recordable(&i(&["blob", "0", "eA=="])));
        p.server(&i(&["blob", "0", "eA=="])).unwrap();
        p.server(&i(&["end", "0"])).unwrap();
        p.client(&i(&["clipboard", "0", "text/plain"])).unwrap();
        let large = STANDARD.encode(vec![b'x'; MAX_DATA_BYTES]);
        for _ in 0..8 {
            p.client(&i(&["blob", "0", &large])).unwrap();
        }
        assert!(p.client(&i(&["blob", "0", "eA=="])).is_err());
        p.client(&i(&["end", "0"])).unwrap();
        p.client(&i(&["clipboard", "0", "text/plain"])).unwrap();
        p.client(&i(&["blob", "0", &STANDARD.encode([0xff])]))
            .unwrap();
        assert!(p.client(&i(&["end", "0"])).is_err());
        let mut vnc = InstructionPolicy::for_protocol(TargetProtocol::Vnc);
        vnc.client(&i(&["clipboard", "0", "text/plain"])).unwrap();
        vnc.client(&i(&["blob", "0", &STANDARD.encode("中".as_bytes())]))
            .unwrap();
        assert_eq!(
            vnc.client(&i(&["end", "0"])),
            Err(ErrorCode::TargetRequestRejected)
        );
    }
    #[test]
    fn only_actual_keyboard_mouse_activity_resets_idle() {
        let mut p = InstructionPolicy::default();
        assert_eq!(p.client(&i(&["key", "65", "1"])), Ok(true));
        assert_eq!(p.client(&i(&["mouse", "10", "20", "0"])), Ok(true));
        assert!(p.client(&i(&["sync", "100"])).is_err());
        p.server(&i(&["sync", "100"])).unwrap();
        assert_eq!(p.client(&i(&["sync", "100"])), Ok(false));
        assert!(p.client(&i(&["sync", "100"])).is_err());
        assert_eq!(p.client(&i(&["size", "1280", "720", "96"])), Ok(false));
        assert!(p.client(&i(&["size", "3841", "720"])).is_err());
    }
    #[test]
    fn mouse_coordinates_survive_resize_in_flight_with_global_bounds() {
        let mut policy = InstructionPolicy::default();
        policy.server(&i(&["size", "0", "1662", "778"])).unwrap();
        policy.server(&i(&["size", "0", "542", "318"])).unwrap();
        assert_eq!(policy.client(&i(&["mouse", "1661", "777", "1"])), Ok(true));
        for args in [
            ["mouse", "-1", "0", "0"],
            ["mouse", "3840", "0", "0"],
            ["mouse", "0", "2160", "0"],
            ["mouse", "0", "0", "32"],
        ] {
            assert_eq!(policy.client(&i(&args)), Err(ErrorCode::InvalidArgument));
        }
    }
    #[test]
    fn framebuffer_layers_and_surrogate_keys_are_bounded() {
        let mut p = InstructionPolicy::default();
        p.server(&i(&["size", "1", "0", "0"])).unwrap();
        assert!(p.server(&i(&["size", "0", "0", "0"])).is_err());
        p.server(&i(&["mouse", "0", "0"])).unwrap();
        p.server(&i(&["mouse", "0", "0", "0", "438053138"]))
            .unwrap();
        assert!(p.server(&i(&["mouse", "0", "0", "0"])).is_err());
        assert!(p.server(&i(&["mouse", "3841", "0"])).is_err());
        assert!(p.server(&i(&["size", "0", "65535", "65535"])).is_err());
        p.server(&i(&["size", "0", "800", "600"])).unwrap();
        assert!(p.client(&i(&["mouse", "800", "100", "0"])).is_ok());
        assert!(p.client(&i(&["mouse", "799", "599", "0"])).is_ok());
        for id in [-1, -2, -3] {
            p.server(&i(&["size", &id.to_string(), "3840", "2160"]))
                .unwrap();
        }
        assert!(p.server(&i(&["size", "-4", "3840", "2160"])).is_err());
        p.server(&i(&["dispose", "-1"])).unwrap();
        p.server(&i(&["size", "-4", "3840", "2160"])).unwrap();
        assert!(p
            .client(&i(&["key", &0x0100d800u32.to_string(), "1"]))
            .is_err());
        assert!(p
            .client(&i(&["key", &0x0101f600u32.to_string(), "1"]))
            .is_err());
        assert!(InstructionPolicy::for_protocol(TargetProtocol::Vnc)
            .client(&i(&["key", &0x0101f600u32.to_string(), "1"]))
            .is_ok());
    }
    #[test]
    fn readiness_marker_is_internal_exactly_once_and_never_client_input() {
        let mut p = InstructionPolicy::default();
        assert!(p.startup(&i(&["zt-target-ready", "true"])).is_err());
        assert_eq!(p.startup(&i(&["zt-target-ready"])), Ok(true));
        assert!(p.startup(&i(&["zt-target-ready"])).is_err());
        assert!(p.server(&i(&["zt-target-ready"])).is_err());
        assert!(p.client(&i(&["zt-target-ready"])).is_err());
    }
    #[test]
    fn startup_sync_acks_are_consumed_internally_and_replay_once() {
        let mut p = InstructionPolicy::default();
        for stamp in [100, 101] {
            let sync = i(&["sync", &stamp.to_string()]);
            p.startup(&sync).unwrap();
            p.startup_sync(&sync).unwrap();
        }
        assert!(p.syncs.is_empty());
        p.startup(&i(&["zt-target-ready"])).unwrap();
        for stamp in [100, 101] {
            let sync = i(&["sync", &stamp.to_string()]);
            assert!(p.replayed_sync(&sync));
            assert_eq!(p.client(&sync), Ok(false));
            assert!(!p.replayed_sync(&sync));
            assert!(p.client(&sync).is_err());
        }
        let sync = i(&["sync", "102"]);
        p.server(&sync).unwrap();
        assert!(!p.replayed_sync(&sync));
        p.client(&sync).unwrap();
        assert!(p.client(&sync).is_err());
    }
}
