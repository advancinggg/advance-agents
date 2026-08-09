//! `InteractiveApproval` (Slice B, AC-07) — stdin-driven `ApprovalStrategy`.
//!
//! AC-07 boundary: "Admin approval required when `required-capabilities` is
//! non-trivial". Short-circuits `Ok(true)` when `manifest.required_capabilities`
//! is empty.
//!
//! Bounded 16-byte ASCII-only line read; default reject.

use std::io::{BufRead, Write};
use std::sync::Mutex;

use async_trait::async_trait;

use crate::error::PackError;
use crate::install::ApprovalStrategy;
use crate::manifest::PackManifest;

const MAX_LINE_BYTES: usize = 16;

pub struct InteractiveApproval<W, R> {
    writer: Mutex<W>,
    reader: Mutex<R>,
}

impl<W, R> InteractiveApproval<W, R>
where
    W: Write + Send + 'static,
    R: BufRead + Send + 'static,
{
    pub fn new(writer: W, reader: R) -> Self {
        Self {
            writer: Mutex::new(writer),
            reader: Mutex::new(reader),
        }
    }
}

impl InteractiveApproval<std::io::Stdout, std::io::BufReader<std::io::Stdin>> {
    pub fn new_stdin() -> Self {
        Self::new(std::io::stdout(), std::io::BufReader::new(std::io::stdin()))
    }
}

#[async_trait]
impl<W, R> ApprovalStrategy for InteractiveApproval<W, R>
where
    W: Write + Send + 'static,
    R: BufRead + Send + 'static,
{
    async fn approve(&self, manifest: &PackManifest) -> Result<bool, PackError> {
        // AC-07 short-circuit: trivial install (empty required-capabilities) does
        // not require admin approval. Approve without prompting.
        if manifest.required_capabilities.is_empty() {
            return Ok(true);
        }
        let caps_str = manifest.required_capabilities.join(", ");
        let trust_str = format!("{:?}", manifest.trust_level).to_lowercase();
        {
            let mut w = self.writer.lock().expect("writer mutex poisoned");
            writeln!(w, "Pack: {}@{}", manifest.name, manifest.version).map_err(|e| {
                PackError::Io {
                    path: std::path::PathBuf::from("<stdout>"),
                    source: e,
                }
            })?;
            writeln!(w, "Required capabilities: [{caps_str}]").map_err(|e| PackError::Io {
                path: std::path::PathBuf::from("<stdout>"),
                source: e,
            })?;
            writeln!(w, "Trust level: {trust_str}").map_err(|e| PackError::Io {
                path: std::path::PathBuf::from("<stdout>"),
                source: e,
            })?;
            write!(w, "Approve? [y/N] ").map_err(|e| PackError::Io {
                path: std::path::PathBuf::from("<stdout>"),
                source: e,
            })?;
            w.flush().map_err(|e| PackError::Io {
                path: std::path::PathBuf::from("<stdout>"),
                source: e,
            })?;
        }
        let line = {
            let mut r = self.reader.lock().expect("reader mutex poisoned");
            match read_bounded_line(&mut *r) {
                Ok(s) => s,
                Err(_) => return Err(PackError::AdminRejected),
            }
        };
        let answer = line.trim().to_lowercase();
        Ok(matches!(answer.as_str(), "y" | "yes"))
    }
}

/// Read up to `MAX_LINE_BYTES` (16) bytes from `reader`, stopping early at:
/// - `\n` (newline; consumed but NOT appended)
/// - EOF (returns whatever was read)
/// - Non-ASCII byte (>= 0x80) → `InvalidData` error
/// - ASCII control byte (< 0x20, except `\t`) → `InvalidData` error
///
/// Works for both interactive stdin (returns at `\n`) and `Cursor<&[u8]>`
/// (returns at EOF or after 16 bytes). The returned `String` is guaranteed
/// to contain only ASCII printable bytes plus `\t`.
fn read_bounded_line<R: BufRead>(reader: &mut R) -> std::io::Result<String> {
    let mut buf = Vec::with_capacity(MAX_LINE_BYTES);
    let mut byte = [0u8; 1];
    for _ in 0..MAX_LINE_BYTES {
        match reader.read(&mut byte) {
            Ok(0) => break, // EOF
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) if byte[0] >= 0x80 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "non-ASCII byte in admin response",
                ));
            }
            Ok(_) if byte[0] < 0x20 && byte[0] != b'\t' => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "ASCII control byte in admin response",
                ));
            }
            Ok(_) => buf.push(byte[0]),
            Err(e) => return Err(e),
        }
    }
    Ok(String::from_utf8(buf).expect("ASCII bytes verified above"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_bounded_line_handles_newline() {
        let mut r = Cursor::new(b"yes\nrest".to_vec());
        let s = read_bounded_line(&mut r).unwrap();
        assert_eq!(s, "yes");
    }

    #[test]
    fn read_bounded_line_handles_eof() {
        let mut r = Cursor::new(b"y".to_vec());
        let s = read_bounded_line(&mut r).unwrap();
        assert_eq!(s, "y");
    }

    #[test]
    fn read_bounded_line_caps_at_16_bytes() {
        let mut r = Cursor::new(b"yyyyyyyyyyyyyyyyEXTRA".to_vec()); // 16 'y' + EXTRA
        let s = read_bounded_line(&mut r).unwrap();
        assert_eq!(s.len(), 16);
        assert!(s.chars().all(|c| c == 'y'));
    }

    #[test]
    fn read_bounded_line_rejects_non_ascii() {
        let mut r = Cursor::new(vec![b'y', 0xFF, b'\n']);
        let e = read_bounded_line(&mut r).expect_err("expected non-ASCII rejection");
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_bounded_line_rejects_control_byte() {
        let mut r = Cursor::new(vec![b'y', 0x07, b'\n']); // bell
        let e = read_bounded_line(&mut r).expect_err("expected control rejection");
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_bounded_line_accepts_tab() {
        let mut r = Cursor::new(b"y\tes\n".to_vec());
        let s = read_bounded_line(&mut r).unwrap();
        assert_eq!(s, "y\tes");
    }
}
