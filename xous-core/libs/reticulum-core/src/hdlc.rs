//! HDLC framing used by Reticulum's `TCPClientInterface`.
//!
//! Frames are delimited by the flag byte `0x7E`. Within a frame, occurrences of
//! the flag and the escape byte `0x7D` are escaped as `ESC, b ^ 0x20`. This
//! matches `RNS/Interfaces/TCPInterface.py`.

pub const FLAG: u8 = 0x7E;
pub const ESC: u8 = 0x7D;
pub const ESC_MASK: u8 = 0x20;

/// Frame a single packet for transmission: `FLAG || escaped(data) || FLAG`.
pub fn frame(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 2);
    out.push(FLAG);
    for &b in data {
        if b == FLAG || b == ESC {
            out.push(ESC);
            out.push(b ^ ESC_MASK);
        } else {
            out.push(b);
        }
    }
    out.push(FLAG);
    out
}

/// Incremental deframer: feed it bytes off the socket; it yields complete,
/// unescaped packets as it finds closing flags.
#[derive(Default)]
pub struct Deframer {
    buf: Vec<u8>,
    in_frame: bool,
    escaped: bool,
}

impl Deframer {
    pub fn new() -> Deframer { Deframer::default() }

    /// Push received bytes; returns any complete packets that were finished.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        for &b in bytes {
            match b {
                FLAG => {
                    if self.in_frame {
                        // closing flag: emit if non-empty (ignore empty keepalive frames)
                        if !self.buf.is_empty() {
                            frames.push(core::mem::take(&mut self.buf));
                        } else {
                            self.buf.clear();
                        }
                        // a flag also opens the next frame (back-to-back flags share)
                        self.in_frame = true;
                        self.escaped = false;
                    } else {
                        self.in_frame = true;
                        self.escaped = false;
                        self.buf.clear();
                    }
                }
                ESC if self.in_frame => {
                    self.escaped = true;
                }
                _ if self.in_frame => {
                    if self.escaped {
                        self.buf.push(b ^ ESC_MASK);
                        self.escaped = false;
                    } else {
                        self.buf.push(b);
                    }
                }
                _ => { /* bytes outside a frame are ignored */ }
            }
        }
        frames
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_unframe_roundtrip() {
        let data = vec![0x00, 0x7E, 0x7D, 0x10, 0x7E, 0xFF];
        let framed = frame(&data);
        assert_eq!(framed[0], FLAG);
        assert_eq!(*framed.last().unwrap(), FLAG);
        // escaped bytes must not contain raw FLAG/ESC in the interior
        assert!(!framed[1..framed.len() - 1].contains(&FLAG));

        let mut d = Deframer::new();
        let out = d.push(&framed);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0], data);
    }

    #[test]
    fn split_across_reads() {
        let data = vec![1u8, 2, 3];
        let framed = frame(&data);
        let mut d = Deframer::new();
        assert!(d.push(&framed[..2]).is_empty());
        let out = d.push(&framed[2..]);
        assert_eq!(out, vec![data]);
    }

    #[test]
    fn two_frames_one_read() {
        let mut buf = frame(&[0xAA]);
        buf.extend(frame(&[0xBB, 0xCC]));
        let mut d = Deframer::new();
        let out = d.push(&buf);
        assert_eq!(out, vec![vec![0xAA], vec![0xBB, 0xCC]]);
    }
}
