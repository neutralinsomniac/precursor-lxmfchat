//! bzip2 decoding APIs

use std::convert::TryInto;

pub use self::error::DecoderError;
pub use self::reader::DecoderReader;
use crate::bitreader::BitReader;
use crate::block::Block;
use crate::header::Header;

mod error;
mod reader;

/// A low-level decoder implementation
///
/// This decoder does no IO by itself, instead enough data
/// has to be written to it in order for it to be able
/// to decode the next block. After that the decompressed content
/// for the block can be read until all of the data from the block
/// has been exhausted.
/// Repeating this process for every block in sequence will result
/// into the entire file being decompressed.
///
/// (PRECURSOR PATCH: `no_run` — the sample file's blocks exceed the clamped
/// `MAX_SUPPORTED_BLOCKSIZE`, so running this example would now error.)
///
/// ```rust,no_run
/// use bzip2_rs::decoder::{Decoder, ReadState, WriteState};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut compressed_file: &[u8] = include_bytes!("../../tests/samplefiles/sample1.bz2").as_ref();
/// let mut output = Vec::new();
///
/// let mut decoder = Decoder::new();
///
/// assert!(
///     !compressed_file.is_empty(),
///     "empty files will cause the following loop to spin forever"
/// );
///
/// let mut buf = [0; 1024];
/// loop {
///     match decoder.read(&mut buf)? {
///         ReadState::NeedsWrite(space) => {
///             // `Decoder` needs more data to be written to it before it
///             // can decode the next block.
///             // If we reached the end of the file `compressed_file.len()` will be 0,
///             // signaling to the `Decoder` that the last block is smaller and it can
///             // proceed with reading.
///             match decoder.write(&compressed_file)? {
///                 WriteState::NeedsRead => unreachable!(),
///                 WriteState::Written(written) => compressed_file = &compressed_file[written..],
///             };
///         }
///         ReadState::Read(n) => {
///             // `n` uncompressed bytes have been read into `buf`
///             output.extend_from_slice(&buf[..n]);
///         }
///         ReadState::Eof => {
///             // we reached the end of the file
///             break;
///         }
///     }
/// }
///
/// // `output` contains the decompressed file
/// let decompressed_file: &[u8] = include_bytes!("../../tests/samplefiles/sample1.ref").as_ref();
/// assert_eq!(output, decompressed_file);
/// #
/// # Ok(())
/// # }
/// ```
pub struct Decoder {
    header_block: Option<(Header, Block)>,

    skip_bits: usize,
    in_buf: Vec<u8>,

    eof: bool,
}

/// State returned by [`Decoder::write`]
pub enum WriteState {
    /// Enough data has already been written to [`Decoder`]
    /// in order for it to be able to decode the next block.
    /// Now call [`Decoder::read`] to read the decompressed data.
    NeedsRead,
    /// N. number of bytes have been written.
    Written(usize),
}

/// State returned by [`Decoder::read`]
pub enum ReadState {
    /// Not enough data has been written to the underlying [`Decoder`]
    /// in order to allow the next block to be decoded. Call
    /// [`Decoder::write`] to write more data. If the end of the file
    /// has been reached, call [`Decoder::write`] with an empty buffer.
    NeedsWrite(usize),
    /// N. number of data has been read
    Read(usize),
    /// The end of the compressed file has been reached and
    /// there is no more data to read
    Eof,
}

impl Decoder {
    /// Construct a new [`Decoder`], ready to decompress a new bzip2 file
    pub fn new() -> Self {
        Self {
            header_block: None,

            skip_bits: 0,
            in_buf: Vec::new(),

            eof: false,
        }
    }

    fn space(&self) -> usize {
        match &self.header_block {
            Some((_, block)) if block.is_reading() => 0,
            Some((header, _)) => {
                let max_length = header.max_blocksize() as usize + (self.skip_bits / 8) + 1;
                max_length - self.in_buf.len()
            }
            None => {
                Header::from_raw_blocksize(1)
                    .expect("blocksize is valid")
                    .max_blocksize() as usize
                    + 4
            }
        }
    }

    /// Write more compressed data into this [`Decoder`]
    ///
    /// See the documentation for [`WriteState`] to decide
    /// what to do next.
    pub fn write(&mut self, buf: &[u8]) -> Result<WriteState, DecoderError> {
        let space = self.space();

        match &mut self.header_block {
            Some((_, block)) if block.is_reading() => Ok(WriteState::NeedsRead),
            Some((header, block)) => {
                let written = space.min(buf.len());

                self.in_buf.extend_from_slice(&buf[..written]);

                let minimum = (self.skip_bits / 8) + header.max_blocksize() as usize;
                if buf.is_empty() || self.in_buf.len() >= minimum {
                    block.set_ready_for_read();
                }

                Ok(WriteState::Written(written))
            }
            None => {
                let written = space.min(buf.len());
                self.in_buf.extend_from_slice(&buf[..written]);

                if self.in_buf.len() < 4 {
                    return Ok(WriteState::Written(buf.len()));
                }

                let header = Header::parse(self.in_buf[..4].try_into().unwrap())?;
                let block = Block::new(header.clone());
                self.header_block = Some((header, block));

                self.skip_bits = 4 * 8;

                if written == buf.len() {
                    return Ok(WriteState::Written(written));
                }

                match self.write(&buf[written..])? {
                    WriteState::NeedsRead => unreachable!(),
                    WriteState::Written(n) => Ok(WriteState::Written(n + written)),
                }
            }
        }
    }

    /// Read more decompressed data from this [`Decoder`]
    ///
    /// See the documentation for [`ReadState`] to decide
    /// what to do next.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<ReadState, DecoderError> {
        match &mut self.header_block {
            Some(_) if self.eof => Ok(ReadState::Eof),
            Some((_, block)) if block.is_not_ready() => Ok(ReadState::NeedsWrite(self.space())),
            Some((_, block)) => {
                let mut reader = BitReader::new(&self.in_buf);
                reader.advance_by(self.skip_bits);

                let ready_for_read = block.is_ready_for_read();

                let read = block.read(&mut reader, buf)?;

                if read == 0 {
                    if !buf.is_empty() {
                        self.eof = ready_for_read;
                    }

                    return Ok(ReadState::NeedsWrite(self.space()));
                }

                if read == 0 && !buf.is_empty() {
                    self.eof = true;
                }

                self.skip_bits = reader.position();

                if block.is_not_ready() {
                    let bytes = self.skip_bits / 8;

                    self.in_buf.drain(..bytes);

                    self.skip_bits -= bytes * 8;
                }

                Ok(ReadState::Read(read))
            }
            None => Ok(ReadState::NeedsWrite(self.space())),
        }
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

// PRECURSOR PATCH: end-to-end decode of a device-sized stream. The vector is
// Python `bz2.compress(b"reticulum resource test payload " * 40)` — a "BZh9"
// header, which used to trigger the 3.6 MB up-front allocation this vendored
// copy exists to remove.
#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::ReadState;

    const COMPRESSED_HEX: &str = "425a6839314159265359096f7be00001c1918040002e26de202000902980000a551a9a36534f53c13b13a13d89913427d1342644d09813227027026c4d84fc26c4d89813809e04c09c89c89d89d09e09a13f8bb9229c284804b7bdf000";

    fn hexdec(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn decodes_a_python_bzh9_stream_without_huge_preallocation() {
        let compressed = hexdec(COMPRESSED_HEX);
        let expected: Vec<u8> = b"reticulum resource test payload ".repeat(40);

        let mut out = Vec::new();
        let mut reader = crate::DecoderReader::new(compressed.as_slice());
        reader.read_to_end(&mut out).expect("decode");
        assert_eq!(out, expected);
    }

    #[test]
    fn read_state_is_exported() {
        // keep the unused-import lint honest about the test-only use above
        let _ = core::mem::size_of::<ReadState>();
    }
}
