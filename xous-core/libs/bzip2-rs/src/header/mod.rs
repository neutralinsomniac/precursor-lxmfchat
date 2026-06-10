//! bzip2 low-level header APIs

pub use self::error::HeaderError;

mod error;

/// PRECURSOR PATCH: the largest block *content* (in bytes of pre-BWT data) this
/// decoder supports, regardless of what the stream header declares.
///
/// `max_blocksize` sizes the BWT working array (4 bytes per content byte) and
/// bounds the reader's input buffering, but encoders declare their block
/// *capacity*, not their content: Python's `bz2` always writes `BZh9`
/// (900,000), so an unclamped decoder allocates 3.6 MB up front to decode even
/// a 1 KB message — an instant OOM abort on the Precursor. Clamping here
/// bounds every allocation in the decoder; blocks whose actual content
/// exceeds the clamp fail with the decoder's existing "data exceeds block
/// size" error instead of allocating. 64 KiB of content is far beyond any
/// LXMF message the device can display, and caps the working array at 256 KiB.
pub(crate) const MAX_SUPPORTED_BLOCKSIZE: u32 = 64 * 1024;

/// A bzip2 header
#[derive(Clone)]
pub struct Header {
    raw_blocksize: u8,
    max_blocksize: u32,
}

impl Header {
    /// Parse a bzip2 header
    pub fn parse(buf: [u8; 4]) -> Result<Self, HeaderError> {
        let signature = &buf[..2];
        if signature != b"BZ" {
            return Err(HeaderError::InvalidSignature);
        }

        let version = buf[2];
        if version != b'h' {
            return Err(HeaderError::UnsupportedVersion);
        }

        let hundred_k_blocksize = buf[3];
        match hundred_k_blocksize {
            b'1'..=b'9' => {
                let raw_blocksize = hundred_k_blocksize - b'0';
                Self::from_raw_blocksize(raw_blocksize)
            }
            _ => Err(HeaderError::InvalidBlockSize),
        }
    }

    /// Construct `Header` from the raw blocksize
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError::InvalidBlockSize`] if `raw_blocksize`
    /// isn't `1..=9`
    pub fn from_raw_blocksize(raw_blocksize: u8) -> Result<Self, HeaderError> {
        if raw_blocksize < 1 || raw_blocksize > 9 {
            return Err(HeaderError::InvalidBlockSize);
        }

        // PRECURSOR PATCH: clamp to keep decoder allocations device-sized; see
        // MAX_SUPPORTED_BLOCKSIZE.
        let max_blocksize = (100 * 1000 * u32::from(raw_blocksize)).min(MAX_SUPPORTED_BLOCKSIZE);
        Ok(Self {
            raw_blocksize,
            max_blocksize,
        })
    }

    /// The raw blocksize, as declared in the bzip2 header
    ///
    /// The returned value is always `1..=9`
    pub fn raw_blocksize(&self) -> u8 {
        self.raw_blocksize
    }

    /// The maximum blocksize (clamped; see [`MAX_SUPPORTED_BLOCKSIZE`])
    pub fn max_blocksize(&self) -> u32 {
        self.max_blocksize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_9k() {
        let header = Header::parse(*b"BZh9").unwrap();
        assert_eq!(header.raw_blocksize(), 9);
        // PRECURSOR PATCH: a "BZh9" header no longer means a 3.6 MB working
        // array — the supported block content is clamped.
        assert_eq!(header.max_blocksize(), MAX_SUPPORTED_BLOCKSIZE);
    }
}
