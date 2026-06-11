//! Minimal MessagePack codec covering exactly the types LXMF uses, so we don't
//! need to pull `rmp-serde` (and its serde machinery) into the Xous image.
//!
//! Supported: nil, bool, ints (fix/u8/u16/u32/u64/i8/i16/i32/i64), float64,
//! str (fixstr/str8/16/32), bin (bin8/16/32), array (fix/16/32), map (fix/16/32).

use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Nil,
    Bool(bool),
    Int(i64),
    F64(f64),
    Str(String),
    Bin(Vec<u8>),
    Array(Vec<Value>),
    /// Map keyed by integer (LXMF field keys are small ints); sufficient here.
    Map(BTreeMap<i64, Value>),
    /// Map keyed by string, ENCODE-ONLY (the decoder still expects int keys).
    /// Used for RNS request data dicts, e.g. NomadNet page URL variables
    /// `{"var_g": "mirrors"}`. A Vec keeps the author's ordering.
    StrMap(Vec<(String, Value)>),
}

impl Value {
    pub fn as_bin(&self) -> Option<&[u8]> {
        match self {
            Value::Bin(b) => Some(b),
            Value::Str(s) => Some(s.as_bytes()),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::F64(f) => Some(*f),
            Value::Int(i) => Some(*i as f64),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
}

pub fn encode(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(v, &mut out);
    out
}

fn write_u(out: &mut Vec<u8>, n: u64) {
    // choose the smallest unsigned encoding
    if n < 0x80 {
        out.push(n as u8);
    } else if n <= u8::MAX as u64 {
        out.push(0xcc);
        out.push(n as u8);
    } else if n <= u16::MAX as u64 {
        out.push(0xcd);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= u32::MAX as u64 {
        out.push(0xce);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(0xcf);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn write_i(out: &mut Vec<u8>, n: i64) {
    if n >= 0 {
        write_u(out, n as u64);
    } else if n >= -32 {
        out.push((n as i8) as u8); // negative fixint
    } else if n >= i8::MIN as i64 {
        out.push(0xd0);
        out.push((n as i8) as u8);
    } else if n >= i16::MIN as i64 {
        out.push(0xd1);
        out.extend_from_slice(&(n as i16).to_be_bytes());
    } else if n >= i32::MIN as i64 {
        out.push(0xd2);
        out.extend_from_slice(&(n as i32).to_be_bytes());
    } else {
        out.push(0xd3);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn encode_into(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Nil => out.push(0xc0),
        Value::Bool(false) => out.push(0xc2),
        Value::Bool(true) => out.push(0xc3),
        Value::Int(n) => write_i(out, *n),
        Value::F64(f) => {
            out.push(0xcb);
            out.extend_from_slice(&f.to_be_bytes());
        }
        Value::Str(s) => {
            let b = s.as_bytes();
            let n = b.len();
            if n < 32 {
                out.push(0xa0 | n as u8);
            } else if n <= u8::MAX as usize {
                out.push(0xd9);
                out.push(n as u8);
            } else if n <= u16::MAX as usize {
                out.push(0xda);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            } else {
                out.push(0xdb);
                out.extend_from_slice(&(n as u32).to_be_bytes());
            }
            out.extend_from_slice(b);
        }
        Value::Bin(b) => {
            let n = b.len();
            if n <= u8::MAX as usize {
                out.push(0xc4);
                out.push(n as u8);
            } else if n <= u16::MAX as usize {
                out.push(0xc5);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            } else {
                out.push(0xc6);
                out.extend_from_slice(&(n as u32).to_be_bytes());
            }
            out.extend_from_slice(b);
        }
        Value::Array(a) => {
            let n = a.len();
            if n < 16 {
                out.push(0x90 | n as u8);
            } else if n <= u16::MAX as usize {
                out.push(0xdc);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            } else {
                out.push(0xdd);
                out.extend_from_slice(&(n as u32).to_be_bytes());
            }
            for e in a {
                encode_into(e, out);
            }
        }
        Value::Map(m) => {
            let n = m.len();
            if n < 16 {
                out.push(0x80 | n as u8);
            } else if n <= u16::MAX as usize {
                out.push(0xde);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            } else {
                out.push(0xdf);
                out.extend_from_slice(&(n as u32).to_be_bytes());
            }
            for (k, val) in m {
                write_i(out, *k);
                encode_into(val, out);
            }
        }
        Value::StrMap(m) => {
            let n = m.len();
            if n < 16 {
                out.push(0x80 | n as u8);
            } else if n <= u16::MAX as usize {
                out.push(0xde);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            } else {
                out.push(0xdf);
                out.extend_from_slice(&(n as u32).to_be_bytes());
            }
            for (k, val) in m {
                encode_into(&Value::Str(k.clone()), out);
                encode_into(val, out);
            }
        }
    }
}

#[derive(Debug)]
pub struct DecodeError(pub &'static str);

pub fn decode(bytes: &[u8]) -> Result<Value, DecodeError> {
    let mut p = Parser { b: bytes, i: 0 };
    let v = p.value()?;
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.i + n > self.b.len() {
            return Err(DecodeError("unexpected end of msgpack input"));
        }
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> { Ok(self.take(1)?[0]) }
    fn be16(&mut self) -> Result<u16, DecodeError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn be32(&mut self) -> Result<u32, DecodeError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn be64(&mut self) -> Result<u64, DecodeError> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_be_bytes(a))
    }

    fn value(&mut self) -> Result<Value, DecodeError> {
        let c = self.u8()?;
        match c {
            0x00..=0x7f => Ok(Value::Int(c as i64)),                  // positive fixint
            0xe0..=0xff => Ok(Value::Int((c as i8) as i64)),          // negative fixint
            0x80..=0x8f => self.map((c & 0x0f) as usize),             // fixmap
            0x90..=0x9f => self.array((c & 0x0f) as usize),           // fixarray
            0xa0..=0xbf => self.str_n((c & 0x1f) as usize),           // fixstr
            0xc0 => Ok(Value::Nil),
            0xc2 => Ok(Value::Bool(false)),
            0xc3 => Ok(Value::Bool(true)),
            0xc4 => {
                let n = self.u8()? as usize;
                self.bin_n(n)
            }
            0xc5 => {
                let n = self.be16()? as usize;
                self.bin_n(n)
            }
            0xc6 => {
                let n = self.be32()? as usize;
                self.bin_n(n)
            }
            0xca => {
                let s = self.take(4)?;
                Ok(Value::F64(f32::from_be_bytes([s[0], s[1], s[2], s[3]]) as f64))
            }
            0xcb => {
                let s = self.take(8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(s);
                Ok(Value::F64(f64::from_be_bytes(a)))
            }
            0xcc => Ok(Value::Int(self.u8()? as i64)),
            0xcd => Ok(Value::Int(self.be16()? as i64)),
            0xce => Ok(Value::Int(self.be32()? as i64)),
            0xcf => Ok(Value::Int(self.be64()? as i64)),
            0xd0 => Ok(Value::Int((self.u8()? as i8) as i64)),
            0xd1 => Ok(Value::Int((self.be16()? as i16) as i64)),
            0xd2 => Ok(Value::Int((self.be32()? as i32) as i64)),
            0xd3 => Ok(Value::Int(self.be64()? as i64)),
            0xd9 => {
                let n = self.u8()? as usize;
                self.str_n(n)
            }
            0xda => {
                let n = self.be16()? as usize;
                self.str_n(n)
            }
            0xdb => {
                let n = self.be32()? as usize;
                self.str_n(n)
            }
            0xdc => {
                let n = self.be16()? as usize;
                self.array(n)
            }
            0xdd => {
                let n = self.be32()? as usize;
                self.array(n)
            }
            0xde => {
                let n = self.be16()? as usize;
                self.map(n)
            }
            0xdf => {
                let n = self.be32()? as usize;
                self.map(n)
            }
            _ => Err(DecodeError("unsupported msgpack type")),
        }
    }

    fn str_n(&mut self, n: usize) -> Result<Value, DecodeError> {
        let s = self.take(n)?;
        Ok(Value::Str(String::from_utf8_lossy(s).into_owned()))
    }
    fn bin_n(&mut self, n: usize) -> Result<Value, DecodeError> {
        Ok(Value::Bin(self.take(n)?.to_vec()))
    }
    fn array(&mut self, n: usize) -> Result<Value, DecodeError> {
        // Each element is at least one byte, so a claimed length larger than the
        // remaining input is malformed. Bounding the pre-allocation this way
        // prevents a bogus length (up to 2^32 from a be32 marker) from triggering
        // a `Vec::with_capacity` capacity-overflow/OOM panic on a 32-bit target.
        if n > self.b.len() - self.i {
            return Err(DecodeError("msgpack array length exceeds remaining input"));
        }
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.value()?);
        }
        Ok(Value::Array(v))
    }
    fn map(&mut self, n: usize) -> Result<Value, DecodeError> {
        let mut m = BTreeMap::new();
        for _ in 0..n {
            let k = match self.value()? {
                Value::Int(i) => i,
                _ => return Err(DecodeError("non-integer map key")),
            };
            let val = self.value()?;
            m.insert(k, val);
        }
        Ok(Value::Map(m))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_lxmf_shape() {
        let v = Value::Array(vec![
            Value::F64(1_700_000_000.5),
            Value::Bin(b"title".to_vec()),
            Value::Bin(b"hello world".to_vec()),
            Value::Map(BTreeMap::new()),
        ]);
        let enc = encode(&v);
        let dec = decode(&enc).unwrap();
        assert_eq!(v, dec);
    }

    #[test]
    fn strmap_matches_umsgpack() {
        // Reference bytes from python umsgpack.packb({"var_g": "mirrors"}) —
        // the request-data dict NomadNet sends for a page URL variable.
        let v = Value::StrMap(vec![("var_g".to_string(), Value::Str("mirrors".to_string()))]);
        assert_eq!(hex::encode(encode(&v)), "81a57661725f67a76d6972726f7273");
    }

    #[test]
    fn ints_and_floats() {
        for n in [0i64, 1, 127, 128, 255, 256, 65535, 70000, -1, -32, -33, -200, -70000] {
            assert_eq!(decode(&encode(&Value::Int(n))).unwrap(), Value::Int(n));
        }
        assert_eq!(decode(&encode(&Value::F64(3.5))).unwrap(), Value::F64(3.5));
    }
}
