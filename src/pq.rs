// A minimal Parquet writer: one row group, one uncompressed data page per
// column, PLAIN or dictionary-encoded, written straight from the column
// buffers. Enough for the two output tables and nothing else.
#![allow(dead_code)]
use std::io::Write;

// Thrift compact protocol field types.
const T_I32: u8 = 5;
const T_I64: u8 = 6;
const T_BIN: u8 = 8;
const T_LIST: u8 = 9;
const T_STRUCT: u8 = 12;

// parquet encodings and page types
const PLAIN: i32 = 0;
const RLE: i32 = 3;
const RLE_DICTIONARY: i32 = 8;
const DATA_PAGE: i32 = 0;
const DICTIONARY_PAGE: i32 = 2;

struct Th {
    b: Vec<u8>,
}

impl Th {
    fn new() -> Th {
        Th { b: Vec::with_capacity(4096) }
    }
    #[inline]
    fn u8(&mut self, v: u8) {
        self.b.push(v);
    }
    fn uvarint(&mut self, mut v: u64) {
        while v >= 0x80 {
            self.b.push((v as u8) | 0x80);
            v >>= 7;
        }
        self.b.push(v as u8);
    }
    fn zigzag(&mut self, v: i64) {
        self.uvarint(((v << 1) ^ (v >> 63)) as u64);
    }
    /// Field header. `last` tracks the previous field id in this struct.
    fn fh(&mut self, last: &mut i16, id: i16, ty: u8) {
        let d = id - *last;
        if d > 0 && d <= 15 {
            self.b.push(((d as u8) << 4) | ty);
        } else {
            self.b.push(ty);
            self.zigzag(id as i64);
        }
        *last = id;
    }
    fn i32f(&mut self, last: &mut i16, id: i16, v: i32) {
        self.fh(last, id, T_I32);
        self.zigzag(v as i64);
    }
    fn i64f(&mut self, last: &mut i16, id: i16, v: i64) {
        self.fh(last, id, T_I64);
        self.zigzag(v);
    }
    fn strf(&mut self, last: &mut i16, id: i16, s: &str) {
        self.fh(last, id, T_BIN);
        self.uvarint(s.len() as u64);
        self.b.extend_from_slice(s.as_bytes());
    }
    fn list(&mut self, last: &mut i16, id: i16, ety: u8, n: usize) {
        self.fh(last, id, T_LIST);
        if n < 15 {
            self.b.push(((n as u8) << 4) | ety);
        } else {
            self.b.push(0xf0 | ety);
            self.uvarint(n as u64);
        }
    }
    fn stop(&mut self) {
        self.b.push(0);
    }
}

// the kind fixes the parquet type; the encoding is chosen per file
#[derive(Copy, Clone, PartialEq)]
pub enum Kind<'a> {
    // int64 from 8 bytes a row
    I64,
    // int32 from 4 bytes a row
    I32,
    // int32 from 8 bytes a row, every value fitting an i32
    I64As32,
    // date from a 4-byte day number a row
    Date,
    // string, plain-encoded by push_str
    Utf8,
    // the same, equal values next to each other: one dictionary entry per run
    Utf8Runs,
    // nullable string, plain-encoded, only the rows whose def is 1
    Utf8Opt,
    // nullable string from one byte a row: an index into these names or NO_CODE
    Dict(&'a [Vec<u8>]),
}

pub const NO_CODE: u8 = 255;

pub struct Col<'a> {
    pub name: &'static str,
    pub kind: Kind<'a>,
    // laid out as `kind` says
    pub vals: &'a [u8],
    /// One definition level per row (0 or 1); empty unless the kind is Utf8Opt.
    pub defs: &'a [u8],
    /// Number of values present (non-null).
    pub nvals: i64,
}

fn type_code(k: Kind) -> i32 {
    match k {
        Kind::I64 => 2,                                   // INT64
        Kind::I32 | Kind::I64As32 | Kind::Date => 1,      // INT32
        Kind::Utf8 | Kind::Utf8Runs | Kind::Utf8Opt | Kind::Dict(_) => 6, // BYTE_ARRAY
    }
}

fn nullable(k: Kind) -> bool {
    matches!(k, Kind::Utf8Opt | Kind::Dict(_))
}

const BUF: usize = 1 << 17;
const DIRECT: usize = 1 << 15;
const DICT_MAX: u64 = 1 << 16;

// short pieces collect in `buf`, long ones go straight to the file
struct Sink {
    f: std::fs::File,
    buf: Vec<u8>,
    pos: u64,
}

fn varint_len(v: u64) -> usize {
    (70 - (v | 1).leading_zeros() as usize) / 7
}

fn packed_len(n: usize, width: u32) -> usize {
    let groups = (n + 7) / 8;
    varint_len(((groups as u64) << 1) | 1) + groups * width as usize
}

fn bits_for(max: u64) -> u32 {
    (64 - max.leading_zeros()).max(1)
}

#[inline(always)]
unsafe fn int_at<const W: usize>(vals: &[u8], i: usize) -> i64 {
    let p = vals.as_ptr().add(i * W);
    if W == 8 {
        i64::from_le((p as *const i64).read_unaligned())
    } else {
        i32::from_le((p as *const i32).read_unaligned()) as i64
    }
}

impl Sink {
    fn flush(&mut self) -> std::io::Result<()> {
        if !self.buf.is_empty() {
            self.f.write_all(&self.buf)?;
            self.buf.clear();
        }
        Ok(())
    }
    fn small(&mut self, b: &[u8]) -> std::io::Result<()> {
        if self.buf.len() + b.len() > BUF {
            self.flush()?;
        }
        self.buf.extend_from_slice(b);
        self.pos += b.len() as u64;
        Ok(())
    }
    fn put(&mut self, b: &[u8]) -> std::io::Result<()> {
        if b.len() < DIRECT {
            return self.small(b);
        }
        self.flush()?;
        self.pos += b.len() as u64;
        self.f.write_all(b)
    }
    fn header(&mut self, page: i32, bytes: usize, nvals: usize, encoding: i32) -> std::io::Result<()> {
        let mut t = Th::new();
        let mut last = 0i16;
        t.i32f(&mut last, 1, page);
        t.i32f(&mut last, 2, bytes as i32); // uncompressed_page_size
        t.i32f(&mut last, 3, bytes as i32); // compressed_page_size
        let mut l2 = 0i16;
        if page == DATA_PAGE {
            t.fh(&mut last, 5, T_STRUCT);
            t.i32f(&mut l2, 1, nvals as i32); // num_values includes nulls
            t.i32f(&mut l2, 2, encoding);
            t.i32f(&mut l2, 3, RLE); // definition_level_encoding
            t.i32f(&mut l2, 4, RLE); // repetition_level_encoding
        } else {
            t.fh(&mut last, 7, T_STRUCT);
            t.i32f(&mut l2, 1, nvals as i32);
            t.i32f(&mut l2, 2, encoding);
        }
        t.stop();
        t.stop();
        self.small(&t.b)
    }
    // one bit-packed run of the rle hybrid, padded to whole groups of eight
    fn pack<F: Fn(usize) -> u32>(&mut self, n: usize, width: u32, get: F) -> std::io::Result<()> {
        let groups = (n + 7) / 8;
        let mut t = Th { b: Vec::new() };
        t.uvarint(((groups as u64) << 1) | 1);
        self.small(&t.b)?;
        // values per step: what fits a word beside seven pending bits
        match width {
            1..=7 => self.pack_by::<8, F>(n, width, &get),
            8..=14 => self.pack_by::<4, F>(n, width, &get),
            15..=28 => self.pack_by::<2, F>(n, width, &get),
            _ => self.pack_by::<1, F>(n, width, &get),
        }
    }
    fn pack_by<const K: usize, F: Fn(usize) -> u32>(&mut self, n: usize, width: u32, get: &F) -> std::io::Result<()> {
        assert!(width >= 1 && K as u32 * width <= 56);
        let total = (n + 7) / 8 * width as usize;
        let (mut acc, mut bits, mut done, mut i) = (0u64, 0u32, 0usize, 0usize);
        let mut at = self.buf.len();
        while i < n {
            if at + 8 > BUF {
                unsafe { self.buf.set_len(at) };
                self.flush()?;
                at = 0;
            }
            let k = K.min(n - i);
            let mut step = 0u64;
            if k == K {
                for j in 0..K {
                    step |= (get(i + j) as u64) << (j as u32 * width);
                }
            } else {
                for j in 0..k {
                    step |= (get(i + j) as u64) << (j as u32 * width);
                }
            }
            i += k;
            acc |= step << bits;
            bits += k as u32 * width;
            // the whole word goes out; only its complete bytes are kept
            unsafe { (self.buf.as_mut_ptr().add(at) as *mut u64).write_unaligned(acc.to_le()) };
            let whole = (bits >> 3) as usize;
            at += whole;
            done += whole;
            acc >>= whole * 8;
            bits &= 7;
        }
        unsafe { self.buf.set_len(at) };
        if bits > 0 {
            self.buf.push(acc as u8);
            done += 1;
        }
        self.buf.resize(self.buf.len() + (total - done), 0);
        self.pos += total as u64;
        Ok(())
    }
    fn levels<F: Fn(usize) -> u32>(&mut self, n: usize, present: F) -> std::io::Result<()> {
        self.small(&(packed_len(n, 1) as u32).to_le_bytes())?;
        self.pack(n, 1, present)
    }
    // a narrow range becomes bit-packed indexes into a dictionary of the range
    fn int_col<const W: usize>(&mut self, vals: &[u8], n: usize, out: usize) -> std::io::Result<Option<u64>> {
        assert!(vals.len() == n * W, "column length");
        let (mut lo, mut hi) = (i64::MAX, i64::MIN);
        for i in 0..n {
            let v = unsafe { int_at::<W>(vals, i) };
            lo = lo.min(v);
            hi = hi.max(v);
        }
        let span = hi.wrapping_sub(lo) as u64;
        if span < DICT_MAX {
            let width = bits_for(span);
            let dict_bytes = (span as usize + 1) * out;
            let index_bytes = 1 + packed_len(n, width);
            if dict_bytes + index_bytes + 32 < n * out {
                self.header(DICTIONARY_PAGE, dict_bytes, span as usize + 1, PLAIN)?;
                for v in lo..=hi {
                    self.small(&v.to_le_bytes()[..out])?;
                }
                let data_at = self.pos;
                self.header(DATA_PAGE, index_bytes, n, RLE_DICTIONARY)?;
                self.small(&[width as u8])?;
                self.pack(n, width, |i| unsafe { int_at::<W>(vals, i) }.wrapping_sub(lo) as u32)?;
                return Ok(Some(data_at));
            }
        }
        self.header(DATA_PAGE, n * out, n, PLAIN)?;
        if W == out {
            self.put(vals)?;
        } else {
            // keep the low half of every value
            let mut narrow = [0u8; 4096];
            for block in vals.chunks(2 * narrow.len()) {
                for (d, s) in narrow.chunks_exact_mut(4).zip(block.chunks_exact(8)) {
                    d.copy_from_slice(&s[..4]);
                }
                self.small(&narrow[..block.len() / 2])?;
            }
        }
        Ok(None)
    }
    // returns where the data page starts when a dictionary page precedes it
    fn col(&mut self, c: &Col, n: usize) -> std::io::Result<Option<u64>> {
        match c.kind {
            Kind::I64 => self.int_col::<8>(c.vals, n, 8),
            Kind::I64As32 => self.int_col::<8>(c.vals, n, 4),
            Kind::I32 | Kind::Date => self.int_col::<4>(c.vals, n, 4),
            Kind::Utf8 => {
                self.header(DATA_PAGE, c.vals.len(), n, PLAIN)?;
                self.put(c.vals)?;
                Ok(None)
            }
            Kind::Utf8Runs => {
                let v = c.vals;
                // (offset of the value with its length, its bytes, rows in the run)
                let mut runs: Vec<(usize, usize, u32)> = Vec::new();
                let rd8 = |i: usize| u64::from_le_bytes(v[i..i + 8].try_into().unwrap());
                let mut p = 0usize;
                let (mut q, mut ql) = (0usize, usize::MAX);
                for _ in 0..n {
                    let len = 4 + u32::from_le_bytes(v[p..p + 4].try_into().unwrap()) as usize;
                    // same length, then two overlapping words for ids of 8 to 16 bytes
                    let same = len == ql
                        && if len >= 12 && len <= 20 {
                            rd8(p + 4) == rd8(q + 4) && rd8(p + len - 8) == rd8(q + len - 8)
                        } else {
                            v[q..q + len] == v[p..p + len]
                        };
                    if same {
                        runs.last_mut().unwrap().2 += 1;
                    } else {
                        runs.push((p, len, 1));
                        (q, ql) = (p, len);
                    }
                    p += len;
                }
                assert!(p == v.len(), "column length");
                let width = bits_for(runs.len().saturating_sub(1) as u64);
                let vb = ((width + 7) / 8) as usize;
                let dict_bytes: usize = runs.iter().map(|r| r.1).sum();
                let index_bytes = 1 + runs.iter().map(|r| varint_len((r.2 as u64) << 1) + vb).sum::<usize>();
                if n == 0 || dict_bytes + index_bytes + 64 >= v.len() {
                    self.header(DATA_PAGE, v.len(), n, PLAIN)?;
                    self.put(v)?;
                    return Ok(None);
                }
                self.header(DICTIONARY_PAGE, dict_bytes, runs.len(), PLAIN)?;
                for r in &runs {
                    self.small(&v[r.0..r.0 + r.1])?;
                }
                let data_at = self.pos;
                self.header(DATA_PAGE, index_bytes, n, RLE_DICTIONARY)?;
                self.small(&[width as u8])?;
                // one rle run per value: its row count, then its index
                let mut t = Th::new();
                for (k, r) in runs.iter().enumerate() {
                    t.uvarint((r.2 as u64) << 1);
                    t.b.extend_from_slice(&(k as u32).to_le_bytes()[..vb]);
                    if t.b.len() > BUF / 2 {
                        self.small(&t.b)?;
                        t.b.clear();
                    }
                }
                self.small(&t.b)?;
                Ok(Some(data_at))
            }
            Kind::Utf8Opt => {
                self.header(DATA_PAGE, 4 + packed_len(n, 1) + c.vals.len(), n, PLAIN)?;
                assert!(c.defs.len() == n, "column length");
                self.levels(n, |i| c.defs[i] as u32)?;
                self.put(c.vals)?;
                Ok(None)
            }
            Kind::Dict(names) => {
                let codes = c.vals;
                assert!(codes.len() == n, "column length");
                let used: Vec<u8> = codes.iter().copied().filter(|&x| x != NO_CODE).collect();
                let present = used.len();
                let width = bits_for(names.len().saturating_sub(1) as u64);
                let dict_bytes: usize = names.iter().map(|s| 4 + s.len()).sum();
                self.header(DICTIONARY_PAGE, dict_bytes, names.len(), PLAIN)?;
                for s in names {
                    self.small(&(s.len() as u32).to_le_bytes())?;
                    self.put(s)?;
                }
                let data_at = self.pos;
                let index_bytes = if present > 0 { packed_len(present, width) } else { 0 };
                self.header(DATA_PAGE, 4 + packed_len(n, 1) + 1 + index_bytes, n, RLE_DICTIONARY)?;
                self.levels(n, |i| (codes[i] != NO_CODE) as u32)?;
                self.small(&[width as u8])?;
                if present > 0 {
                    self.pack(present, width, |i| used[i] as u32)?;
                }
                Ok(Some(data_at))
            }
        }
    }
}

struct Chunk {
    start: u64,
    data_at: u64,
    bytes: u64,
    dict: bool,
}

pub fn write(path: &std::path::Path, nrows: i64, cols: &[Col]) -> std::io::Result<()> {
    let n = nrows as usize;
    let mut s = Sink { f: std::fs::File::create(path)?, buf: Vec::with_capacity(BUF + 64), pos: 0 };
    s.small(b"PAR1")?;

    let mut chunks: Vec<Chunk> = Vec::with_capacity(cols.len());
    if n > 0 {
        for c in cols {
            let start = s.pos;
            let data_at = s.col(c, n)?;
            chunks.push(Chunk { start, data_at: data_at.unwrap_or(start), bytes: s.pos - start, dict: data_at.is_some() });
        }
    }

    // ---- footer
    let mut t = Th::new();
    let mut last = 0i16;
    t.i32f(&mut last, 1, 1); // version
    t.list(&mut last, 2, T_STRUCT, cols.len() + 1);
    {
        // root
        let mut l = 0i16;
        t.strf(&mut l, 4, "schema");
        t.i32f(&mut l, 5, cols.len() as i32);
        t.stop();
        for c in cols {
            let mut l = 0i16;
            t.i32f(&mut l, 1, type_code(c.kind));
            t.i32f(&mut l, 3, if nullable(c.kind) { 1 } else { 0 }); // OPTIONAL/REQUIRED
            t.strf(&mut l, 4, c.name);
            match c.kind {
                Kind::Date => {
                    t.i32f(&mut l, 6, 6); // DATE
                    t.fh(&mut l, 10, T_STRUCT); // LogicalType
                    let mut l2 = 0i16;
                    t.fh(&mut l2, 6, T_STRUCT); // DATE
                    t.stop();
                    t.stop();
                }
                Kind::Utf8 | Kind::Utf8Runs | Kind::Utf8Opt | Kind::Dict(_) => {
                    t.i32f(&mut l, 6, 0); // UTF8
                    t.fh(&mut l, 10, T_STRUCT);
                    let mut l2 = 0i16;
                    t.fh(&mut l2, 1, T_STRUCT); // STRING
                    t.stop();
                    t.stop();
                }
                Kind::I64 | Kind::I32 | Kind::I64As32 => {}
            }
            t.stop();
        }
    }
    t.i64f(&mut last, 3, nrows);
    // row groups
    t.list(&mut last, 4, T_STRUCT, if n > 0 { 1 } else { 0 });
    if n > 0 {
        let mut l = 0i16;
        t.list(&mut l, 1, T_STRUCT, cols.len());
        for (c, ch) in cols.iter().zip(chunks.iter()) {
            let mut l2 = 0i16;
            t.i64f(&mut l2, 2, ch.start as i64); // file_offset
            t.fh(&mut l2, 3, T_STRUCT); // meta_data
            {
                let mut l3 = 0i16;
                t.i32f(&mut l3, 1, type_code(c.kind));
                let levels = nullable(c.kind) || ch.dict;
                t.list(&mut l3, 2, T_I32, 1 + levels as usize + ch.dict as usize);
                t.zigzag(PLAIN as i64);
                if levels {
                    t.zigzag(RLE as i64);
                }
                if ch.dict {
                    t.zigzag(RLE_DICTIONARY as i64);
                }
                t.list(&mut l3, 3, T_BIN, 1);
                t.uvarint(c.name.len() as u64);
                t.b.extend_from_slice(c.name.as_bytes());
                t.i32f(&mut l3, 4, 0); // UNCOMPRESSED
                t.i64f(&mut l3, 5, nrows);
                t.i64f(&mut l3, 6, ch.bytes as i64);
                t.i64f(&mut l3, 7, ch.bytes as i64);
                t.i64f(&mut l3, 9, ch.data_at as i64); // data_page_offset
                if ch.dict {
                    t.i64f(&mut l3, 11, ch.start as i64); // dictionary_page_offset
                }
                t.stop();
            }
            t.stop();
        }
        t.i64f(&mut l, 2, s.pos as i64 - 4); // total_byte_size
        t.i64f(&mut l, 3, nrows);
        t.stop();
    }
    t.strf(&mut last, 6, "shopsess");
    t.stop();

    s.put(&t.b)?;
    s.small(&(t.b.len() as u32).to_le_bytes())?;
    s.small(b"PAR1")?;
    s.flush()
}

/// Append one PLAIN-encoded byte-array value. Short values are copied with
/// plain stores; `extend_from_slice` would be a memcpy call per value.
#[inline]
pub fn push_str(buf: &mut Vec<u8>, s: &[u8]) {
    let n = s.len();
    if n > 32 {
        buf.extend_from_slice(&(n as u32).to_le_bytes());
        buf.extend_from_slice(s);
        return;
    }
    buf.reserve(n + 4);
    unsafe {
        let p = buf.as_mut_ptr().add(buf.len());
        (p as *mut u32).write_unaligned(n as u32);
        let mut i = 0usize;
        if n >= 8 {
            (p.add(4) as *mut u64).write_unaligned((s.as_ptr() as *const u64).read_unaligned());
            i = 8;
        }
        while i < n {
            *p.add(4 + i) = *s.get_unchecked(i);
            i += 1;
        }
        buf.set_len(buf.len() + n + 4);
    }
}

#[inline]
pub fn as_bytes<T: Copy>(v: &[T]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(v.as_ptr() as *const u8, std::mem::size_of_val(v)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unpack(b: &[u8], n: usize, width: u32) -> Vec<u32> {
        let groups = (n + 7) / 8;
        let mut at = 0;
        let mut header = 0u64;
        let mut shift = 0;
        loop {
            header |= ((b[at] & 0x7f) as u64) << shift;
            shift += 7;
            at += 1;
            if b[at - 1] < 0x80 {
                break;
            }
        }
        assert_eq!(header, ((groups as u64) << 1) | 1);
        assert_eq!(b.len(), at + groups * width as usize);
        assert_eq!(b.len(), packed_len(n, width));
        let mut padded = b[at..].to_vec();
        padded.extend_from_slice(&[0; 8]);
        let all: Vec<u32> = (0..groups * 8)
            .map(|k| {
                let o = k * width as usize;
                let w = u64::from_le_bytes(padded[o / 8..o / 8 + 8].try_into().unwrap());
                (w >> (o % 8) & ((1u64 << width) - 1)) as u32
            })
            .collect();
        assert!(all[n..].iter().all(|&x| x == 0));
        all[..n].to_vec()
    }

    #[test]
    fn bit_packing_round_trips_at_every_width_and_across_flushes() {
        let dir = std::env::temp_dir().join(format!("shopsess-pack-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bits");
        for width in 1..=32u32 {
            for &n in &[0usize, 1, 7, 8, 9, 1000, 1_100_003] {
                let mask = (1u64 << width) - 1;
                let vals: Vec<u32> = (0..n as u64).map(|i| (i.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 23 & mask) as u32).collect();
                let mut s = Sink { f: std::fs::File::create(&path).unwrap(), buf: Vec::with_capacity(BUF + 64), pos: 0 };
                s.small(&[0xab; 5]).unwrap();
                s.pack(n, width, |i| vals[i]).unwrap();
                s.flush().unwrap();
                let pos = s.pos as usize;
                drop(s);
                let b = std::fs::read(&path).unwrap();
                assert_eq!(b.len(), pos);
                assert_eq!(unpack(&b[5..], n, width), vals, "width {} n {}", width, n);
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
