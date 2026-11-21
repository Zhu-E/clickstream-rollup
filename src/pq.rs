// A minimal Parquet writer: one row group, one uncompressed PLAIN data page
// per column. Enough for the two output tables and nothing else.
#![allow(dead_code)]

// Thrift compact protocol field types.
const T_I32: u8 = 5;
const T_I64: u8 = 6;
const T_BIN: u8 = 8;
const T_LIST: u8 = 9;
const T_STRUCT: u8 = 12;

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

#[derive(Copy, Clone, PartialEq)]
pub enum Kind {
    I64,
    Date,
    Utf8,
    Utf8Opt,
}

pub struct Col<'a> {
    pub name: &'static str,
    pub kind: Kind,
    /// PLAIN-encoded values (little-endian ints, or u32 length + bytes).
    pub vals: &'a [u8],
    /// One definition level per row (0 or 1); empty for required columns.
    pub defs: &'a [u8],
    /// Number of values present (non-null).
    pub nvals: i64,
}

/// RLE/bit-packed hybrid with bit width 1: a run header varint then one byte.
fn rle_levels(defs: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(defs.len() / 32 + 16);
    let mut i = 0;
    while i < defs.len() {
        let v = defs[i];
        let mut j = i + 1;
        while j < defs.len() && defs[j] == v {
            j += 1;
        }
        let mut run = ((j - i) as u64) << 1;
        // header varint, then the value in one byte
        loop {
            if run >= 0x80 {
                out.push((run as u8) | 0x80);
                run >>= 7;
            } else {
                out.push(run as u8);
                break;
            }
        }
        out.push(v);
        i = j;
    }
    out
}

fn type_code(k: Kind) -> i32 {
    match k {
        Kind::I64 => 2,            // INT64
        Kind::Date => 1,           // INT32
        Kind::Utf8 | Kind::Utf8Opt => 6, // BYTE_ARRAY
    }
}

pub fn write(path: &std::path::Path, nrows: i64, cols: &[Col]) -> std::io::Result<()> {
    use std::io::Write;
    let mut body: Vec<u8> = Vec::with_capacity(
        cols.iter().map(|c| c.vals.len() + 64).sum::<usize>() + 1024,
    );
    body.extend_from_slice(b"PAR1");

    struct ChunkInfo {
        page_off: u64,
        total: u64,
    }
    let mut chunks: Vec<ChunkInfo> = Vec::with_capacity(cols.len());

    for c in cols {
        let page_off = body.len() as u64;
        let lvl = if c.defs.is_empty() { Vec::new() } else { rle_levels(c.defs) };
        let page_size = c.vals.len() + if lvl.is_empty() { 0 } else { lvl.len() + 4 };
        // page header
        let mut t = Th::new();
        let mut last = 0i16;
        t.i32f(&mut last, 1, 0); // type = DATA_PAGE
        t.i32f(&mut last, 2, page_size as i32);
        t.i32f(&mut last, 3, page_size as i32);
        t.fh(&mut last, 5, T_STRUCT);
        {
            let mut l2 = 0i16;
            t.i32f(&mut l2, 1, nrows as i32); // num_values includes nulls
            t.i32f(&mut l2, 2, 0); // encoding = PLAIN
            t.i32f(&mut l2, 3, 3); // definition_level_encoding = RLE
            t.i32f(&mut l2, 4, 3); // repetition_level_encoding = RLE
            t.stop();
        }
        t.stop();
        body.extend_from_slice(&t.b);
        let data_start = body.len() as u64;
        if !lvl.is_empty() {
            body.extend_from_slice(&(lvl.len() as u32).to_le_bytes());
            body.extend_from_slice(&lvl);
        }
        body.extend_from_slice(c.vals);
        chunks.push(ChunkInfo { page_off, total: body.len() as u64 - page_off });
        let _ = data_start;
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
            t.i32f(&mut l, 3, if c.kind == Kind::Utf8Opt { 1 } else { 0 }); // OPTIONAL/REQUIRED
            t.strf(&mut l, 4, c.name);
            match c.kind {
                Kind::Date => t.i32f(&mut l, 6, 6),                     // DATE
                Kind::Utf8 | Kind::Utf8Opt => t.i32f(&mut l, 6, 0),     // UTF8
                Kind::I64 => {}
            }
            match c.kind {
                Kind::Date => {
                    t.fh(&mut l, 10, T_STRUCT); // LogicalType
                    let mut l2 = 0i16;
                    t.fh(&mut l2, 6, T_STRUCT); // DATE
                    t.stop();
                    t.stop();
                }
                Kind::Utf8 | Kind::Utf8Opt => {
                    t.fh(&mut l, 10, T_STRUCT);
                    let mut l2 = 0i16;
                    t.fh(&mut l2, 1, T_STRUCT); // STRING
                    t.stop();
                    t.stop();
                }
                Kind::I64 => {}
            }
            t.stop();
        }
    }
    t.i64f(&mut last, 3, nrows);
    // row groups
    let nrg = if nrows > 0 { 1 } else { 0 };
    t.list(&mut last, 4, T_STRUCT, nrg);
    if nrg == 1 {
        let mut l = 0i16;
        t.list(&mut l, 1, T_STRUCT, cols.len());
        for (c, ci) in cols.iter().zip(chunks.iter()) {
            let mut l2 = 0i16;
            t.i64f(&mut l2, 2, ci.page_off as i64); // file_offset
            t.fh(&mut l2, 3, T_STRUCT); // meta_data
            {
                let mut l3 = 0i16;
                t.i32f(&mut l3, 1, type_code(c.kind));
                t.list(&mut l3, 2, T_I32, if c.defs.is_empty() { 1 } else { 2 });
                t.zigzag(0); // PLAIN
                if !c.defs.is_empty() {
                    t.zigzag(3); // RLE (levels)
                }
                t.list(&mut l3, 3, T_BIN, 1);
                t.uvarint(c.name.len() as u64);
                t.b.extend_from_slice(c.name.as_bytes());
                t.i32f(&mut l3, 4, 0); // UNCOMPRESSED
                t.i64f(&mut l3, 5, nrows);
                t.i64f(&mut l3, 6, ci.total as i64);
                t.i64f(&mut l3, 7, ci.total as i64);
                t.i64f(&mut l3, 9, ci.page_off as i64);
                t.stop();
            }
            t.stop();
        }
        t.i64f(&mut l, 2, body.len() as i64 - 4); // total_byte_size
        t.i64f(&mut l, 3, nrows);
        t.stop();
    }
    t.strf(&mut last, 6, "shopsess");
    t.stop();

    body.extend_from_slice(&t.b);
    body.extend_from_slice(&(t.b.len() as u32).to_le_bytes());
    body.extend_from_slice(b"PAR1");

    let mut f = std::fs::File::create(path)?;
    f.write_all(&body)?;
    Ok(())
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
