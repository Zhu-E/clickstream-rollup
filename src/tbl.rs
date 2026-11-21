// Hashing, exact-ish key packing, timestamp parsing, open-addressing maps.
#![allow(dead_code)]

#[inline(always)]
pub fn mix(a: u64, b: u64) -> u64 {
    let r = (a as u128).wrapping_mul(b as u128);
    (r as u64) ^ ((r >> 64) as u64)
}

const S0: u64 = 0xa076_1d64_78bd_642f;
const S1: u64 = 0xe703_7ed1_a0b4_28db;
const S2: u64 = 0x8ebc_6af0_9c88_c6e3;

#[inline(always)]
fn rd8(b: &[u8], i: usize) -> u64 {
    let mut t = [0u8; 8];
    t.copy_from_slice(&b[i..i + 8]);
    u64::from_le_bytes(t)
}
#[inline(always)]
fn rd4(b: &[u8], i: usize) -> u64 {
    let mut t = [0u8; 4];
    t.copy_from_slice(&b[i..i + 4]);
    u32::from_le_bytes(t) as u64
}

/// wyhash-style 64-bit hash. Never returns 0 (0 marks an empty slot).
#[inline]
pub fn hash(b: &[u8]) -> u64 {
    let n = b.len();
    let (a, c) = if n >= 16 {
        return hash_long(b);
    } else if n >= 8 {
        (rd8(b, 0), rd8(b, n - 8))
    } else if n >= 4 {
        (rd4(b, 0), rd4(b, n - 4))
    } else if n > 0 {
        (
            ((b[0] as u64) << 16) | ((b[n >> 1] as u64) << 8) | (b[n - 1] as u64),
            0,
        )
    } else {
        (0, 0)
    };
    let h = mix(a ^ S0, c ^ S1 ^ (n as u64).wrapping_mul(S2));
    let h = mix(h ^ S2, h.rotate_left(29) ^ S0);
    if h == 0 { 1 } else { h }
}

#[inline(never)]
fn hash_long(b: &[u8]) -> u64 {
    let mut h = S0 ^ (b.len() as u64).wrapping_mul(S2);
    let mut i = 0;
    while i + 16 <= b.len() {
        h = mix(h ^ rd8(b, i) ^ S1, rd8(b, i + 8) ^ S2);
        i += 16;
    }
    if i < b.len() {
        let n = b.len();
        let a = if n >= 8 { rd8(b, n - 8) } else { 0 };
        h = mix(h ^ a ^ S1, (n as u64) ^ S2);
    }
    h = mix(h ^ S2, h.rotate_left(29) ^ S0);
    if h == 0 { 1 } else { h }
}

/// 96-bit key for an id: exact (lossless) for ids up to 11 bytes, hashed above.
/// The high byte of `hi` holds the length (or 0xFF for the hashed form), so an
/// occupied slot always has `hi != 0`.
#[inline(always)]
pub fn key96(b: &[u8]) -> (u64, u32) {
    let n = b.len();
    if n <= 11 {
        // Pack the bytes with plain loads; a variable-length copy_from_slice
        // would call memcpy once per row.
        let (lo, hi3) = if n >= 8 {
            let mut h = 0u32;
            let mut i = 8;
            while i < n {
                h |= (unsafe { *b.get_unchecked(i) } as u32) << (8 * (i - 8));
                i += 1;
            }
            (rd8(b, 0), h)
        } else {
            let mut l = 0u64;
            let mut i = 0;
            while i < n {
                l |= (unsafe { *b.get_unchecked(i) } as u64) << (8 * i);
                i += 1;
            }
            (l, 0u32)
        };
        (lo, (hi3 & 0x00ff_ffff) | ((n as u32) << 24))
    } else {
        let h = hash(b);
        let g = mix(h ^ S1, S0);
        (h, (g as u32 & 0x00ff_ffff) | 0xff00_0000)
    }
}

// ---------------------------------------------------------------- timestamps

pub const DAY_MS: i64 = 86_400_000;

#[inline(always)]
fn d2(b: &[u8], i: usize) -> Option<u32> {
    let a = b[i].wrapping_sub(b'0');
    let c = b[i + 1].wrapping_sub(b'0');
    if a > 9 || c > 9 {
        None
    } else {
        Some(a as u32 * 10 + c as u32)
    }
}
#[inline(always)]
fn d4(b: &[u8], i: usize) -> Option<u32> {
    let hi = d2(b, i)?;
    let lo = d2(b, i + 2)?;
    Some(hi * 100 + lo)
}

#[inline(always)]
pub fn is_leap(y: u32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

#[inline(always)]
fn days_in_month(y: u32, m: u32) -> u32 {
    const DIM: [u32; 13] = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if m == 2 && is_leap(y) {
        29
    } else {
        DIM[m as usize]
    }
}

/// Days since 1970-01-01 for a valid civil date (Howard Hinnant's algorithm).
#[inline(always)]
pub fn days_from_civil(y: u32, m: u32, d: u32) -> i64 {
    let y = y as i64 - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Civil date from days since epoch.
pub fn civil_from_days(z: i64) -> (u32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    ((y + if m <= 2 { 1 } else { 0 }) as u32, m as u32, d as u32)
}

/// Seconds-of-day plus calendar checks shared by F1 and F2.
#[inline(always)]
fn civil_ms(b: &[u8]) -> Option<i64> {
    if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let y = d4(b, 0)?;
    let mo = d2(b, 5)?;
    let d = d2(b, 8)?;
    let h = d2(b, 11)?;
    let mi = d2(b, 14)?;
    let s = d2(b, 17)?;
    if mo < 1 || mo > 12 || d < 1 || d > days_in_month(y, mo) || h > 23 || mi > 59 || s > 59 {
        return None;
    }
    Some(days_from_civil(y, mo, d) * DAY_MS + (h as i64 * 3600 + mi as i64 * 60 + s as i64) * 1000)
}

/// Parse one of the three timestamp forms into epoch milliseconds.
#[inline]
pub fn parse_ts(b: &[u8]) -> Option<i64> {
    let n = b.len();
    if n == 20 && b[19] == b'Z' && b[4] == b'-' {
        civil_ms(b)
    } else if n == 25 && b[4] == b'-' && (b[19] == b'+' || b[19] == b'-') {
        let base = civil_ms(b)?;
        if b[22] != b':' {
            return None;
        }
        let oh = d2(b, 20)?;
        let om = d2(b, 23)?;
        if oh > 23 || om > 59 {
            return None;
        }
        let off = (oh as i64 * 3600 + om as i64 * 60) * 1000;
        Some(if b[19] == b'+' { base - off } else { base + off })
    } else {
        parse_epoch_ms(b)
    }
}

/// Digits-only epoch milliseconds; saturates instead of overflowing.
#[inline]
pub fn parse_epoch_ms(b: &[u8]) -> Option<i64> {
    if b.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    let mut sat = false;
    for &c in b {
        let d = c.wrapping_sub(b'0');
        if d > 9 {
            return None;
        }
        if !sat {
            match v.checked_mul(10).and_then(|x| x.checked_add(d as u64)) {
                Some(x) if x <= i64::MAX as u64 => v = x,
                _ => sat = true,
            }
        }
    }
    Some(if sat { i64::MAX } else { v as i64 })
}

// ------------------------------------------------------------------- maps

/// Open-addressing map from a non-zero u64 key to a u64 value.
pub struct Map64 {
    pub slots: Vec<(u64, u64)>,
    mask: u64,
    len: usize,
    limit: usize,
}

impl Map64 {
    /// Sized for `n` entries at a 0.75 load factor: a smaller table means
    /// fewer cache misses, and at 16 bytes an entry a short probe chain
    /// usually stays inside the line already fetched.
    pub fn with_capacity(n: usize) -> Map64 {
        let mut cap = 16usize;
        while cap * 3 < n * 4 {
            cap <<= 1;
        }
        Map64 { slots: vec![(0u64, 0u64); cap], mask: (cap - 1) as u64, len: 0, limit: cap * 3 / 4 }
    }
    #[cold]
    fn grow(&mut self) {
        let cap = self.slots.len() * 2;
        let old = std::mem::replace(&mut self.slots, vec![(0u64, 0u64); cap]);
        self.mask = (cap - 1) as u64;
        self.limit = cap * 3 / 4;
        for (k, v) in old {
            if k != 0 {
                let mut i = self.home(k);
                while unsafe { self.slots.get_unchecked(i) }.0 != 0 {
                    i = (i + 1) & self.mask as usize;
                }
                self.slots[i] = (k, v);
            }
        }
    }
    #[inline(always)]
    fn home(&self, k: u64) -> usize {
        // Keys may be dense encodings rather than hashes, so mix before masking.
        (mix(k, 0x9e37_79b9_7f4a_7c15) & self.mask) as usize
    }
    #[inline(always)]
    pub fn get(&self, k: u64) -> Option<u64> {
        let mut i = self.home(k);
        loop {
            let s = unsafe { *self.slots.get_unchecked(i) };
            if s.0 == k {
                return Some(s.1);
            }
            if s.0 == 0 {
                return None;
            }
            i = (i + 1) & self.mask as usize;
        }
    }
    #[inline]
    pub fn insert(&mut self, k: u64, v: u64) {
        let mut i = self.home(k);
        loop {
            let s = unsafe { *self.slots.get_unchecked(i) };
            if s.0 == k {
                self.slots[i].1 = v;
                return;
            }
            if s.0 == 0 {
                self.slots[i] = (k, v);
                self.len += 1;
                if self.len > self.limit {
                    self.grow();
                }
                return;
            }
            i = (i + 1) & self.mask as usize;
        }
    }
    /// Insert only if absent; returns the value now stored.
    #[inline]
    pub fn get_or_insert(&mut self, k: u64, v: u64) -> u64 {
        let mut i = self.home(k);
        loop {
            let s = unsafe { *self.slots.get_unchecked(i) };
            if s.0 == k {
                return s.1;
            }
            if s.0 == 0 {
                self.slots[i] = (k, v);
                self.len += 1;
                if self.len > self.limit {
                    self.grow();
                }
                return v;
            }
            i = (i + 1) & self.mask as usize;
        }
    }
}

// ------------------------------------------------- fast timestamp parsing

/// True when all eight bytes are ASCII digits.
#[inline(always)]
fn digits8(w: u64) -> bool {
    const HN: u64 = 0xf0f0_f0f0_f0f0_f0f0;
    const Z: u64 = 0x3030_3030_3030_3030;
    (w & HN) == Z && (w.wrapping_add(0x0606_0606_0606_0606) & HN) == Z
}

/// Eight ASCII digits, most significant first, to a number.
#[inline(always)]
fn val8(w: u64) -> u64 {
    let x = w.wrapping_sub(0x3030_3030_3030_3030);
    let y = (x & 0x000f_000f_000f_000f) * 10 + ((x >> 8) & 0x000f_000f_000f_000f);
    let z = (y & 0x0000_00ff_0000_00ff) * 100 + ((y >> 16) & 0x0000_00ff_0000_00ff);
    (z & 0xffff) * 10000 + ((z >> 32) & 0xffff)
}

/// `HH:MM:SS` at `b[11..19]` as milliseconds into the day.
#[inline(always)]
fn time_ms(b: &[u8]) -> Option<i64> {
    let w = rd8(b, 11);
    // ':' at word bytes 2 and 5
    if (w & 0x0000_ff00_00ff_0000) != 0x0000_3a00_003a_0000 {
        return None;
    }
    // replace the separators with '0' so one digit test covers the word
    let y = (w & !0x0000_ff00_00ff_0000) | 0x0000_3000_0030_0000;
    if !digits8(y) {
        return None;
    }
    let h = (b[11] - b'0') as i64 * 10 + (b[12] - b'0') as i64;
    let m = (b[14] - b'0') as i64 * 10 + (b[15] - b'0') as i64;
    let s = (b[17] - b'0') as i64 * 10 + (b[18] - b'0') as i64;
    if h > 23 || m > 59 || s > 59 {
        return None;
    }
    Some((h * 3600 + m * 60 + s) * 1000)
}

/// Caches `YYYY-MM-DD` -> days since the epoch. A dataset's window spans a
/// couple of weeks, so a handful of dates cover almost every row.
pub struct DateCache {
    klo: [u64; 64],
    khi: [u16; 64],
    val: [i64; 64],
}

const BAD: i64 = i64::MIN;

impl DateCache {
    pub fn new() -> DateCache {
        DateCache { klo: [1; 64], khi: [0; 64], val: [BAD; 64] }
    }
    #[inline(always)]
    fn days(&mut self, b: &[u8]) -> Option<i64> {
        let k = rd8(b, 0);
        let k2 = u16::from_le_bytes([b[8], b[9]]);
        let i = (((b[8] as usize) << 4) ^ (b[9] as usize)) & 63;
        unsafe {
            if *self.klo.get_unchecked(i) == k && *self.khi.get_unchecked(i) == k2 {
                let v = *self.val.get_unchecked(i);
                return if v == BAD { None } else { Some(v) };
            }
        }
        let v = date_days(b);
        self.klo[i] = k;
        self.khi[i] = k2;
        self.val[i] = v.unwrap_or(BAD);
        v
    }
}

/// Validate `YYYY-MM-DD` and convert to days since the epoch.
#[inline(never)]
fn date_days(b: &[u8]) -> Option<i64> {
    if b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let w = (rd8(b, 0) & !0xff00_00ff_0000_0000) | 0x3000_0030_0000_0000; // '-' -> '0'
    if !digits8(w) || !(b[8].wrapping_sub(b'0') <= 9) || !(b[9].wrapping_sub(b'0') <= 9) {
        return None;
    }
    let y = (val8(w) / 10_000) as u32;
    let mo = ((b[5] - b'0') * 10 + (b[6] - b'0')) as u32;
    let d = ((b[8] - b'0') * 10 + (b[9] - b'0')) as u32;
    if mo < 1 || mo > 12 || d < 1 || d > days_in_month(y, mo) {
        return None;
    }
    Some(days_from_civil(y, mo, d))
}

/// Digits-only epoch milliseconds, fast path for up to 18 digits.
#[inline(always)]
fn epoch_fast(b: &[u8]) -> Option<i64> {
    let n = b.len();
    if n == 0 {
        return None;
    }
    if n > 18 {
        return parse_epoch_ms(b);
    }
    let mut v: u64 = 0;
    let mut i = 0usize;
    while i + 8 <= n {
        let w = rd8(b, i);
        if !digits8(w) {
            return None;
        }
        v = v * 100_000_000 + val8(w);
        i += 8;
    }
    while i < n {
        let d = unsafe { *b.get_unchecked(i) }.wrapping_sub(b'0');
        if d > 9 {
            return None;
        }
        v = v * 10 + d as u64;
        i += 1;
    }
    Some(v as i64)
}

/// Same contract as `parse_ts`, with the date cache in front.
#[inline(always)]
pub fn parse_ts_c(b: &[u8], dc: &mut DateCache) -> Option<i64> {
    let n = b.len();
    if n == 20 {
        if b[19] != b'Z' || b[10] != b'T' {
            return epoch_fast(b);
        }
        let days = dc.days(b)?;
        Some(days * DAY_MS + time_ms(b)?)
    } else if n == 25 && (b[19] == b'+' || b[19] == b'-') {
        if b[10] != b'T' || b[22] != b':' {
            return None;
        }
        let days = dc.days(b)?;
        let base = days * DAY_MS + time_ms(b)?;
        let oh = d2(b, 20)?;
        let om = d2(b, 23)?;
        if oh > 23 || om > 59 {
            return None;
        }
        let off = (oh as i64 * 3600 + om as i64 * 60) * 1000;
        Some(if b[19] == b'+' { base - off } else { base + off })
    } else {
        epoch_fast(b)
    }
}

// --------------------------------------------- invertible short-id encoding
//
// Ids here are short strings over a small alphabet, so one fits in a u64 and
// a record can carry the id itself instead of a pointer to the bytes it was
// read from: 8 bytes less to shuffle per event.
//
// Each byte becomes a 6-bit code, packed most significant first and padded
// with zeros to ten symbols, plus one so that no id encodes to 0:
//
//     key = 1 + sum code(b[i]) << (6 * (9 - i))
//
// Codes run 1..=63 in byte order and 0 is only ever padding, which makes the
// map injective *and* order preserving: comparing two keys compares the two
// ids byte-wise, the comparison the rules ask for. Ids that are longer than
// ten bytes or use other bytes get a hashed key with the top bit set, and
// their names live in a side table.

/// Set on keys that are hashes rather than encodings.
pub const PTAG: u64 = 1 << 63;
pub const MAXENC: usize = 10;

/// The 63 symbols, in byte order; '-' is left out so that 0 can mean padding.
const ALPHA: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

const fn enc_tbl() -> [u8; 256] {
    let mut t = [0u8; 256];
    let mut i = 0usize;
    while i < ALPHA.len() {
        t[ALPHA[i] as usize] = (i + 1) as u8;
        i += 1;
    }
    t
}

static ENC: [u8; 256] = enc_tbl();

/// The id itself as a u64, or None if it does not fit the alphabet.
#[inline(always)]
pub fn enc_name(b: &[u8]) -> Option<u64> {
    if b.len() > MAXENC {
        return None;
    }
    let mut acc = 0u64;
    for &c in b {
        let d = unsafe { *ENC.get_unchecked(c as usize) };
        if d == 0 {
            return None;
        }
        acc = (acc << 6) | d as u64;
    }
    Some((acc << (6 * (MAXENC - b.len()))) + 1)
}

/// The person key for an id: the id itself when it fits, else a hash.
#[inline(always)]
pub fn person_key(b: &[u8]) -> u64 {
    match enc_name(b) {
        Some(v) => v,
        None => hash(b) | PTAG,
    }
}

/// Writes the id back out; only valid for keys without PTAG.
pub fn dec_name(k: u64, out: &mut [u8; MAXENC]) -> usize {
    debug_assert_eq!(k & PTAG, 0);
    let mut acc = k - 1;
    let mut len = 0usize;
    for i in (0..MAXENC).rev() {
        let c = (acc & 63) as usize;
        acc >>= 6;
        if c != 0 {
            out[i] = ALPHA[c - 1];
            if len == 0 {
                len = i + 1;
            }
        }
    }
    len
}

#[cfg(test)]
mod tests {
    use super::*;

    fn both(x: &str) -> (Option<i64>, Option<i64>) {
        let mut dc = DateCache::new();
        (parse_ts(x.as_bytes()), parse_ts_c(x.as_bytes(), &mut dc))
    }


    #[test]
    fn name_encoding_round_trips_and_keeps_byte_order() {
        let mut names: Vec<Vec<u8>> = vec![Vec::new()];
        for n in 1..=12usize {
            for seed in 0..96u64 {
                let mut v = Vec::new();
                let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ (n as u64);
                for _ in 0..n {
                    v.push(ALPHA[(x % 63) as usize]);
                    x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
                }
                names.push(v);
            }
        }
        for extra in [
            &b"u8w84o3T"[..], b"u8w84o3t", b"u", b"U", b"_", b"0", b"00", b"000000000",
            b"0000000000", b"zzzzzzzzzz", b"a", b"ab", b"abc", b"b", b"-", b"u-1",
            b"has space", b"u.dot", b"\x00", b"\xff",
        ] {
            names.push(extra.to_vec());
        }
        names.sort();
        names.dedup();
        let enc: Vec<(Vec<u8>, u64)> = names
            .iter()
            .filter(|v| v.len() <= MAXENC && v.iter().all(|&c| ENC[c as usize] != 0))
            .map(|v| (v.clone(), person_key(v)))
            .collect();
        for v in &names {
            let k = person_key(v);
            assert_ne!(k, 0, "{:?}", v);
            let ok = v.len() <= MAXENC && v.iter().all(|&c| ENC[c as usize] != 0);
            assert_eq!(k & PTAG == 0, ok, "{:?}", v);
            if ok {
                let mut out = [0u8; MAXENC];
                let n = dec_name(k, &mut out);
                assert_eq!(&out[..n], &v[..], "round trip {:?} -> {:x}", v, k);
            }
        }
        for (a, ka) in &enc {
            for (b, kb) in &enc {
                assert_eq!(ka.cmp(kb), a.cmp(b), "order: {:?} vs {:?}", a, b);
            }
        }
    }

    #[test]
    fn map64_handles_dense_keys() {
        let mut m = Map64::with_capacity(4096);
        let mut keys = Vec::new();
        for i in 0..2000u64 {
            let s = format!("u{}", i);
            let k = person_key(s.as_bytes());
            m.insert(k, i + 1);
            keys.push((k, i + 1));
        }
        for (k, v) in keys {
            assert_eq!(m.get(k), Some(v));
        }
        assert_eq!(m.get(person_key(b"nope")), None);
    }

    #[test]
    fn timestamps_agree() {
        let cases = [
            "2026-10-03T23:58:10Z",
            "2026-10-03T19:58:10-04:00",
            "2026-10-03T23:58:10+00:00",
            "2026-10-03T23:58:10-00:00",
            "2026-10-04T11:58:10+12:00",
            "1791071890000",
            "0001791071890000",
            "86400000",
            "0",
            "",
            "2026-10-03T23:58:10.5Z",
            "2026-10-03t23:58:10Z",
            "2026-10-03T23:58:10z",
            "2026-10-03 23:58:10Z",
            "2026-10-03T23:58:10",
            "2026-13-03T23:58:10Z",
            "2026-02-30T23:58:10Z",
            "2027-02-29T00:00:00Z",
            "2028-02-29T00:00:00Z",
            "2026-10-03T24:00:00Z",
            "2026-10-03T23:60:10Z",
            "2026-10-03T23:58:60Z",
            "2026-10-03T23:58:10+24:00",
            "2026-10-03T23:58:10+05:60",
            "2026-10-03T23:58:10+0200",
            "1791071890000.0",
            "1.79e12",
            "-5",
            "99999999999999999999999999",
            "2026-00-03T23:58:10Z",
            "2026-10-00T23:58:10Z",
            "2026-10-32T23:58:10Z",
            "202X-10-03T23:58:10Z",
            "2026-1O-03T23:58:10Z",
            "2026-10-03X23:58:10Z",
            "2026-10-03T23X58:10Z",
            "2026-10-03T23:58X10Z",
            " 1791071890000",
            "1791071890000 ",
            "2026-10-03T23:58:10Y",
            "2100-02-29T00:00:00Z",
            "2000-02-29T00:00:00Z",
            "9999-12-31T23:59:59Z",
            "0001-01-01T00:00:00Z",
        ];
        for c in cases {
            let (a, b) = both(c);
            assert_eq!(a, b, "mismatch for {:?}: slow {:?} fast {:?}", c, a, b);
        }
    }

    #[test]
    fn date_cache_holds_many_dates() {
        let mut dc = DateCache::new();
        for y in [2025u32, 2026, 2027, 2028] {
            for m in 1..=12u32 {
                for d in 1..=31u32 {
                    let s = format!("{:04}-{:02}-{:02}T12:34:56Z", y, m, d);
                    let a = parse_ts(s.as_bytes());
                    let b = parse_ts_c(s.as_bytes(), &mut dc);
                    assert_eq!(a, b, "{}", s);
                }
            }
        }
    }

    #[test]
    fn epoch_digits() {
        let mut dc = DateCache::new();
        for n in 1..=25usize {
            for seed in 0..40u64 {
                let v = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) % 10u64.pow(n.min(19) as u32);
                let s = format!("{:0width$}", v, width = n);
                let a = parse_ts(s.as_bytes());
                let b = parse_ts_c(s.as_bytes(), &mut dc);
                assert_eq!(a, b, "{}", s);
            }
        }
    }

    #[test]
    fn key96_is_injective_for_short_ids() {
        let ids: Vec<Vec<u8>> = vec![
            b"".to_vec(), b"e".to_vec(), b"ea".to_vec(), b"e42huhoug".to_vec(),
            b"e42huhouG".to_vec(), b"e42huhou".to_vec(), b"01234567890".to_vec(),
            b"0123456789".to_vec(), b" e1".to_vec(), b"e1 ".to_vec(),
        ];
        for i in 0..ids.len() {
            for j in 0..ids.len() {
                let a = key96(&ids[i]);
                let b = key96(&ids[j]);
                assert_eq!(a == b, i == j, "{:?} vs {:?}", ids[i], ids[j]);
            }
        }
    }
}

// ------------------------------------------------------------ bloom prefilter
//
// Most events belong to users that appear in no link, and the link map is far
// too big to stay in cache. A blocked Bloom filter answers "no link" from one
// cache line, so only the events that may be linked pay for the real lookup.
// False positives cost a map lookup that returns None, which is the same
// answer, so only the no-false-negatives property matters here.

pub struct Bloom {
    w: Vec<u64>,   // 8 words = one 64-byte block
    blocks: usize, // power of two
}

impl Bloom {
    /// Sized at 16 bits per key, which gives a false positive rate of a few
    /// parts in a thousand with four probes.
    pub fn new(n: usize) -> Bloom {
        let mut blocks = 1usize;
        while blocks * 512 < n * 16 {
            blocks <<= 1;
        }
        Bloom { w: vec![0u64; blocks * 8], blocks }
    }
    #[inline(always)]
    pub fn insert(&mut self, k: u64) {
        let h = mix(k, 0x9e37_79b9_7f4a_7c15);
        let b = (((h >> 40) as usize) & (self.blocks - 1)) * 8;
        let g = mix(k, 0xff51_afd7_ed55_8ccd);
        let w0 = b + (g & 7) as usize;
        let w1 = b + ((g >> 3) & 7) as usize;
        self.w[w0] |= 1u64 << ((g >> 6) & 63);
        self.w[w0] |= 1u64 << ((g >> 12) & 63);
        self.w[w1] |= 1u64 << ((g >> 18) & 63);
        self.w[w1] |= 1u64 << ((g >> 24) & 63);
    }
    #[inline(always)]
    pub fn maybe(&self, k: u64) -> bool {
        let h = mix(k, 0x9e37_79b9_7f4a_7c15);
        let b = (((h >> 40) as usize) & (self.blocks - 1)) * 8;
        let g = mix(k, 0xff51_afd7_ed55_8ccd);
        let w0 = unsafe { *self.w.get_unchecked(b + (g & 7) as usize) };
        let w1 = unsafe { *self.w.get_unchecked(b + ((g >> 3) & 7) as usize) };
        let m0 = (1u64 << ((g >> 6) & 63)) | (1u64 << ((g >> 12) & 63));
        let m1 = (1u64 << ((g >> 18) & 63)) | (1u64 << ((g >> 24) & 63));
        (w0 & m0) == m0 && (w1 & m1) == m1
    }
}
