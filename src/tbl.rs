// Hashing, exact-ish key packing, timestamp parsing, open-addressing maps.
#![allow(dead_code)]
use crate::sys::{prefetch, Blob};


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
        // the last sixteen bytes, overlapping the block before
        let n = b.len();
        h = mix(h ^ rd8(b, n - 16) ^ S1, rd8(b, n - 8) ^ S2);
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
    if n.wrapping_sub(8) <= 3 {
        // the usual length: the tail comes out of the last four bytes
        let tail = (rd4(b, n - 4) >> (8 * (12 - n))) as u32;
        return (rd8(b, 0), tail | ((n as u32) << 24));
    }
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
    pub slots: Blob<(u64, u64)>,
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
        Map64 { slots: Blob::zeroed(cap), mask: (cap - 1) as u64, len: 0, limit: cap * 3 / 4 }
    }
    #[cold]
    fn grow(&mut self) {
        let cap = self.slots.len() * 2;
        let old = std::mem::replace(&mut self.slots, Blob::zeroed(cap));
        self.mask = (cap - 1) as u64;
        self.limit = cap * 3 / 4;
        for &(k, v) in old.iter() {
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
    /// Start the fetch of the line a later `get` will land on.
    #[inline(always)]
    pub fn prefetch(&self, k: u64) {
        prefetch(unsafe { self.slots.as_ptr().add(self.home(k)) } as *const u8);
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

const ZEROS: u64 = 0x3030_3030_3030_3030;

/// True when all eight bytes are ASCII digits.
#[inline(always)]
fn digits8(w: u64) -> bool {
    const HN: u64 = 0xf0f0_f0f0_f0f0_f0f0;
    (w & HN) == ZEROS && (w.wrapping_add(0x0606_0606_0606_0606) & HN) == ZEROS
}

/// Eight digit values, most significant in the low byte, to a number.
#[inline(always)]
fn val8x(x: u64) -> u64 {
    let y = (x & 0x000f_000f_000f_000f) * 10 + ((x >> 8) & 0x000f_000f_000f_000f);
    let z = (y & 0x0000_00ff_0000_00ff) * 100 + ((y >> 16) & 0x0000_00ff_0000_00ff);
    (z & 0xffff) * 10000 + ((z >> 32) & 0xffff)
}

/// Eight ASCII digits, most significant first, to a number.
#[inline(always)]
fn val8(w: u64) -> u64 {
    val8x(w.wrapping_sub(ZEROS))
}

// A time of day is read two bytes at a time through tables indexed by the
// pair itself, so a lookup validates and converts at once and anything that
// is not the expected pair lands on `TBAD`. The pairs of `HH:MM:SS` are
// `HH`, `:M`, `M:` and `SS`, which leaves no separator unchecked.

/// At least this much in a sum of table entries means some pair was wrong.
const TBAD: u32 = 1 << 20;

const fn pair(a: u8, b: u8) -> usize {
    a as usize | ((b as usize) << 8)
}

/// Seconds for `HH`, `:M`, `M:` and `SS`.
const fn tod_tbl(kind: usize) -> [u32; 65536] {
    let mut t = [TBAD; 65536];
    let mut a = 0u8;
    while a < 10 {
        let mut c = 0u8;
        while c < 10 {
            let v = (a * 10 + c) as u32;
            if kind == 0 && v < 24 {
                t[pair(b'0' + a, b'0' + c)] = v * 3600;
            }
            if kind == 3 && v < 60 {
                t[pair(b'0' + a, b'0' + c)] = v;
            }
            c += 1;
        }
        if kind == 1 && a < 6 {
            t[pair(b':', b'0' + a)] = a as u32 * 600;
        }
        if kind == 2 {
            t[pair(b'0' + a, b':')] = a as u32 * 60;
        }
        a += 1;
    }
    t
}

static TOD: [[u32; 65536]; 4] = [tod_tbl(0), tod_tbl(1), tod_tbl(2), tod_tbl(3)];

#[inline(always)]
fn rd2(b: &[u8], i: usize) -> usize {
    let mut t = [0u8; 2];
    t.copy_from_slice(&b[i..i + 2]);
    u16::from_le_bytes(t) as usize
}

/// Seconds into the day of `HH:MM:SS` at `b[i..i + 8]`, or `TBAD` and up.
#[inline(always)]
fn tod(b: &[u8], i: usize) -> u32 {
    TOD[0][rd2(b, i)] + TOD[1][rd2(b, i + 2)] + TOD[2][rd2(b, i + 4)] + TOD[3][rd2(b, i + 6)]
}

/// Seconds of the `HH:MM` at `b[i..i + 5]`, or `TBAD` and up.
#[inline(always)]
fn hhmm(b: &[u8], i: usize) -> u32 {
    TOD[0][rd2(b, i)] + TOD[1][rd2(b, i + 2)] + TOD[2][pair(b[i + 4], b':')]
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DateEnt {
    k1: u64,
    k2: u64,
    ms: i64,
    sec: i64,
}

/// Caches `YYYY-MM-DDT` -> that midnight, in milliseconds and in seconds. A
/// dataset's window spans a couple of weeks, so a handful of dates cover
/// almost every row. Only real dates whose seconds fit a u32 get in, so a hit
/// needs no further check; everything else goes to `parse_ts` each time.
pub struct DateCache {
    e: [DateEnt; 128],
}

/// Where a date lives: the low bits of its day and the parity of its month.
#[inline(always)]
fn slot(k2: u64) -> usize {
    const M: u64 = (1 << 24) | (3 << 40) | (0xf << 48);
    #[cfg(all(target_arch = "x86_64", target_feature = "bmi2"))]
    unsafe {
        core::arch::x86_64::_pext_u64(k2, M) as usize
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "bmi2")))]
    {
        (((k2 >> 24) & 1) | ((k2 >> 39) & 6) | ((k2 >> 45) & 0x78)) as usize
    }
}

impl DateCache {
    pub fn new() -> DateCache {
        // no slot starts out holding a key that maps to it
        let mut e = [DateEnt { k1: 0, k2: !0, ms: 0, sec: 0 }; 128];
        e[127].k2 = 0;
        DateCache { e }
    }
    /// The entry for the date `b` opens with, which a `T` must follow; `b`
    /// has at least eleven bytes.
    #[inline(always)]
    fn day(&mut self, b: &[u8]) -> Option<&DateEnt> {
        let k1 = rd8(b, 0);
        let k2 = rd8(b, 3);
        let i = slot(k2);
        let hit = {
            let e = unsafe { self.e.get_unchecked(i) };
            ((e.k1 ^ k1) | (e.k2 ^ k2)) == 0
        };
        if !hit && !self.fill(b, i, k1, k2) {
            return None;
        }
        Some(unsafe { self.e.get_unchecked(i) })
    }
    /// Put the date in its slot, if it is one.
    #[cold]
    #[inline(never)]
    fn fill(&mut self, b: &[u8], i: usize, k1: u64, k2: u64) -> bool {
        if b[10] != b'T' {
            return false;
        }
        // 1970-01-02 to 2104: seconds after midnight still fit a u32
        match date_days(b) {
            Some(d) if d >= 1 && d <= 49_000 => {
                self.e[i & 127] = DateEnt { k1, k2, ms: d * DAY_MS, sec: d * 86_400 };
                true
            }
            _ => false,
        }
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

const POW10: [u64; 9] = [1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000];

/// For sixteen bytes read as `b[..8]` then `b[k..k + 8]`: all of the first
/// word and the last `k` bytes of the second, which repeats the rest.
const fn fresh_tbl() -> [[u8; 16]; 9] {
    let mut t = [[0u8; 16]; 9];
    let mut k = 0;
    while k < 9 {
        let mut i = 0;
        while i < 16 {
            if i < 8 || i >= 16 - k {
                t[k][i] = 0xff;
            }
            i += 1;
        }
        k += 1;
    }
    t
}

static FRESH: [[u8; 16]; 9] = fresh_tbl();

/// Eight to sixteen digits, `k = len - 8`: the first eight as one number and
/// the remaining `k` as another, or None if any byte is not a digit.
#[cfg(all(target_arch = "x86_64", target_feature = "sse4.1"))]
#[inline(always)]
fn split_digits(b: &[u8], k: usize) -> Option<(u64, u64)> {
    use core::arch::x86_64::*;
    debug_assert!(b.len() == k + 8 && k <= 8);
    unsafe {
        let hi = _mm_loadl_epi64(b.as_ptr() as *const __m128i);
        let lo = _mm_loadl_epi64(b.as_ptr().add(k) as *const __m128i);
        let x = _mm_sub_epi8(_mm_unpacklo_epi64(hi, lo), _mm_set1_epi8(0x30));
        let over = _mm_subs_epu8(x, _mm_set1_epi8(9));
        if _mm_testz_si128(over, over) == 0 {
            return None;
        }
        let x = _mm_and_si128(x, _mm_loadu_si128(FRESH.get_unchecked(k).as_ptr() as *const __m128i));
        // pairs, then fours, then eights
        let a = _mm_maddubs_epi16(x, _mm_set1_epi16(0x010a));
        let c = _mm_madd_epi16(a, _mm_set1_epi32(0x0001_0064));
        let e = _mm_madd_epi16(_mm_packus_epi32(c, c), _mm_set1_epi32(0x0001_2710));
        let r = _mm_cvtsi128_si64(e) as u64;
        Some((r & 0xffff_ffff, r >> 32))
    }
}

#[cfg(not(all(target_arch = "x86_64", target_feature = "sse4.1")))]
#[inline(always)]
fn split_digits(b: &[u8], k: usize) -> Option<(u64, u64)> {
    split_digits_sw(b, k)
}

/// The same with 64-bit words only.
#[inline(always)]
fn split_digits_sw(b: &[u8], k: usize) -> Option<(u64, u64)> {
    let hi = rd8(b, 0);
    let lo = rd8(b, k);
    if !(digits8(hi) & digits8(lo)) {
        return None;
    }
    let fresh = rd8(&FRESH[k], 8);
    Some((val8(hi), val8x(lo.wrapping_sub(ZEROS) & fresh)))
}

/// Digits-only epoch milliseconds. Eight to sixteen digits, which is every
/// one the generator writes, take two overlapping words and no loop.
#[inline(always)]
fn epoch_fast(b: &[u8]) -> Option<i64> {
    let n = b.len();
    if n == 13 {
        // what the generator writes: the same with every constant known
        let (hi, lo) = split_digits(b, 5)?;
        return Some((hi * 100_000 + lo) as i64);
    }
    if n.wrapping_sub(8) <= 8 {
        let k = n - 8;
        let (hi, lo) = split_digits(b, k)?;
        return Some((hi * unsafe { *POW10.get_unchecked(k) } + lo) as i64);
    }
    epoch_slow(b)
}

#[inline(never)]
fn epoch_slow(b: &[u8]) -> Option<i64> {
    let n = b.len();
    if n == 0 {
        return None;
    }
    if n > 18 {
        return parse_epoch_ms(b);
    }
    let mut v: u64 = 0;
    for &c in b {
        let d = c.wrapping_sub(b'0');
        if d > 9 {
            return None;
        }
        v = v * 10 + d as u64;
    }
    Some(v as i64)
}

/// Whatever the fast paths would not take: the reference decides.
#[cold]
#[inline(never)]
fn ts_slow(b: &[u8]) -> Option<i64> {
    parse_ts(b)
}

/// Same contract as `parse_ts`. The two calendar forms are taken only when
/// the date is cached and every pair of the time checks out; anything else
/// about them is `parse_ts`'s to judge.
#[inline(always)]
pub fn parse_ts_c(b: &[u8], dc: &mut DateCache) -> Option<i64> {
    let n = b.len();
    if n == 20 {
        if let Some(e) = dc.day(b) {
            let t = tod(b, 11);
            if (t < TBAD) & (b[19] == b'Z') {
                return Some(e.ms + t as i64 * 1000);
            }
        }
        ts_slow(b)
    } else if n == 25 {
        if let Some(e) = dc.day(b) {
            let t = tod(b, 11);
            let o = hhmm(b, 20);
            let neg = b[19] == b'-';
            if ((t | o) < TBAD) & (neg | (b[19] == b'+')) {
                let o = o as i64 * 1000;
                return Some(e.ms + t as i64 * 1000 + if neg { o } else { -o });
            }
        }
        ts_slow(b)
    } else {
        epoch_fast(b)
    }
}

/// An `ingest_ts`: milliseconds, and whole seconds clamped to a u32. Both are
/// zero when the field is not a timestamp.
#[derive(Clone, Copy)]
pub struct Ingest {
    pub ms: i64,
    pub sec: u32,
}

#[cold]
#[inline(never)]
fn ingest_slow(b: &[u8]) -> Ingest {
    let ms = parse_ts(b).unwrap_or(0);
    Ingest { ms, sec: if ms <= 0 { 0 } else { (ms / 1000).min(u32::MAX as i64) as u32 } }
}

/// `ingest_ts`, which the rules promise is `YYYY-MM-DDTHH:MM:SSZ`: no choice
/// of form on the way in. Anything else gets what `parse_ts` makes of it.
#[inline(always)]
pub fn ingest(b: &[u8], dc: &mut DateCache) -> Ingest {
    if b.len() == 20 {
        if let Some(e) = dc.day(b) {
            let t = tod(b, 11);
            if (t < TBAD) & (b[19] == b'Z') {
                return Ingest { ms: e.ms + t as i64 * 1000, sec: (e.sec + t as i64) as u32 };
            }
        }
    }
    ingest_slow(b)
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

/// Eight to ten bytes at once. The two nibbles of each byte pick one bit set
/// each, which meet only on a byte outside the alphabet; the high nibble
/// also picks what to add to get the code, and two multiply-adds pack the
/// codes six bits apiece.
#[cfg(all(target_arch = "x86_64", target_feature = "sse4.1"))]
#[inline(always)]
fn enc_wide(b: &[u8]) -> Option<u64> {
    use core::arch::x86_64::*;
    let n = b.len();
    debug_assert!(n >= 8 && n <= MAXENC);
    let sh = 4 * (16 - n) as u32;
    let lo = rd8(b, 0);
    let hi = (rd8(b, n - 8) >> sh) >> sh;
    unsafe {
        let v = _mm_set_epi64x(hi as i64, lo as i64);
        let nib = _mm_set1_epi8(0x0f);
        let ln = _mm_and_si128(v, nib);
        let hn = _mm_and_si128(_mm_srli_epi16(v, 4), nib);
        // classes by high nibble: 3 digits, 4 and 6 letters from 1, 5 P-Z and _, 7 p-z
        let hcls = _mm_setr_epi8(16, 16, 16, 1, 2, 4, 2, 8, 16, 16, 16, 16, 16, 16, 16, 16);
        // low nibbles each class does not have
        let lcls = _mm_setr_epi8(18, 16, 16, 16, 16, 16, 16, 16, 16, 16, 17, 29, 29, 29, 29, 25);
        let bad = _mm_and_si128(_mm_shuffle_epi8(hcls, hn), _mm_shuffle_epi8(lcls, ln));
        let ok = _mm_movemask_epi8(_mm_cmpeq_epi8(bad, _mm_setzero_si128())) as u32;
        if !ok & ((1u32 << n) - 1) != 0 {
            return None;
        }
        let add = _mm_setr_epi8(0, 0, 0, -0x2f, -0x36, -0x36, -0x3b, -0x3b, 0, 0, 0, 0, 0, 0, 0, 0);
        let us = _mm_and_si128(_mm_cmpeq_epi8(v, _mm_set1_epi8(0x5f)), _mm_set1_epi8(-4));
        let code = _mm_add_epi8(_mm_add_epi8(v, _mm_shuffle_epi8(add, hn)), us);
        let pair = _mm_maddubs_epi16(code, _mm_set1_epi16(0x0140));
        let four = _mm_madd_epi16(pair, _mm_set1_epi32(0x0001_1000));
        let r = _mm_cvtsi128_si64(four) as u64;
        let tail = _mm_extract_epi32(four, 2) as u32 as u64;
        Some((((r & 0xffff_ffff) << 36) | ((r >> 32) << 12) | (tail >> 12)) + 1)
    }
}

/// The id itself as a u64, or None if it does not fit the alphabet.
#[inline(always)]
pub fn enc_name(b: &[u8]) -> Option<u64> {
    #[cfg(all(target_arch = "x86_64", target_feature = "sse4.1"))]
    if b.len().wrapping_sub(8) <= MAXENC - 8 {
        return enc_wide(b);
    }
    enc_bytes(b)
}

/// Any length, a byte at a time.
#[inline(always)]
fn enc_bytes(b: &[u8]) -> Option<u64> {
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

/// Built with SS_NOENC=1, every id takes the hashed path. The two paths must
/// agree on every output, so this is how the side-table path gets tested.
const NOENC: bool = option_env!("SS_NOENC").is_some();

/// The person key for an id: the id itself when it fits, else a hash.
#[inline(always)]
pub fn person_key(b: &[u8]) -> u64 {
    if NOENC {
        return hash(b) | PTAG;
    }
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
    fn name_encoding_agrees_with_the_byte_loop() {
        let mut x = 0x6a09_e667_f3bc_c909u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for n in 0..=12usize {
            // every byte value at every position of a valid name
            let mut v: Vec<u8> = (0..n).map(|i| ALPHA[(i * 7 + n) % 63]).collect();
            assert_eq!(enc_name(&v), enc_bytes(&v), "{:?}", v);
            for i in 0..n {
                let keep = v[i];
                for c in 0..=255u8 {
                    v[i] = c;
                    assert_eq!(enc_name(&v), enc_bytes(&v), "{:?}", v);
                }
                v[i] = keep;
            }
        }
        for it in 0..2_000_000u32 {
            let n = (next() % 13) as usize;
            let v: Vec<u8> = (0..n)
                .map(|_| if it % 5 == 0 && next() % 6 == 0 { next() as u8 } else { ALPHA[(next() % 63) as usize] })
                .collect();
            assert_eq!(enc_name(&v), enc_bytes(&v), "{:?}", v);
        }
    }

    #[test]
    fn long_hash_reads_every_byte() {
        for n in 16..=64usize {
            let base: Vec<u8> = (0..n).map(|i| b'a' + (i % 26) as u8).collect();
            let h = hash(&base);
            for i in 0..n {
                let mut v = base.clone();
                v[i] ^= 1;
                assert_ne!(hash(&v), h, "length {} ignores byte {}", n, i);
            }
        }
    }

    #[test]
    fn bloom_has_no_false_negatives_and_few_false_positives() {
        let id = |i: u64| -> u64 {
            let mut x = i.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
            let mut v = vec![b'u'];
            for _ in 0..7 {
                v.push(b"0123456789abcdefghijklmnopqrstuvwxyz"[(x % 36) as usize]);
                x /= 36;
            }
            person_key(&v)
        };
        let n = 200_000u64;
        let mut b = Bloom::new(n as usize);
        for i in 0..n {
            b.insert(id(i));
        }
        for i in 0..n {
            assert!(b.maybe(id(i)));
        }
        let fp = (n..3 * n).filter(|&i| b.maybe(id(i))).count();
        println!("bloom false positives: {} of {}", fp, 2 * n);
        assert!(fp < (2 * n / 100) as usize, "false positive rate {} of {}", fp, 2 * n);
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

    #[inline(never)]
    pub fn probe_ts(b: &[u8], dc: &mut DateCache) -> i64 {
        parse_ts_c(b, dc).unwrap_or(0)
    }
    #[inline(never)]
    pub fn probe_ingest(b: &[u8], dc: &mut DateCache) -> i64 {
        let g = ingest(b, dc);
        g.ms ^ g.sec as i64
    }

    /// both fast decoders against the reference, for one field
    fn same(v: &[u8], dc: &mut DateCache) {
        let want = parse_ts(v);
        assert_eq!(parse_ts_c(v, dc), want, "{:?}", String::from_utf8_lossy(v));
        let ms = want.unwrap_or(0);
        let sec = if ms <= 0 { 0u32 } else { (ms / 1000).min(u32::MAX as i64) as u32 };
        let g = ingest(v, dc);
        assert_eq!((g.ms, g.sec), (ms, sec), "ingest {:?}", String::from_utf8_lossy(v));
    }

    #[test]
    fn time_tables_hold_exactly_the_valid_pairs() {
        for v in 0..65536usize {
            let (a, c) = ((v & 255) as u8, (v >> 8) as u8);
            let (da, dc) = (a.wrapping_sub(b'0'), c.wrapping_sub(b'0'));
            let two = if da < 10 && dc < 10 { Some(da as u32 * 10 + dc as u32) } else { None };
            assert_eq!(TOD[0][v], match two { Some(x) if x < 24 => x * 3600, _ => TBAD });
            assert_eq!(TOD[1][v], if a == b':' && dc < 6 { dc as u32 * 600 } else { TBAD });
            assert_eq!(TOD[2][v], if c == b':' && da < 10 { da as u32 * 60 } else { TBAD });
            assert_eq!(TOD[3][v], match two { Some(x) if x < 60 => x, _ => TBAD });
        }
    }

    #[test]
    fn date_cache_survives_collisions_and_odd_dates() {
        let mut rng = Rng(0x7f4a_7c15_9e37_79b9);
        let mut dc = DateCache::new();
        let mut pool: Vec<Vec<u8>> = Vec::new();
        for y in [1969u32, 1970, 1971, 2024, 2027, 2028, 2103, 2104, 2105, 2106, 2107, 9999] {
            for (m, d) in [(1u32, 1u32), (1, 2), (2, 28), (2, 29), (2, 30), (3, 1), (12, 31), (11, 31), (13, 1), (0, 1), (6, 0)] {
                pool.push(format!("{:04}-{:02}-{:02}", y, m, d).into_bytes());
            }
        }
        pool.push(vec![0u8; 10]);
        pool.push(vec![0xffu8; 10]);
        let tails: [&[u8]; 7] = [b"12:34:56Z", b"00:00:00Z", b"23:59:59Z", b"24:00:00Z", b"12:34:56+05:30", b"12:34:56-23:59", b"12:34:56z"];
        for it in 0..400_000u32 {
            let mut v = pool[rng.below(pool.len() as u64) as usize].clone();
            v.push(if rng.below(50) == 0 { b' ' } else { b'T' });
            v.extend_from_slice(tails[rng.below(tails.len() as u64) as usize]);
            same(&v, &mut dc);
            // an untouched cache must not take nothing-but-zeros for a date either
            if it < 200 {
                same(&v, &mut DateCache::new());
            }
        }
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            (self.next() >> 11) % n
        }
    }

    const SHAPES: [&str; 12] = [
        "2026-10-03T23:58:10Z",
        "2026-10-03T19:58:10-04:00",
        "2028-02-29T00:00:00+12:00",
        "2027-12-31T23:59:59-00:00",
        "1791071890000",
        "0001791071890000",
        "17910718",
        "1791071",
        "179107189000012345",
        "12345678901234567890",
        "1234567890123456789012345",
        "9223372036854775807",
    ];

    #[test]
    fn timestamps_agree_for_every_byte_at_every_position() {
        let mut dc = DateCache::new();
        for s in SHAPES {
            let mut v = s.as_bytes().to_vec();
            for i in 0..v.len() {
                let keep = v[i];
                for c in 0..=255u8 {
                    v[i] = c;
                    same(&v, &mut dc);
                }
                v[i] = keep;
            }
        }
    }

    #[test]
    fn timestamps_agree_for_every_two_digit_field() {
        let mut dc = DateCache::new();
        let put = |v: &mut Vec<u8>, at: usize, x: usize| {
            v[at] = b'0' + (x / 10) as u8;
            v[at + 1] = b'0' + (x % 10) as u8;
        };
        for y in ["1900", "2000", "2024", "2025", "2026", "2027", "2028", "2100"] {
            let mut v = format!("{}-01-01T00:00:00+00:00", y).into_bytes();
            for mo in 0..100 {
                for d in 0..100 {
                    put(&mut v, 5, mo);
                    put(&mut v, 8, d);
                    same(&v, &mut dc);
                    same(&v[..19], &mut dc);
                    v[19] = b'Z';
                    same(&v[..20], &mut dc);
                    v[19] = b'+';
                }
            }
        }
        for sign in [b'+', b'-'] {
            for at in [11usize, 14, 17, 20, 23] {
                let mut v = b"2027-06-15T12:34:56+05:30".to_vec();
                v[19] = sign;
                for a in 0..100 {
                    put(&mut v, at, a);
                    for at2 in [11usize, 14, 17, 20, 23] {
                        if at2 == at {
                            continue;
                        }
                        let keep = [v[at2], v[at2 + 1]];
                        for b in 0..100 {
                            put(&mut v, at2, b);
                            same(&v, &mut dc);
                            let mut z = v[..20].to_vec();
                            z[19] = b'Z';
                            same(&z, &mut dc);
                        }
                        v[at2] = keep[0];
                        v[at2 + 1] = keep[1];
                    }
                }
            }
        }
    }

    fn civil_text(ms: i64, off_min: i64, rng: &mut Rng) -> String {
        let local = ms + off_min * 60_000;
        let (y, m, d) = civil_from_days(local.div_euclid(DAY_MS));
        let s = local.rem_euclid(DAY_MS) / 1000;
        let head = format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}", y, m, d, s / 3600, s / 60 % 60, s % 60);
        if off_min == 0 && rng.below(2) == 0 {
            format!("{}Z", head)
        } else {
            let a = off_min.abs();
            format!("{}{}{:02}:{:02}", head, if off_min < 0 { '-' } else { '+' }, a / 60, a % 60)
        }
    }

    #[test]
    fn timestamps_round_trip() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut dc = DateCache::new();
        for _ in 0..400_000 {
            let ms = (rng.below(4_000_000_000) as i64) * 1000;
            let off = if rng.below(3) == 0 { 0 } else { rng.below(24 * 60) as i64 - 12 * 60 };
            let s = civil_text(ms, off, &mut rng);
            assert_eq!(parse_ts_c(s.as_bytes(), &mut dc), Some(ms), "{}", s);
            assert_eq!(parse_ts(s.as_bytes()), Some(ms), "{}", s);
            let ms = ms + rng.below(1000) as i64;
            let pad = rng.below(4) as usize;
            let s = format!("{}{}", "0".repeat(pad), ms);
            assert_eq!(parse_ts_c(s.as_bytes(), &mut dc), Some(ms), "{}", s);
        }
    }

    #[test]
    fn timestamps_agree_under_random_damage() {
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        let mut dc = DateCache::new();
        let pool = b"0123456789-+:TZtz ,.\"e\r\x00\xff/";
        for it in 0..3_000_000u32 {
            let mut v: Vec<u8> = if it % 3 == 0 {
                SHAPES[rng.below(SHAPES.len() as u64) as usize].as_bytes().to_vec()
            } else if it % 3 == 1 {
                let ms = (rng.below(4_000_000_000) as i64) * 1000;
                let off = if rng.below(2) == 0 { 0 } else { rng.below(24 * 60) as i64 - 12 * 60 };
                civil_text(ms, off, &mut rng).into_bytes()
            } else {
                let n = rng.below(22) as usize;
                (0..n).map(|_| b'0' + rng.below(10) as u8).collect()
            };
            for _ in 0..rng.below(4) {
                match rng.below(8) {
                    0 if !v.is_empty() => {
                        let at = rng.below(v.len() as u64) as usize;
                        v.remove(at);
                    }
                    1 => {
                        let at = rng.below(v.len() as u64 + 1) as usize;
                        v.insert(at, pool[rng.below(pool.len() as u64) as usize]);
                    }
                    _ if !v.is_empty() => {
                        let at = rng.below(v.len() as u64) as usize;
                        v[at] = pool[rng.below(pool.len() as u64) as usize];
                    }
                    _ => {}
                }
            }
            same(&v, &mut dc);
        }
    }

    #[test]
    fn digit_words_agree() {
        let mut rng = Rng(0x1234_5678_9abc_def1);
        for it in 0..2_000_000u32 {
            let n = 8 + rng.below(9) as usize;
            let mut v: Vec<u8> = (0..n).map(|_| b'0' + rng.below(10) as u8).collect();
            if it % 4 == 0 {
                let at = rng.below(n as u64) as usize;
                v[at] = rng.next() as u8;
            }
            let want = if v.iter().all(|c| c.is_ascii_digit()) {
                let s = std::str::from_utf8(&v).unwrap();
                Some((s[..8].parse::<u64>().unwrap(), s[8..].parse::<u64>().unwrap_or(0)))
            } else {
                None
            };
            assert_eq!(split_digits(&v, n - 8), want, "{:?}", String::from_utf8_lossy(&v));
            assert_eq!(split_digits_sw(&v, n - 8), want, "{:?}", String::from_utf8_lossy(&v));
        }
    }

    #[test]
    fn key96_matches_the_byte_loop() {
        let slow = |b: &[u8]| -> (u64, u32) {
            let mut lo = 0u64;
            let mut hi = 0u32;
            for (i, &c) in b.iter().enumerate() {
                if i < 8 {
                    lo |= (c as u64) << (8 * i);
                } else {
                    hi |= (c as u32) << (8 * (i - 8));
                }
            }
            (lo, hi | ((b.len() as u32) << 24))
        };
        let mut rng = Rng(0x0f0f_1234_5678_9abd);
        for _ in 0..200_000 {
            let n = rng.below(12) as usize;
            let v: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
            assert_eq!(key96(&v), slow(&v), "{:?}", v);
        }
    }

    /// Not a test: `SS_KIND=f1|f2|f3|ing|pair|none SS_N=<calls>` under
    /// `perf stat`, differenced against `SS_N=0`, gives instructions a call.
    #[test]
    #[ignore]
    fn bench_ts() {
        let kind = std::env::var("SS_KIND").unwrap_or_default();
        let n: usize = std::env::var("SS_N").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
        let mut rng = Rng(0x1357_9bdf_2468_ace1);
        let w0 = 1_828_000_000_000i64;
        // (ts, ingest) as an event row has them: same window, minutes apart
        let rows: Vec<(String, String)> = (0..1024)
            .map(|_| {
                let ts = w0 + rng.below(14 * 86_400) as i64 * 1000;
                let ing = ts + (1 + rng.below(600)) as i64 * 1000;
                let off = [0i64, 60, -240, 330, 720, -600][rng.below(6) as usize];
                let t = match kind.as_str() {
                    "f2" => {
                        let mut s = civil_text(ts, off, &mut rng);
                        while s.len() != 25 {
                            s = civil_text(ts, off, &mut rng);
                        }
                        s
                    }
                    "f3" => format!("{}", ts + rng.below(1000) as i64),
                    _ => {
                        let mut s = civil_text(ts, 0, &mut rng);
                        while s.len() != 20 {
                            s = civil_text(ts, 0, &mut rng);
                        }
                        s
                    }
                };
                let mut g = civil_text(ing, 0, &mut rng);
                while g.len() != 20 {
                    g = civil_text(ing, 0, &mut rng);
                }
                (t, g)
            })
            .collect();
        // one loop per kind, so no dispatch is counted
        fn run<F: FnMut(&[u8], &[u8]) -> i64>(rows: &[(String, String)], n: usize, mut f: F) -> i64 {
            let mut acc = 0i64;
            for i in 0..n {
                let (t, g) = &rows[i & 1023];
                acc ^= f(std::hint::black_box(t.as_bytes()), std::hint::black_box(g.as_bytes()));
            }
            acc
        }
        let mut dc = DateCache::new();
        let acc = match kind.as_str() {
            "none" => run(&rows, n, |t, g| t.len() as i64 ^ g.len() as i64),
            "ing" => run(&rows, n, |_, g| {
                let a = ingest(g, &mut dc);
                a.ms ^ a.sec as i64
            }),
            "old_ing" => run(&rows, n, |_, g| {
                let ms = parse_ts_c(g, &mut dc).unwrap_or(0);
                let sec = if ms <= 0 { 0u32 } else { (ms / 1000).min(u32::MAX as i64) as u32 };
                ms ^ sec as i64
            }),
            _ => run(&rows, n, |t, _| parse_ts_c(t, &mut dc).unwrap_or(0)),
        };
        println!("acc {}", std::hint::black_box(acc));
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
    w: Blob<u64>,  // 8 words = one 64-byte block
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
        Bloom { w: Blob::zeroed(blocks * 8), blocks }
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
    /// Start the fetch of the one line `maybe` will read.
    #[inline(always)]
    pub fn prefetch(&self, k: u64) {
        let h = mix(k, 0x9e37_79b9_7f4a_7c15);
        let b = (((h >> 40) as usize) & (self.blocks - 1)) * 8;
        prefetch(unsafe { self.w.as_ptr().add(b) } as *const u8);
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
