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
}

impl Map64 {
    pub fn with_capacity(n: usize) -> Map64 {
        let mut cap = 16usize;
        while cap < n * 2 {
            cap <<= 1;
        }
        Map64 { slots: vec![(0u64, 0u64); cap], mask: (cap - 1) as u64 }
    }
    #[inline(always)]
    pub fn get(&self, k: u64) -> Option<u64> {
        let mut i = (k & self.mask) as usize;
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
        let mut i = (k & self.mask) as usize;
        loop {
            let s = unsafe { *self.slots.get_unchecked(i) };
            if s.0 == k {
                self.slots[i].1 = v;
                return;
            }
            if s.0 == 0 {
                self.slots[i] = (k, v);
                return;
            }
            i = (i + 1) & self.mask as usize;
        }
    }
    /// Insert only if absent; returns the value now stored.
    #[inline]
    pub fn get_or_insert(&mut self, k: u64, v: u64) -> u64 {
        let mut i = (k & self.mask) as usize;
        loop {
            let s = unsafe { *self.slots.get_unchecked(i) };
            if s.0 == k {
                return s.1;
            }
            if s.0 == 0 {
                self.slots[i] = (k, v);
                return v;
            }
            i = (i + 1) & self.mask as usize;
        }
    }
}
