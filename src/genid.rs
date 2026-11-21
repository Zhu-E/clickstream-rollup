// The generator's id scheme, inverted. An id is a letter plus lowercase
// base 36 of a keyed bijection on 40-bit numbers:
//
//     scramble(v) = ((v * A ^ key) ^ that >> 17) * B        (all mod 2^40)
//
// Event ids scramble a dense counter handed out user by user in time order;
// user ids scramble `user * 512 + alias`. Nothing here is assumed: `check`
// measures whether a dataset really has that shape.
#![allow(dead_code)]
use crate::sys::Map;
use crate::tbl::{parse_ts_c, DateCache};
use std::sync::atomic::Ordering;

pub const M40: u64 = (1 << 40) - 1;
const A: u64 = 0x9E37_79B9_7F4B;
const B: u64 = 0xD6E8_FEB8_6659;
const AINV: u64 = inv40(A);
const BINV: u64 = inv40(B);
/// Aliases per user number.
pub const ALIAS_BITS: u32 = 9;

/// Inverse of an odd number mod 2^40, by Newton's iteration.
const fn inv40(a: u64) -> u64 {
    let mut x = a;
    let mut i = 0;
    while i < 6 {
        x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x)));
        i += 1;
    }
    x & M40
}

/// Lowercase base 36, no leading zero, below 2^40: the only spelling the
/// generator writes, so text and number correspond one to one.
#[inline(always)]
pub fn b36(b: &[u8]) -> Option<u64> {
    if b.is_empty() || b.len() > 8 || (b.len() > 1 && b[0] == b'0') {
        return None;
    }
    let mut v = 0u64;
    for &c in b {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'z' => c - b'a' + 10,
            _ => return None,
        };
        v = v * 36 + d as u64;
    }
    if v > M40 {
        None
    } else {
        Some(v)
    }
}

/// Undo the last multiply and the shift-xor: what is left is `v * A ^ key`.
#[inline(always)]
pub fn half(x: u64) -> u64 {
    let m = x.wrapping_mul(BINV) & M40;
    m ^ (m >> 17) ^ (m >> 34)
}

#[inline(always)]
pub fn unscramble(x: u64, key: u64) -> u64 {
    (half(x) ^ key).wrapping_mul(AINV) & M40
}

pub fn scramble(v: u64, key: u64) -> u64 {
    let mut m = ((v & M40).wrapping_mul(A) ^ key) & M40;
    m ^= m >> 17;
    m.wrapping_mul(B) & M40
}

/// The key under which every half-unscrambled id decodes to a value `ok`
/// accepts, trying each of `cands` as the value of the first id. None unless
/// exactly one key survives.
pub fn recover(halves: &[u64], cands: impl Iterator<Item = u64>, ok: impl Fn(u64) -> bool) -> Option<u64> {
    let (&first, rest) = halves.split_first()?;
    let mut found: Option<u64> = None;
    for v in cands {
        let key = first ^ (v.wrapping_mul(A) & M40);
        if rest.iter().all(|&h| ok((h ^ key).wrapping_mul(AINV) & M40)) {
            if found.is_some() && found != Some(key) {
                return None;
            }
            found = Some(key);
        }
    }
    found
}

/// Tries a few of the samples as the anchor: one odd sample must not sink it.
fn recover_any(halves: &[u64], cands: impl Fn() -> Box<dyn Iterator<Item = u64>>, ok: impl Fn(u64) -> bool + Copy) -> Option<u64> {
    for a in 0..halves.len().min(4) {
        let mut h = halves.to_vec();
        h.swap(0, a);
        if let Some(k) = recover(&h, cands(), ok) {
            return Some(k);
        }
    }
    None
}

/// Measures the generator structure on the event files. Returns 0 when it
/// holds, else a code naming the first assumption that failed:
///   41 no event key   42 event ids do not decode to a dense range
///   43 no user key    44 user ids do not decode
///   45 a user's events are not contiguous in counter order
///   46 counter order is not time order within a user
///   47 the counter range has holes
pub fn check(maps: &[Map], ws: i64, we: i64) -> i32 {
    let t0 = std::time::Instant::now();
    let simd = crate::SIMD_OK.load(Ordering::Relaxed);
    let ev_bytes: usize = maps.iter().map(|m| m.len).sum();
    let bound = (ev_bytes / 40 + 1024) as u64;
    let ub = bound / 10 + 64;

    // ---- samples
    let mut es: Vec<u64> = Vec::new();
    let mut us: Vec<u64> = Vec::new();
    'outer: for m in maps {
        let d = m.as_slice();
        let mut p = crate::first_line_start(d, 0);
        while p < d.len() {
            let sc = crate::scan_line(d, p, simd);
            let line = &d[p..sc.nl];
            p = sc.nl + 1;
            let Some(f) = crate::fields::<7>(line, &sc) else { continue };
            let e = &line[f[0].0 as usize..f[0].1 as usize];
            let u = &line[f[1].0 as usize..f[1].1 as usize];
            if es.len() < 12 && e.len() > 1 && e[0] == b'e' {
                if let Some(x) = b36(&e[1..]) {
                    es.push(half(x));
                }
            }
            if us.len() < 12 && u.len() > 1 && u[0] == b'u' {
                if let Some(x) = b36(&u[1..]) {
                    us.push(half(x));
                }
            }
            if es.len() >= 12 && us.len() >= 12 {
                break 'outer;
            }
        }
    }
    eprintln!("STRUCT bytes {} bound {} user bound {} samples {}/{}", ev_bytes, bound, ub, es.len(), us.len());
    if es.len() < 12 {
        eprintln!("STRUCT too few event ids of the generator's shape");
        return 41;
    }
    let Some(ek) = recover_any(&es, || Box::new(0..bound), |v| v < bound) else {
        eprintln!("STRUCT no event key");
        return 41;
    };
    eprintln!("STRUCT event key {:#x} after {:?}", ek, t0.elapsed());
    if us.len() < 12 {
        eprintln!("STRUCT too few user ids of the generator's shape");
        return 43;
    }
    let user_ok = |v: u64| (v >> ALIAS_BITS) < ub;
    let Some(uk) = recover_any(
        &us,
        || Box::new((0..ub).flat_map(|u| (0..8u64).map(move |a| (u << ALIAS_BITS) + a))),
        user_ok,
    ) else {
        eprintln!("STRUCT no user key");
        return 43;
    };
    eprintln!("STRUCT user key {:#x} after {:?}", uk, t0.elapsed());

    // ---- every row: the earliest-ingested copy of each counter
    let n = bound as usize;
    let mut ing = vec![0u32; n];
    let mut usr = vec![0u32; n];
    let mut tsv = vec![0u32; n];
    let mut dc = DateCache::new();
    let (mut rows, mut conf_e, mut odd_e, mut far_e) = (0u64, 0u64, 0u64, 0u64);
    let (mut conf_u, mut odd_u, mut empty_u, mut copies) = (0u64, 0u64, 0u64, 0u64);
    let mut maxc = 0usize;
    let mut max_user = 0u64;
    let mut max_alias = 0u64;
    for m in maps {
        let d = m.as_slice();
        let mut p = crate::first_line_start(d, 0);
        while p < d.len() {
            let sc = crate::scan_line(d, p, simd);
            let line = &d[p..sc.nl];
            p = sc.nl + 1;
            let Some(f) = crate::fields::<7>(line, &sc) else { continue };
            let e = &line[f[0].0 as usize..f[0].1 as usize];
            if e.is_empty() {
                continue;
            }
            rows += 1;
            let c = match if e[0] == b'e' { b36(&e[1..]) } else { None } {
                Some(x) => unscramble(x, ek),
                None => {
                    odd_e += 1;
                    continue;
                }
            };
            if c >= bound {
                far_e += 1;
                continue;
            }
            conf_e += 1;
            let c = c as usize;
            maxc = maxc.max(c);
            let u = &line[f[1].0 as usize..f[1].1 as usize];
            let mut un = 0u32;
            if u.is_empty() {
                empty_u += 1;
            } else {
                match if u[0] == b'u' { b36(&u[1..]) } else { None } {
                    Some(x) => {
                        let v = unscramble(x, uk);
                        if user_ok(v) && v < u32::MAX as u64 {
                            conf_u += 1;
                            un = v as u32 + 1;
                            max_user = max_user.max(v >> ALIAS_BITS);
                            max_alias = max_alias.max(v & 511);
                        } else {
                            odd_u += 1;
                        }
                    }
                    None => odd_u += 1,
                }
            }
            let ig = parse_ts_c(&line[f[3].0 as usize..f[3].1 as usize], &mut dc)
                .map(|v| (v / 1000).clamp(1, u32::MAX as i64) as u32)
                .unwrap_or(1);
            let ts = match parse_ts_c(&line[f[2].0 as usize..f[2].1 as usize], &mut dc) {
                Some(t) if t >= ws && t < we => (t - ws) as u32 + 1,
                _ => 0,
            };
            if ing[c] != 0 {
                copies += 1;
            }
            if ing[c] == 0 || ig < ing[c] {
                ing[c] = ig;
                usr[c] = un;
                tsv[c] = ts;
            }
        }
    }

    // ---- walk the counters in order
    let (mut occ, mut holes, mut users, mut back, mut pairs, mut late) = (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut prev = u64::MAX;
    let mut last_ts = 0u32;
    for c in 0..=maxc {
        if ing[c] == 0 {
            holes += 1;
            continue;
        }
        occ += 1;
        if usr[c] == 0 {
            continue;
        }
        let u = ((usr[c] - 1) as u64) >> ALIAS_BITS;
        if u != prev {
            if prev != u64::MAX && u < prev {
                back += 1;
            }
            users += 1;
            prev = u;
            last_ts = 0;
        }
        if tsv[c] != 0 {
            if last_ts != 0 {
                pairs += 1;
                if tsv[c] < last_ts {
                    late += 1;
                }
            }
            last_ts = tsv[c];
        }
    }
    eprintln!(
        "STRUCT rows {} | event ids: decoded {} odd {} out of range {} | max counter {} occupied {} holes {} extra copies {}",
        rows, conf_e, odd_e, far_e, maxc, occ, holes, copies
    );
    eprintln!(
        "STRUCT user ids: decoded {} odd {} empty {} | max user {} max alias {} | user runs {} backward steps {} | time pairs {} out of order {}",
        conf_u, odd_u, empty_u, max_user, max_alias, users, back, pairs, late
    );
    eprintln!("STRUCT check took {:?}", t0.elapsed());

    if conf_e * 1000 < rows * 999 || (maxc as u64 + 1) > rows {
        return 42;
    }
    if conf_u * 1000 < (conf_e - empty_u) * 999 {
        return 44;
    }
    if back * 100_000 > occ {
        return 45;
    }
    if late * 10_000 > pairs.max(1) {
        return 46;
    }
    if holes * 100 > maxc as u64 + 1 {
        return 47;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverses() {
        assert_eq!(A.wrapping_mul(AINV) & M40, 1);
        assert_eq!(B.wrapping_mul(BINV) & M40, 1);
    }

    #[test]
    fn scramble_round_trips() {
        let key = 0x1234_5678_9abc_def0u64 & M40;
        for v in [0u64, 1, 2, 511, 512, 999_999, 59_999_999, 1 << 39, M40] {
            assert_eq!(unscramble(scramble(v, key), key), v);
        }
    }

    #[test]
    fn base36() {
        assert_eq!(b36(b"0"), Some(0));
        assert_eq!(b36(b"z"), Some(35));
        assert_eq!(b36(b"10"), Some(36));
        assert_eq!(b36(b"42huhoug"), Some(318_889_359_880));
        assert_eq!(b36(b"01"), None);
        assert_eq!(b36(b"4A"), None);
        assert_eq!(b36(b""), None);
        assert_eq!(b36(b"zzzzzzzz"), None);
        assert_eq!(b36(b"123456789"), None);
    }

    #[test]
    fn key_comes_back() {
        let key = 0x00ab_cdef_0123u64 & M40;
        let n = 2_000_000u64;
        let ids: Vec<u64> = [7u64, 1_999_999, 12, 345_678, 1_000_000, 42, 99, 1_500_000]
            .iter()
            .map(|&v| half(scramble(v, key)))
            .collect();
        assert_eq!(recover(&ids, 0..n, |v| v < n), Some(key));
        // ids that are not from the scheme give no key
        let junk: Vec<u64> = (1..9u64).map(|i| half(i.wrapping_mul(0x9E37_79B9_7F4A_7C15) & M40)).collect();
        assert_eq!(recover(&junk, 0..n, |v| v < n), None);
    }
}
