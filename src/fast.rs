// fast path: ids decode to counters, so dedup is a slot and order is free
use crate::genid::{half, scramble, unscramble, A, AINV, M40};
use crate::*;
use std::collections::HashMap;
use std::ops::Range;
use std::sync::atomic::AtomicU64;

const ALIAS: u64 = 511;
const DELTA_BITS: u32 = 17;
const DELTA_MASK: u64 = (1 << DELTA_BITS) - 1;
/// ingest second minus event second, shifted so 24 h late still fits
const BIAS: i64 = (1 << DELTA_BITS) - 1 - 86_400;
const MAX_SHIFT: u32 = 15;
const CSHIFT: u32 = 10;
const GENERAL: u32 = 1 << 31;

const DEAD: u64 = 1;
const LIVE: u64 = 2;
const ESC: u64 = 3;

pub(crate) struct Keys {
    ek: u64,
    uk: u64,
    /// counters below this get a slot
    ncap: u64,
    /// user numbers below this get a table entry
    ucap: u64,
    shift: u32,
}

/// a = ts:31 user:31 tag:2, b = pc:32 delta:17 slot:15 (dead, escaped: ingest:32 0:17 slot:15)
#[repr(C)]
#[derive(Copy, Clone)]
struct FRec {
    a: u64,
    b: u64,
}

/// a = user:22 ts:31 alias:9, b = camp:16 file:8 offset:36 len:4
#[repr(C)]
#[derive(Copy, Clone)]
struct FC {
    a: u64,
    b: u64,
}

#[derive(Copy, Clone)]
struct Span {
    fi: u32,
    len: u32,
    off: u64,
}

impl Span {
    #[inline]
    fn bytes<'a>(&self, ctx: &'a Ctx) -> &'a [u8] {
        &ctx.maps[self.fi as usize].as_slice()[self.off as usize..self.off as usize + self.len as usize]
    }
    fn sref(&self) -> u64 {
        sref_of(self.fi as usize, self.off as usize, self.len as usize)
    }
}

#[derive(Copy, Clone)]
struct OddEv {
    klo: u64,
    khi: u32,
    ing: u32,
    tsf: u32,
    pc: u32,
    user: Span,
}

#[derive(Copy, Clone)]
struct Esc {
    ts: u32,
    pc: u32,
    user: Span,
}

#[derive(Copy, Clone)]
struct OddCl {
    user: Span,
    sref: u64,
    ts: u32,
    camp: u32,
}

// ------------------------------------------------------------------ decoding

const fn d36_tbl() -> [u8; 256] {
    let mut t = [0x80u8; 256];
    let mut i = 0;
    while i < 10 {
        t[b'0' as usize + i] = i as u8;
        i += 1;
    }
    let mut i = 0;
    while i < 26 {
        t[b'a' as usize + i] = 10 + i as u8;
        i += 1;
    }
    t
}

static D36: [u8; 256] = d36_tbl();

/// same contract as genid::b36, without a branch per digit
#[inline(always)]
fn b36f(b: &[u8]) -> Option<u64> {
    let n = b.len();
    if n == 0 || n > 8 || (n > 1 && b[0] == b'0') {
        return None;
    }
    let mut v = 0u64;
    let mut bad = 0u8;
    for &c in b {
        let d = unsafe { *D36.get_unchecked(c as usize) };
        bad |= d;
        v = v * 36 + (d & 63) as u64;
    }
    if bad & 0x80 != 0 || v > M40 {
        None
    } else {
        Some(v)
    }
}

const L8: u64 = 0x0101_0101_0101_0101;

/// the 8 bytes ending at `e`, zero-filled before `s`; none unless 1-8 digits, no leading zero
#[inline(always)]
fn word(d: &[u8], s: usize, e: usize) -> Option<u64> {
    let n = e.wrapping_sub(s);
    if n.wrapping_sub(1) > 7 || e < 8 || e > d.len() || (n > 1 && d[s] == b'0') {
        return None;
    }
    let w = u64::from_le_bytes(d[e - 8..e].try_into().unwrap());
    Some(if n == 8 { w } else { (w & (!0u64 << (64 - 8 * n))) | ((L8 * 0x30) >> (8 * n)) })
}

/// eight base-36 digits, first in the low byte; checked by encoding back
#[inline(always)]
fn swar36(w: u64) -> Option<u64> {
    let alpha = (w >> 6) & L8;
    let v = (w & (L8 * 0x0f)) + alpha * 9 + (alpha & (w >> 4)) * 16;
    let ten = ((v + L8 * 118) >> 7) & L8;
    if v + L8 * 0x30 + ten * 0x27 != w || (v + L8 * 92) & (L8 * 0x80) != 0 {
        return None;
    }
    let v = (v & 0x00ff_00ff_00ff_00ff) * 36 + ((v >> 8) & 0x00ff_00ff_00ff_00ff);
    let v = (v & 0x0000_ffff_0000_ffff) * 1296 + ((v >> 16) & 0x0000_ffff_0000_ffff);
    let v = (v & 0xffff_ffff) * 1_679_616 + (v >> 32);
    if v > M40 {
        None
    } else {
        Some(v)
    }
}

/// `b36f(&d[s..e])` without the loop
#[inline(always)]
fn b36w(d: &[u8], s: usize, e: usize) -> Option<u64> {
    if e < 8 {
        return if s <= e && e <= d.len() { b36f(&d[s..e]) } else { None };
    }
    let w = word(d, s, e)?;
    if cfg!(all(target_arch = "x86_64", target_feature = "sse4.1")) {
        pair36(w, w).0
    } else {
        swar36(w)
    }
}

/// two words of digits in one vector
#[cfg(all(target_arch = "x86_64", target_feature = "sse4.1"))]
#[inline(always)]
fn pair36(w0: u64, w1: u64) -> (Option<u64>, Option<u64>) {
    use core::arch::x86_64::*;
    unsafe {
        let x = _mm_set_epi64x(w1 as i64, w0 as i64);
        let alpha = _mm_cmpgt_epi8(x, _mm_set1_epi8(0x60));
        let v = _mm_sub_epi8(x, _mm_add_epi8(_mm_set1_epi8(0x30), _mm_and_si128(alpha, _mm_set1_epi8(0x27))));
        let lim = _mm_add_epi8(_mm_set1_epi8(9), _mm_and_si128(alpha, _mm_set1_epi8(26)));
        let ok = _mm_movemask_epi8(_mm_cmpeq_epi8(_mm_min_epu8(v, lim), v)) as u32;
        let p = _mm_maddubs_epi16(v, _mm_set1_epi16(0x0124));
        let q = _mm_madd_epi16(p, _mm_set1_epi32(0x0001_0510));
        let z0 = _mm_cvtsi128_si64(q) as u64;
        let z1 = _mm_extract_epi64(q, 1) as u64;
        let v0 = (z0 & 0xffff_ffff) * 1_679_616 + (z0 >> 32);
        let v1 = (z1 & 0xffff_ffff) * 1_679_616 + (z1 >> 32);
        (
            if ok & 0xff == 0xff && v0 <= M40 { Some(v0) } else { None },
            if ok >> 8 == 0xff && v1 <= M40 { Some(v1) } else { None },
        )
    }
}

#[cfg(not(all(target_arch = "x86_64", target_feature = "sse4.1")))]
#[inline(always)]
fn pair36(w0: u64, w1: u64) -> (Option<u64>, Option<u64>) {
    (swar36(w0), swar36(w1))
}

/// `(b36w(d, s0, e0), b36w(d, s1, e1))`
#[inline(always)]
fn b36pair(d: &[u8], s0: usize, e0: usize, s1: usize, e1: usize) -> (Option<u64>, Option<u64>) {
    if e0 < 8 || e1 < 8 {
        return (b36w(d, s0, e0), b36w(d, s1, e1));
    }
    match (word(d, s0, e0), word(d, s1, e1)) {
        (Some(a), Some(b)) => pair36(a, b),
        (a, b) => (a.and_then(swar36), b.and_then(swar36)),
    }
}

impl Keys {
    /// counter of the non-empty event id and `user` of the user id
    #[inline(always)]
    fn event_at(&self, d: &[u8], es: usize, ee: usize, us: usize, ue: usize) -> (Option<u64>, Option<u64>) {
        let (xe, xu) = b36pair(d, es + 1, ee, us + 1, ue);
        let c = match xe {
            Some(x) if d[es] == b'e' => Some(unscramble(x, self.ek)).filter(|&c| c < self.ncap),
            _ => None,
        };
        let u = match xu {
            Some(x) if d[us] == b'u' => Some(unscramble(x, self.uk)).filter(|&v| v < self.ucap << 9),
            _ => None,
        };
        (c, u)
    }
    /// `user` for the id at `d[s..e]`, which must not be empty
    #[inline(always)]
    fn user_at(&self, d: &[u8], s: usize, e: usize) -> Option<u64> {
        if d[s] != b'u' {
            return None;
        }
        let v = unscramble(b36w(d, s + 1, e)?, self.uk);
        if v < self.ucap << 9 {
            Some(v)
        } else {
            None
        }
    }
    /// user number * 512 + alias, for ids the user table covers
    #[inline(always)]
    fn user(&self, uid: &[u8]) -> Option<u64> {
        if uid.is_empty() || uid[0] != b'u' {
            return None;
        }
        let v = unscramble(b36f(&uid[1..])?, self.uk);
        if v < self.ucap << 9 {
            Some(v)
        } else {
            None
        }
    }
    /// `user` of the id a person key encodes ('0'-'9' are codes 1-10, 'a'-'z' 38-63)
    fn user_of_key(&self, key: u64) -> Option<u64> {
        if key & PTAG != 0 || key == 0 {
            return None;
        }
        let acc = key - 1;
        if acc >> 54 != 58 || acc & 63 != 0 {
            return None;
        }
        let mut v = 0u64;
        let mut n = 0;
        while n < 8 {
            let c = (acc >> (48 - 6 * n)) & 63;
            let d = match c {
                0 => break,
                1..=10 => c - 1,
                38..=63 => c - 28,
                _ => return None,
            };
            if n == 1 && v == 0 {
                return None;
            }
            v = v * 36 + d;
            n += 1;
        }
        // nothing but padding may follow the digits
        if n == 0 || acc & ((1u64 << (54 - 6 * n)) - 1) != 0 || v > M40 {
            return None;
        }
        let v = unscramble(v, self.uk);
        if v < self.ucap << 9 {
            Some(v)
        } else {
            None
        }
    }
    fn user_str(&self, un: u64, out: &mut [u8; 9]) -> usize {
        const DIG: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
        let mut x = scramble(un, self.uk);
        // the last digit taken is the first written: build the word backwards
        let mut w = 0u64;
        let mut n = 0;
        loop {
            w = (w << 8) | DIG[(x % 36) as usize] as u64;
            n += 1;
            x /= 36;
            if x == 0 {
                break;
            }
        }
        out[0] = b'u';
        out[1..].copy_from_slice(&w.to_le_bytes());
        n + 1
    }
}

// -------------------------------------------------------------- key recovery

/// keys under which candidate `i` is the first sample and the rest pass `lim`
fn scan_keys(samples: &[u64], lo: u64, hi: u64, lim: u64, users: bool, out: &mut Vec<u64>) {
    let first = samples[0];
    let d = first ^ samples[1];
    let val = |i: u64| if users { ((i >> 3) << 9) | (i & 7) } else { i };
    const B: u64 = 256;
    let mut s = lo;
    while s < hi {
        let e = (s + B).min(hi);
        let mut any = false;
        for i in s..e {
            let x = val(i).wrapping_mul(A);
            any |= ((d ^ x).wrapping_mul(AINV) & M40) < lim;
        }
        if any {
            for i in s..e {
                let key = first ^ (val(i).wrapping_mul(A) & M40);
                if samples[1..].iter().all(|&h| ((h ^ key).wrapping_mul(AINV) & M40) < lim) {
                    out.push(key);
                }
            }
        }
        s = e;
    }
}

/// the one key that decodes every sample below `lim`, if there is exactly one
fn find_key(samples: &[u64], ncand: u64, lim: u64, users: bool, nt: usize) -> Option<u64> {
    if samples.len() < 8 {
        return None;
    }
    for anchor in 0..4 {
        let mut s = samples.to_vec();
        s.swap(0, anchor);
        let nt = if ncand < (1 << 20) { 1 } else { nt.max(1) as u64 };
        let per = ncand / nt + 1;
        let mut found: Vec<u64> = Vec::new();
        std::thread::scope(|sc| {
            let hs: Vec<_> = (0..nt)
                .map(|t| {
                    let s = &s;
                    sc.spawn(move || {
                        let mut out = Vec::new();
                        scan_keys(s, (t * per).min(ncand), ((t + 1) * per).min(ncand), lim, users, &mut out);
                        out
                    })
                })
                .collect();
            for h in hs {
                found.extend(h.join().unwrap());
            }
        });
        found.sort_unstable();
        found.dedup();
        if found.len() == 1 {
            return Some(found[0]);
        }
        if found.len() > 1 {
            return None;
        }
    }
    None
}

/// both id keys from the first rows; none means the general pipeline
pub(crate) fn probe(maps: &[Map], nt: usize) -> Option<Keys> {
    if std::env::var_os("SS_NOFAST").is_some() {
        return None;
    }
    // person keys must be the encoded ids, not hashes
    if person_key(b"u0") & PTAG != 0 {
        return None;
    }
    let t0 = std::time::Instant::now();
    let simd = SIMD_OK.load(Ordering::Relaxed);
    let bytes: usize = maps.iter().map(|m| m.len).sum();
    let ncap = ((bytes / 48 + 1024) as u64).min(1 << 31);
    let ucap = (ncap / 12 + 1024).min(1 << 22);
    const WANT: usize = 12;
    let mut es: Vec<u64> = Vec::new();
    let mut us: Vec<u64> = Vec::new();
    let mut lines = 0;
    'files: for m in maps {
        let d = m.as_slice();
        let mut p = first_line_start(d, 0);
        let mut here = 0;
        while p < d.len() && here < 256 {
            let sc = scan_line(d, p, simd);
            let line = &d[p..sc.nl];
            p = sc.nl + 1;
            here += 1;
            lines += 1;
            let Some(f) = fields::<7>(line, &sc) else { continue };
            let e = &line[f[0].0 as usize..f[0].1 as usize];
            let u = &line[f[1].0 as usize..f[1].1 as usize];
            if es.len() < WANT && e.len() > 1 && e[0] == b'e' {
                if let Some(x) = b36f(&e[1..]) {
                    es.push(half(x));
                }
            }
            if us.len() < WANT && u.len() > 1 && u[0] == b'u' {
                if let Some(x) = b36f(&u[1..]) {
                    us.push(half(x));
                }
            }
            if es.len() >= WANT && us.len() >= WANT {
                break 'files;
            }
        }
        if lines > 4096 {
            break;
        }
    }
    if es.len() < WANT || us.len() < WANT {
        return None;
    }
    let ek = find_key(&es, ncap, ncap, false, nt)?;
    let uk = find_key(&us, ucap * 8, ucap << 9, true, nt)?;
    let est = (bytes / 88) as u64;
    let mut shift = 12;
    while shift < MAX_SHIFT && (est >> shift) > 2048 {
        shift += 1;
    }
    if let Some(s) = std::env::var("SS_FSHIFT").ok().and_then(|v| v.parse::<u32>().ok()) {
        shift = s.clamp(8, MAX_SHIFT);
    }
    if std::env::var("SS_TIMING").is_ok() {
        eprintln!("  fast: keys {:#x} {:#x} in {:?}, ncap {} ucap {} shift {}", ek, uk, t0.elapsed(), ncap, ucap, shift);
    }
    Some(Keys { ek, uk, ncap, ucap, shift })
}

// ------------------------------------------------------------------- parsing

struct PSt<'a> {
    es: Sink<'a, FRec>,
    cs: Sink<'a, FC>,
    odd: Vec<OddEv>,
    esc: Vec<(u64, Esc)>,
    oddc: Vec<OddCl>,
    dc: DateCache,
    ix: Box<split::Index>,
    maxc: u64,
    rows: usize,
}

struct Parsed {
    es: Vec<Vec<Blk<FRec>>>,
    cs: Vec<Vec<Blk<FC>>>,
    odd: Vec<OddEv>,
    esc: Vec<(u64, Esc)>,
    oddc: Vec<OddCl>,
    maxc: u64,
    rows: usize,
}

/// row rules as in `parse_events`; only the record differs
fn parse_ev(ctx: &Ctx, k: &Keys, fi: usize, from: usize, to: usize, st: &mut PSt) {
    let simd = SIMD_OK.load(Ordering::Relaxed);
    let d = ctx.maps[fi].as_slice();
    let p = first_line_start(d, from);
    let low = (1u64 << k.shift) - 1;
    let PSt { es, odd, esc, dc, ix, .. } = st;
    let mut rows = 0usize;
    let mut maxc = 0u64;
    split::each_row::<7, _>(d, p, to, simd, ix, #[inline(always)] |lp, s, e| {
        let fld = |k: usize| -> &[u8] { unsafe { d.get_unchecked(lp + s[k] as usize..lp + e[k] as usize) } };
        if s[0] == e[0] {
            return;
        }
        rows += 1;
        let ing_ms = parse_ts_c(fld(3), dc).unwrap_or(0);
        let ing = if ing_ms <= 0 { 0u32 } else { (ing_ms / 1000).min(u32::MAX as i64) as u32 };
        let user = fld(1);
        let mut valid = false;
        let mut ts = 0i64;
        let mut pc = 0u32;
        loop {
            if user.is_empty() {
                break;
            }
            ts = match parse_ts_c(fld(2), dc) {
                Some(t) => t,
                None => break,
            };
            if ts < ctx.ev_lo || ts >= ctx.ev_hi {
                break;
            }
            if ing_ms.saturating_sub(ts) > LATE_MS {
                break;
            }
            let ety = fld(4);
            let is_pur = match ety.len() {
                4 => {
                    if ety != b"view" && ety != b"cart" {
                        break;
                    }
                    false
                }
                8 => {
                    if ety != b"purchase" {
                        break;
                    }
                    true
                }
                _ => break,
            };
            let pid = fld(5);
            if pid.is_empty() {
                break;
            }
            if is_pur {
                let price = match digits_u32(fld(6)) {
                    Some(v) if v >= 1 && v <= 10_000_000 => v,
                    _ => break,
                };
                pc = (ctx.cat_of(pid) << 24) | price;
            }
            valid = true;
            break;
        }
        let tsf = if valid { (ts - ctx.base) as u32 } else { 0 };
        let uspan = Span { fi: fi as u32, len: user.len() as u32, off: (lp + s[1] as usize) as u64 };
        let (c, un) = k.event_at(d, lp + s[0] as usize, lp + e[0] as usize, lp + s[1] as usize, lp + e[1] as usize);
        let c = match c {
            Some(c) => c,
            None => {
                let (klo, khi) = key96(fld(0));
                odd.push(OddEv {
                    klo,
                    khi,
                    ing,
                    tsf: if valid { tsf | 0x8000_0000 } else { 0 },
                    pc: if valid { pc } else { 0 },
                    user: uspan,
                });
                return;
            }
        };
        maxc = maxc.max(c);
        let b = (c >> k.shift) as usize;
        let cl = c & low;
        if !valid {
            es.push(b, FRec { a: DEAD, b: ((ing as u64) << 32) | cl });
            return;
        }
        let delta = ing as i64 - ts.div_euclid(1000) + BIAS;
        match un {
            Some(un) if delta >= 0 && delta <= DELTA_MASK as i64 => {
                es.push(
                    b,
                    FRec {
                        a: ((tsf as u64) << 33) | (un << 2) | LIVE,
                        b: ((pc as u64) << 32) | ((delta as u64) << MAX_SHIFT) | cl,
                    },
                );
            }
            _ => {
                esc.push(((c << 32) | ing as u64, Esc { ts: tsf, pc, user: uspan }));
                es.push(b, FRec { a: ESC, b: ((ing as u64) << 32) | cl });
            }
        }
    });
    st.maxc = st.maxc.max(maxc);
    st.rows += rows;
}

/// row rules as in `parse_clicks`; the person is resolved later
fn parse_cl(ctx: &Ctx, k: &Keys, cl0: usize, fi: usize, from: usize, to: usize, st: &mut PSt) {
    let simd = SIMD_OK.load(Ordering::Relaxed);
    let d = ctx.maps[fi].as_slice();
    let p = first_line_start(d, from);
    let PSt { cs, oddc, dc, ix, .. } = st;
    let fr = (fi - cl0) as u64;
    split::each_row::<4, _>(d, p, to, simd, ix, #[inline(always)] |lp, s, e| {
        let fld = |k: usize| -> &[u8] { unsafe { d.get_unchecked(lp + s[k] as usize..lp + e[k] as usize) } };
        if s[0] == e[0] {
            return;
        }
        let user = fld(1);
        if user.is_empty() {
            return;
        }
        let ts = match parse_ts_c(fld(3), dc) {
            Some(t) => t,
            None => return,
        };
        if ts < ctx.cl_lo || ts >= ctx.cl_hi {
            return;
        }
        let camp = match ctx.camp_of(fld(2)) {
            Some(c) => c,
            None => return,
        };
        let ts = (ts - ctx.base) as u32;
        let off = (lp + s[0] as usize) as u64;
        let len = (e[0] - s[0]) as u64;
        match k.user_at(d, lp + s[1] as usize, lp + e[1] as usize) {
            Some(un) if len <= 15 && fr < 256 && off < (1 << 36) && camp < (1 << 16) => {
                let ui = un >> 9;
                cs.push(
                    (ui >> CSHIFT) as usize,
                    FC {
                        a: (ui << 40) | ((ts as u64) << 9) | (un & ALIAS),
                        b: ((camp as u64) << 48) | (fr << 40) | (off << 4) | len,
                    },
                );
            }
            _ => oddc.push(OddCl {
                user: Span { fi: fi as u32, len: user.len() as u32, off: (lp + s[1] as usize) as u64 },
                sref: sref_of(fi, off as usize, len as usize),
                ts,
                camp,
            }),
        }
    });
}

// ---------------------------------------------------------------- user table

/// per user: `k | name << 9` when its linked ids are exactly aliases 0..=k, else GENERAL
fn build_utab(links: &Links, k: &Keys) -> Blob<u32> {
    const HAS: u32 = 1 << 30;
    let mut u: Blob<u32> = Blob::zeroed(k.ucap as usize);
    let dec = |key: u64| k.user_of_key(key);
    // scratch: root alias:9, other members:10, max alias:9
    for &(id, root) in links.link.slots.iter() {
        if id == 0 {
            continue;
        }
        match (dec(id), dec(root)) {
            (Some(i), Some(r)) if i >> 9 == r >> 9 => {
                let e = &mut u[(i >> 9) as usize];
                if *e & GENERAL != 0 {
                    continue;
                }
                let (ia, ra) = ((i & ALIAS) as u32, (r & ALIAS) as u32);
                if *e & HAS == 0 {
                    *e = HAS | ra | (ra << 19);
                } else if *e & 511 != ra {
                    *e = GENERAL;
                    continue;
                }
                let mx = ((*e >> 19) & 511).max(ia);
                let cnt = ((*e >> 9) & 1023) + 1;
                *e = HAS | ra | (cnt << 9) | (mx << 19);
            }
            (i, r) => {
                if let Some(i) = i {
                    u[(i >> 9) as usize] = GENERAL;
                }
                if let Some(r) = r {
                    u[(r >> 9) as usize] = GENERAL;
                }
            }
        }
    }
    for e in u.iter_mut() {
        if *e & GENERAL != 0 || *e == 0 {
            continue;
        }
        let (root, cnt, mx) = (*e & 511, (*e >> 9) & 1023, (*e >> 19) & 511);
        *e = if mx == cnt { mx | (root << 9) } else { GENERAL };
    }
    u
}

#[inline(always)]
fn member(ue: u32, alias: u64) -> bool {
    ue & GENERAL == 0 && alias as u32 <= (ue & 511)
}

// ------------------------------------------------------------- click groups

/// a click bucket by user: `starts[l]..starts[l + 1]` is user l's own person
#[derive(Copy, Clone)]
struct CG {
    starts: *const u32,
    recs: *const FC,
}
unsafe impl Send for CG {}
unsafe impl Sync for CG {}

fn group_clicks(
    u: &[u32],
    blocks: &[Blk<FC>],
    bump: &mut Bump,
    cnt: &mut Vec<u32>,
    mut general: impl FnMut(&FC),
) -> CG {
    let nu = 1usize << CSHIFT;
    cnt.clear();
    cnt.resize(nu + 1, 0);
    for blk in blocks {
        for r in blk.as_slice() {
            let ui = (r.a >> 40) as usize;
            if member(u[ui], r.a & ALIAS) {
                cnt[ui & (nu - 1)] += 1;
            } else {
                general(r);
            }
        }
    }
    let starts = bump.alloc((nu + 1) * 4) as *mut u32;
    let mut acc = 0u32;
    for l in 0..nu {
        unsafe { *starts.add(l) = acc };
        let c = cnt[l];
        cnt[l] = acc;
        acc += c;
    }
    unsafe { *starts.add(nu) = acc };
    let recs = bump.alloc(acc as usize * 16 + 16) as *mut FC;
    for blk in blocks {
        for r in blk.as_slice() {
            let ui = (r.a >> 40) as usize;
            if member(u[ui], r.a & ALIAS) {
                let at = &mut cnt[ui & (nu - 1)];
                unsafe { *recs.add(*at as usize) = *r };
                *at += 1;
            }
        }
    }
    CG { starts, recs }
}

// ---------------------------------------------------------------------- walk

struct Sh<'a> {
    ctx: &'a Ctx,
    k: &'a Keys,
    u: &'a [u32],
    eb: &'a [Vec<Blk<FRec>>],
    cg: &'a [CG],
    esc: &'a HashMap<u64, Esc>,
    /// users whose own person has clicks only the general fold can read
    forced: &'a [u64],
    /// users whose own person has events outside the slots
    defer: &'a [u64],
    /// users folded in place, to catch one showing up twice
    seen: &'a [AtomicU64],
    bad: &'a AtomicBool,
    cl0: usize,
    gbits: u32,
}

impl<'a> Sh<'a> {
    #[inline(always)]
    fn gb(&self, person: u64) -> usize {
        if self.gbits == 0 {
            0
        } else {
            (mix(person, 0xff51_afd7_ed55_8ccd) >> (64 - self.gbits)) as usize
        }
    }
    #[inline]
    fn clicks_of(&self, ui: u32) -> &[FC] {
        let g = &self.cg[(ui >> CSHIFT) as usize];
        if g.starts.is_null() {
            return &[];
        }
        let l = (ui as usize) & ((1 << CSHIFT) - 1);
        unsafe {
            let (s, e) = (*g.starts.add(l) as usize, *g.starts.add(l + 1) as usize);
            std::slice::from_raw_parts(g.recs.add(s), e - s)
        }
    }
    #[inline]
    fn crec(&self, f: &FC, person: u64) -> CRec {
        let fi = self.cl0 + ((f.b >> 40) & 255) as usize;
        let off = ((f.b >> 4) & ((1 << 36) - 1)) as usize;
        CRec {
            person,
            sref: sref_of(fi, off, (f.b & 15) as usize),
            ts: ((f.a >> 9) & 0x7fff_ffff) as u32,
            camp: (f.b >> 48) as u32,
        }
    }
    /// the user's own person as the general fold keys it
    fn own_key(&self, ui: u32) -> u64 {
        let mut nb = [0u8; 9];
        let un = ((ui as u64) << 9) | ((self.u[ui as usize] >> 9) & 511) as u64;
        let n = self.k.user_str(un, &mut nb);
        person_key(&nb[..n])
    }
    #[inline(always)]
    fn ing(&self, r: &FRec) -> i64 {
        if r.a & 3 == LIVE {
            (self.ctx.base + (r.a >> 33) as i64).div_euclid(1000) + ((r.b >> MAX_SHIFT) & DELTA_MASK) as i64 - BIAS
        } else {
            (r.b >> 32) as i64
        }
    }
}

/// part of one user's events: a run cut by a bucket edge, or odd-id events
struct Frag {
    ui: u32,
    at: u32,
    ev: Vec<PRec>,
}

struct Wk<'a> {
    slots: Blob<FRec>,
    run: Vec<PRec>,
    cl: Vec<CRec>,
    t: Tmp,
    o: Out,
    gp: Sink<'a, PRec>,
    gc: Sink<'a, CRec>,
    frags: Vec<Frag>,
    xn: Vec<(u64, u64)>,
    g_un: u64,
    g_person: u64,
    hits: usize,
    inline_ev: usize,
    general_ev: usize,
}
struct SendWk<'a>(Wk<'a>);
unsafe impl<'a> Send for SendWk<'a> {}
unsafe impl<'a> Sync for SendWk<'a> {}

fn new_tmp(ctx: &Ctx) -> Tmp {
    let stride = ctx.ndays + 2;
    Tmp {
        ss: Vec::new(),
        sd: Vec::new(),
        sr: Vec::new(),
        sp: Vec::new(),
        cum: vec![0; stride + 2],
        cnt: vec![0; stride + 2],
        iv: vec![(0, 0); ctx.ncamp + 1],
        mark: vec![0; ctx.ncamp + 1],
        tc: vec![0; ctx.ncamp + 1],
        gen: 0,
        catrev: vec![0; ctx.cats.len() + 1],
        touch: vec![0; ctx.cats.len() + 1],
    }
}

fn new_out(ctx: &Ctx) -> Out {
    let stride = ctx.ndays + 2;
    Out {
        cd: vec![CD::default(); (ctx.ncamp + 1) * stride],
        uid: Vec::new(),
        day: Vec::new(),
        sessions: Vec::new(),
        events: Vec::new(),
        rev: Vec::new(),
        tcval: Vec::new(),
        tcdef: Vec::new(),
        tcn: 0,
    }
}

fn write_part(o: &Out, path: &Path) {
    let n = o.day.len();
    if n == 0 {
        return;
    }
    let cols = [
        pq::Col { name: "user_id", kind: pq::Kind::Utf8, vals: &o.uid, defs: &[], nvals: n as i64 },
        pq::Col { name: "day", kind: pq::Kind::Date, vals: pq::as_bytes(&o.day), defs: &[], nvals: n as i64 },
        pq::Col { name: "sessions", kind: pq::Kind::I64, vals: pq::as_bytes(&o.sessions), defs: &[], nvals: n as i64 },
        pq::Col { name: "events", kind: pq::Kind::I64, vals: pq::as_bytes(&o.events), defs: &[], nvals: n as i64 },
        pq::Col { name: "revenue_cents", kind: pq::Kind::I64, vals: pq::as_bytes(&o.rev), defs: &[], nvals: n as i64 },
        pq::Col { name: "top_category", kind: pq::Kind::Utf8Opt, vals: &o.tcval, defs: &o.tcdef, nvals: o.tcn },
    ];
    pq::write(path, n as i64, &cols).unwrap();
}

impl<'a> Wk<'a> {
    fn new(sh: &Sh, arena: &'a Arena) -> Wk<'a> {
        let nbg = 1usize << sh.gbits;
        Wk {
            slots: Blob::zeroed(1 << sh.k.shift),
            run: Vec::new(),
            cl: Vec::new(),
            t: new_tmp(sh.ctx),
            o: new_out(sh.ctx),
            gp: Sink::new(arena, nbg, 64),
            gc: Sink::new(arena, nbg, 64),
            frags: Vec::new(),
            xn: Vec::new(),
            g_un: u64::MAX,
            g_person: 0,
            hits: 0,
            inline_ev: 0,
            general_ev: 0,
        }
    }

    /// an event whose id is not part of its user's own person
    #[inline]
    fn general(&mut self, sh: &Sh, un: u64, ts: u32, pc: u32) {
        if un != self.g_un {
            let mut nb = [0u8; 9];
            let n = sh.k.user_str(un, &mut nb);
            self.g_un = un;
            self.g_person = sh.ctx.person_of(&nb[..n], &mut self.hits);
        }
        let person = self.g_person;
        self.general_ev += 1;
        self.gp.push(sh.gb(person), PRec { person, ts, pc });
    }

    /// an event whose user id is not the generator's: resolve the bytes
    fn general_str(&mut self, sh: &Sh, user: Span, ts: u32, pc: u32) {
        let person = sh.ctx.person_of(user.bytes(sh.ctx), &mut self.hits);
        if person & PTAG != 0 && sh.ctx.names.get(person).is_none() {
            self.xn.push((person, user.sref()));
        }
        self.general_ev += 1;
        self.gp.push(sh.gb(person), PRec { person, ts, pc });
    }

    /// `self.run` holds every slot event of this user's own person
    fn finish(&mut self, sh: &Sh, ui: u32, unsorted: bool) {
        if self.run.is_empty() {
            return;
        }
        if sh.forced[(ui >> 6) as usize] >> (ui & 63) & 1 != 0 {
            let person = sh.own_key(ui);
            let b = sh.gb(person);
            for e in &self.run {
                self.gp.push(b, PRec { person, ts: e.ts, pc: e.pc });
            }
            self.general_ev += self.run.len();
            return;
        }
        let bit = 1u64 << (ui & 63);
        if sh.seen[(ui >> 6) as usize].fetch_or(bit, Ordering::SeqCst) & bit != 0 {
            sh.bad.store(true, Ordering::SeqCst);
            return;
        }
        if unsorted {
            self.run.sort_unstable_by_key(|r| r.ts);
        }
        let fcs = sh.clicks_of(ui);
        self.cl.clear();
        self.cl.reserve(fcs.len());
        for f in fcs {
            self.cl.push(sh.crec(f, 0));
        }
        if self.cl.len() <= 24 {
            sort_small_c(&mut self.cl);
        } else {
            self.cl.sort_unstable_by_key(|r| r.ts);
        }
        let mut nb = [0u8; 9];
        let un = ((ui as u64) << 9) | ((sh.u[ui as usize] >> 9) & 511) as u64;
        let n = sh.k.user_str(un, &mut nb);
        self.inline_ev += self.run.len();
        process_person(sh.ctx, &self.run, &self.cl, &mut self.t, &mut self.o, &nb[..n]);
    }

    fn end_run(&mut self, sh: &Sh, ui: u32, at: u32, edge: bool, unsorted: bool) {
        if self.run.is_empty() {
            return;
        }
        if edge || sh.defer[(ui >> 6) as usize] >> (ui & 63) & 1 != 0 {
            self.frags.push(Frag { ui, at, ev: std::mem::take(&mut self.run) });
        } else {
            self.finish(sh, ui, unsorted);
            self.run.clear();
        }
    }

    /// dedup one counter range into the slots, then fold it in counter order
    fn bucket(&mut self, sh: &Sh, b: usize) {
        let blocks = &sh.eb[b];
        if blocks.is_empty() {
            return;
        }
        let n = 1usize << sh.k.shift;
        let low = n - 1;
        let slots = self.slots.as_mut_ptr();
        for blk in blocks {
            for r in blk.as_slice() {
                let s = unsafe { &mut *slots.add(r.b as usize & low) };
                if s.a == 0 || sh.ing(r) < sh.ing(s) {
                    *s = *r;
                }
            }
        }
        const NONE: u32 = u32::MAX;
        let mut cur = NONE;
        let mut ue = 0u32;
        let mut runs = 0u32;
        let mut last = 0u32;
        let mut unsorted = false;
        for i in 0..n {
            let s = unsafe { *slots.add(i) };
            if s.a == 0 {
                continue;
            }
            unsafe { (*slots.add(i)).a = 0 };
            let (ts, un, pc) = match s.a & 3 {
                DEAD => continue,
                LIVE => ((s.a >> 33) as u32, (s.a >> 2) & 0x7fff_ffff, (s.b >> 32) as u32),
                _ => {
                    let c = ((b as u64) << sh.k.shift) | i as u64;
                    let e = match sh.esc.get(&((c << 32) | (s.b >> 32))) {
                        Some(e) => *e,
                        None => {
                            sh.bad.store(true, Ordering::SeqCst);
                            continue;
                        }
                    };
                    match sh.k.user(e.user.bytes(sh.ctx)) {
                        Some(un) => (e.ts, un, e.pc),
                        None => {
                            self.general_str(sh, e.user, e.ts, e.pc);
                            continue;
                        }
                    }
                }
            };
            let ui = (un >> 9) as u32;
            if ui != cur {
                if cur != NONE {
                    self.end_run(sh, cur, (b as u32) << 1, runs == 1, unsorted);
                }
                cur = ui;
                ue = sh.u[ui as usize];
                runs += 1;
                last = 0;
                unsorted = false;
            }
            if member(ue, un & ALIAS) {
                unsorted |= ts < last;
                last = ts;
                self.run.push(PRec { person: 0, ts, pc });
            } else {
                self.general(sh, un, ts, pc);
            }
        }
        if cur != NONE {
            self.end_run(sh, cur, ((b as u32) << 1) | (runs > 1) as u32, true, unsorted);
        }
    }

    /// every fragment of one user, in counter order
    fn group(&mut self, sh: &Sh, frags: &[Frag]) {
        self.run.clear();
        // one allocation, not a doubling chain: big ones are mapped afresh
        self.run.reserve(frags.iter().map(|f| f.ev.len()).sum());
        for f in frags {
            self.run.extend_from_slice(&f.ev);
        }
        let unsorted = self.run.windows(2).any(|w| w[1].ts < w[0].ts);
        self.finish(sh, frags[0].ui, unsorted);
        self.run.clear();
    }
}

// ------------------------------------------------------------------- driver

pub(crate) struct FastOut {
    pub(crate) pb: Vec<Vec<Blk<PRec>>>,
    pub(crate) cb: Vec<Vec<Blk<CRec>>>,
    pub(crate) cd: Vec<CD>,
    pub(crate) rows: usize,
    pub(crate) xn: Vec<(u64, u64)>,
}

pub(crate) fn no_links() -> Links {
    Links { link: Map64::with_capacity(0), lbloom: Bloom::new(0), names: Map64::with_capacity(0) }
}

/// some: folded persons are written, `pb`/`cb` hold the rest; none: nothing written
pub(crate) fn run(
    ctx: &mut Ctx,
    k: &Keys,
    arena: &Arena,
    i_ev: Range<usize>,
    i_cl: Range<usize>,
    i_lk: Range<usize>,
    outdir: &Path,
    nt: usize,
) -> Option<FastOut> {
    let timing = std::env::var("SS_TIMING").is_ok();
    let t0 = std::time::Instant::now();
    let set_links = |ctx: &mut Ctx, l: Links| {
        ctx.link = l.link;
        ctx.lbloom = l.lbloom;
        ctx.names = l.names;
    };
    // timestamps travel as 31-bit offsets from the click window's start
    if ctx.cl_hi - ctx.base >= (1 << 31) || ctx.cl_hi < ctx.base || ctx.base < 0 {
        let l = build_links(&ctx.maps, i_lk, nt);
        set_links(ctx, l);
        return None;
    }

    // ---- parse, with the links built alongside
    const CHUNK: usize = 1 << 20;
    let mut chunks: Vec<(u8, usize, usize, usize)> = Vec::new();
    for (kind, r) in [(0u8, i_ev.clone()), (1u8, i_cl.clone())] {
        for fi in r {
            let n = ctx.maps[fi].len;
            let mut a = 0;
            while a < n {
                chunks.push((kind, fi, a, (a + CHUNK).min(n)));
                a += CHUNK;
            }
        }
    }
    let nb_e = ((k.ncap >> k.shift) + 1) as usize;
    let nb_c = ((k.ucap >> CSHIFT) + 1) as usize;
    let next = AtomicUsize::new(0);
    let (parts, links, utab) = {
        let cx: &Ctx = ctx;
        let work = || -> Parsed {
            let mut st = PSt {
                es: Sink::new(arena, nb_e, 512),
                cs: Sink::new(arena, nb_c, 128),
                odd: Vec::new(),
                esc: Vec::new(),
                oddc: Vec::new(),
                dc: DateCache::new(),
                ix: Box::new(split::Index::new()),
                maxc: 0,
                rows: 0,
            };
            loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= chunks.len() {
                    break;
                }
                let (kind, fi, a, b) = chunks[i];
                if kind == 0 {
                    parse_ev(cx, k, fi, a, b, &mut st);
                } else {
                    parse_cl(cx, k, i_cl.start, fi, a, b, &mut st);
                }
            }
            Parsed { es: st.es.finish(), cs: st.cs.finish(), odd: st.odd, esc: st.esc, oddc: st.oddc, maxc: st.maxc, rows: st.rows }
        };
        std::thread::scope(|s| {
            let hs: Vec<_> = (1..nt).map(|_| s.spawn(work)).collect();
            let links = build_links(&cx.maps, i_lk.clone(), nt.min(2));
            let utab = build_utab(&links, k);
            let mut parts = vec![work()];
            for h in hs {
                parts.push(h.join().unwrap());
            }
            (parts, links, utab)
        })
    };
    set_links(ctx, links);
    let ctx: &Ctx = ctx;
    let u: &[u32] = &utab;
    if timing {
        let ng = u.iter().filter(|&&e| e & GENERAL != 0).count();
        eprintln!("  fast: general users {} of {}", ng, u.len());
    }
    let t_parse = t0.elapsed();

    let mut eparts = Vec::new();
    let mut cparts = Vec::new();
    let mut odd: Vec<OddEv> = Vec::new();
    let mut oddc: Vec<OddCl> = Vec::new();
    let mut esc: HashMap<u64, Esc> = HashMap::new();
    let (mut maxc, mut rows) = (0u64, 0usize);
    for p in parts {
        eparts.push(p.es);
        cparts.push(p.cs);
        odd.extend_from_slice(&p.odd);
        oddc.extend_from_slice(&p.oddc);
        esc.extend(p.esc);
        maxc = maxc.max(p.maxc);
        rows += p.rows;
    }
    // a few odd rows are expected; many mean this is not the generator's data
    let odd_cap = std::env::var("SS_FODD").ok().and_then(|v| v.parse::<usize>().ok()).unwrap_or(rows / 16 + 4096);
    if odd.len() + esc.len() + oddc.len() > odd_cap {
        if timing {
            eprintln!("  fast: gave up, odd rows {} escaped {} odd clicks {}", odd.len(), esc.len(), oddc.len());
        }
        return None;
    }
    let eb = merge_blocks(eparts, nb_e);
    let cbk = merge_blocks(cparts, nb_c);
    let gbits = ctx.per_bits.min(10);
    let nbg = 1usize << gbits;
    let gbk = |person: u64| -> usize {
        if gbits == 0 {
            0
        } else {
            (mix(person, 0xff51_afd7_ed55_8ccd) >> (64 - gbits)) as usize
        }
    };
    let cl0 = i_cl.start;
    let mut gpp: Vec<Vec<Vec<Blk<PRec>>>> = Vec::new();
    let mut gcp: Vec<Vec<Vec<Blk<CRec>>>> = Vec::new();

    // ---- clicks: regroup each bucket by user
    let mut cg: Vec<CG> = vec![CG { starts: std::ptr::null(), recs: std::ptr::null() }; nb_c];
    {
        let next = AtomicUsize::new(0);
        let cbk = &cbk;
        std::thread::scope(|s| {
            let hs: Vec<_> = (0..nt)
                .map(|_| {
                    let next = &next;
                    s.spawn(move || {
                        let mut bump = Bump::new(arena);
                        let mut gc: Sink<CRec> = Sink::new(arena, nbg, 64);
                        let mut cnt: Vec<u32> = Vec::new();
                        let mut out: Vec<(usize, CG)> = Vec::new();
                        let mut hits = 0usize;
                        let (mut l_un, mut l_person) = (u64::MAX, 0u64);
                        loop {
                            let j = next.fetch_add(1, Ordering::Relaxed);
                            if j >= nb_c {
                                break;
                            }
                            if cbk[j].is_empty() {
                                continue;
                            }
                            let g = group_clicks(u, &cbk[j], &mut bump, &mut cnt, |f| {
                                let un = ((f.a >> 40) << 9) | (f.a & ALIAS);
                                if un != l_un {
                                    let mut nb = [0u8; 9];
                                    let n = k.user_str(un, &mut nb);
                                    l_un = un;
                                    l_person = ctx.person_of(&nb[..n], &mut hits);
                                }
                                let fi = cl0 + ((f.b >> 40) & 255) as usize;
                                let off = ((f.b >> 4) & ((1 << 36) - 1)) as usize;
                                gc.push(
                                    gbk(l_person),
                                    CRec {
                                        person: l_person,
                                        sref: sref_of(fi, off, (f.b & 15) as usize),
                                        ts: ((f.a >> 9) & 0x7fff_ffff) as u32,
                                        camp: (f.b >> 48) as u32,
                                    },
                                );
                            });
                            out.push((j, g));
                        }
                        (out, gc.finish())
                    })
                })
                .collect();
            for h in hs {
                let (out, gc) = h.join().unwrap();
                for (j, g) in out {
                    cg[j] = g;
                }
                gcp.push(gc);
            }
        });
    }
    let t_cg = t0.elapsed();

    let nw = (k.ucap as usize + 63) / 64;
    let mut forced = vec![0u64; nw];
    let mut defer = vec![0u64; nw];
    let mut frags: Vec<Frag> = Vec::new();
    let seen: Vec<AtomicU64> = (0..nw).map(|_| AtomicU64::new(0)).collect();
    let bad = AtomicBool::new(false);
    let mut xn: Vec<(u64, u64)> = Vec::new();

    // ---- rows that did not decode: string-keyed dedup, then the general fold
    {
        let mut gp: Sink<PRec> = Sink::new(arena, nbg, 64);
        let mut gc: Sink<CRec> = Sink::new(arena, nbg, 64);
        let mut hits = 0usize;
        let mut win: HashMap<(u64, u32), usize> = HashMap::new();
        for (i, r) in odd.iter().enumerate() {
            let e = win.entry((r.klo, r.khi)).or_insert(i);
            if r.ing < odd[*e].ing {
                *e = i;
            }
        }
        let sh = Sh { ctx, k, u, eb: &eb, cg: &cg, esc: &esc, forced: &[], defer: &[], seen: &seen, bad: &bad, cl0, gbits };
        // the user whose own person these bytes name, if they name one
        let own = |bytes: &[u8]| -> Option<u32> {
            let un = k.user(bytes)?;
            let ui = (un >> 9) as u32;
            if member(u[ui as usize], un & ALIAS) {
                Some(ui)
            } else {
                None
            }
        };
        // a click the groups cannot hold sends its whole person to the general fold
        for r in &oddc {
            let bytes = r.user.bytes(ctx);
            let person = match own(bytes) {
                Some(ui) => {
                    let person = sh.own_key(ui);
                    let w = &mut forced[(ui >> 6) as usize];
                    if *w >> (ui & 63) & 1 == 0 {
                        *w |= 1 << (ui & 63);
                        for f in sh.clicks_of(ui) {
                            gc.push(gbk(person), sh.crec(f, person));
                        }
                    }
                    person
                }
                None => ctx.person_of(bytes, &mut hits),
            };
            gc.push(gbk(person), CRec { person, sref: r.sref, ts: r.ts, camp: r.camp });
        }
        // an event joins its user's runs as one more piece
        let mut extra: HashMap<u32, Vec<PRec>> = HashMap::new();
        for &i in win.values() {
            let r = &odd[i];
            if r.tsf & 0x8000_0000 == 0 {
                continue;
            }
            let bytes = r.user.bytes(ctx);
            let (ts, pc) = (r.tsf & 0x7fff_ffff, r.pc);
            let person = match own(bytes) {
                Some(ui) if forced[(ui >> 6) as usize] >> (ui & 63) & 1 == 0 => {
                    defer[(ui >> 6) as usize] |= 1 << (ui & 63);
                    extra.entry(ui).or_default().push(PRec { person: 0, ts, pc });
                    continue;
                }
                Some(ui) => sh.own_key(ui),
                None => ctx.person_of(bytes, &mut hits),
            };
            if person & PTAG != 0 && ctx.names.get(person).is_none() {
                xn.push((person, r.user.sref()));
            }
            gp.push(gbk(person), PRec { person, ts, pc });
        }
        for (ui, ev) in extra {
            frags.push(Frag { ui, at: u32::MAX, ev });
        }
        gpp.push(gp.finish());
        gcp.push(gc.finish());
    }

    // ---- walk the counters
    let sh = Sh { ctx, k, u, eb: &eb, cg: &cg, esc: &esc, forced: &forced, defer: &defer, seen: &seen, bad: &bad, cl0, gbits };
    let sh = &sh;
    let nbu = ((maxc >> k.shift) + 1) as usize;
    let next = AtomicUsize::new(0);
    let mut wks: Vec<SendWk> = Vec::new();
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..nt)
            .map(|_| {
                let next = &next;
                s.spawn(move || {
                    let mut w = Wk::new(sh, arena);
                    loop {
                        let b = next.fetch_add(1, Ordering::Relaxed);
                        if b >= nbu {
                            break;
                        }
                        w.bucket(sh, b);
                    }
                    SendWk(w)
                })
            })
            .collect();
        for h in hs {
            wks.push(h.join().unwrap());
        }
    });
    let t_walk = t0.elapsed();

    // ---- runs cut by a bucket edge: put each user's pieces back together
    for w in wks.iter_mut() {
        frags.append(&mut w.0.frags);
    }
    frags.sort_unstable_by_key(|f| (f.ui, f.at));
    let mut groups: Vec<(usize, usize, usize)> = Vec::new();
    let mut i = 0;
    while i < frags.len() {
        let mut j = i;
        let mut n = 0;
        while j < frags.len() && frags[j].ui == frags[i].ui {
            n += frags[j].ev.len();
            j += 1;
        }
        groups.push((n, i, j));
        i = j;
    }
    groups.sort_unstable_by(|a, b| b.0.cmp(&a.0));
    let next = AtomicUsize::new(0);
    let wks: Vec<SendWk> = std::thread::scope(|s| {
        let hs: Vec<_> = wks
            .into_iter()
            .map(|w| {
                let (next, groups, frags) = (&next, &groups, &frags);
                s.spawn(move || {
                    let mut w = w;
                    loop {
                        let g = next.fetch_add(1, Ordering::Relaxed);
                        if g >= groups.len() {
                            break;
                        }
                        let (_, a, b) = groups[g];
                        w.0.group(sh, &frags[a..b]);
                    }
                    w
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let t_stitch = t0.elapsed();
    if bad.load(Ordering::SeqCst) {
        if timing {
            eprintln!("  fast: gave up, a user's rows were not contiguous");
        }
        return None;
    }

    // ---- write what was folded here
    let ud = outdir.join("user_daily");
    std::fs::create_dir_all(&ud).unwrap();
    let stride = ctx.ndays + 2;
    let mut cd = vec![CD::default(); (ctx.ncamp + 1) * stride];
    let mut nrows = 0usize;
    let (mut n_inline, mut n_general) = (0usize, 0usize);
    std::thread::scope(|s| {
        for (t, w) in wks.iter().enumerate() {
            let ud = &ud;
            s.spawn(move || write_part(&w.0.o, &ud.join(format!("fast-{:02}.parquet", t))));
        }
    });
    for w in wks {
        let w = w.0;
        for (a, c) in cd.iter_mut().zip(w.o.cd.iter()) {
            a.sessions += c.sessions;
            a.purch += c.purch;
            a.assist += c.assist;
            a.rev += c.rev;
        }
        nrows += w.o.day.len();
        n_inline += w.inline_ev;
        n_general += w.general_ev;
        xn.extend_from_slice(&w.xn);
        gpp.push(w.gp.finish());
        gcp.push(w.gc.finish());
    }
    let nb_per = 1usize << ctx.per_bits;
    let mut pb = merge_blocks(gpp, nbg);
    let mut cb = merge_blocks(gcp, nbg);
    pb.resize_with(nb_per, Vec::new);
    cb.resize_with(nb_per, Vec::new);
    if timing {
        eprintln!(
            "  fast: parse {:?} clicks {:?} walk {:?} stitch {:?} write {:?} | rows {} odd {} esc {} odd clicks {} | folded here {} general {} groups {}",
            t_parse,
            t_cg - t_parse,
            t_walk - t_cg,
            t_stitch - t_walk,
            t0.elapsed() - t_stitch,
            rows,
            odd.len(),
            esc.len(),
            oddc.len(),
            n_inline,
            n_general,
            groups.len()
        );
    }
    Some(FastOut { pb, cb, cd, rows: nrows, xn })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b36f_matches_reference() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let pool = b"0123456789abcdefghijklmnopqrstuvwxyzAZ_ -";
        for i in 0..200_000u64 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let n = (x % 11) as usize;
            let mut s = Vec::new();
            let mut y = x;
            for _ in 0..n {
                let m = if i % 4 == 0 { pool.len() as u64 } else { 36 };
                s.push(pool[(y % m) as usize]);
                y /= 41;
            }
            assert_eq!(b36f(&s), crate::genid::b36(&s), "{:?}", s);
        }
        assert_eq!(b36f(b"zzzzzzzz"), None);
        assert_eq!(b36f(b"e1nrf1r3"), crate::genid::b36(b"e1nrf1r3"));
    }

    #[test]
    fn b36w_matches_reference() {
        // every byte value at every position of every length
        let mut buf = vec![b'q'; 40];
        for n in 0..=10usize {
            for s in [0usize, 1, 3, 7, 8, 9, 20] {
                let e = s + n;
                for pos in s..e.max(s + 1).min(40) {
                    for c in 0..=255u8 {
                        for fill in [b'0', b'7', b'a', b'z', b'1'] {
                            for x in buf.iter_mut() {
                                *x = b',';
                            }
                            for x in buf[s..e].iter_mut() {
                                *x = fill;
                            }
                            if pos < e {
                                buf[pos] = c;
                            }
                            let want = crate::genid::b36(&buf[s..e]);
                            assert_eq!(b36w(&buf, s, e), want, "{:?}", &buf[s..e]);
                            if e >= 8 {
                                assert_eq!(word(&buf, s, e).and_then(swar36), want, "{:?}", &buf[s..e]);
                            }
                            assert_eq!(b36pair(&buf, s, e, 28, 33), (want, crate::genid::b36(&buf[28..33])), "{:?}", &buf[s..e]);
                            assert_eq!(b36pair(&buf, 29, 37, s, e), (crate::genid::b36(&buf[29..37]), want), "{:?}", &buf[s..e]);
                        }
                    }
                }
            }
        }
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let dig = b"0123456789abcdefghijklmnopqrstuvwxyz";
        for _ in 0..200_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let n = (x % 9) as usize;
            let mut y = x >> 8;
            let mut b = b"xxxxxxxxxx,u".to_vec();
            let s = b.len();
            for _ in 0..n {
                b.push(dig[(y % 36) as usize]);
                y /= 36;
            }
            let e = b.len();
            b.extend_from_slice(b",rest");
            assert_eq!(b36w(&b, s, e), crate::genid::b36(&b[s..e]), "{:?}", &b[s..e]);
            let want = crate::genid::b36(&b[s..e]);
            assert_eq!(b36pair(&b, s, e, 2, 10), (want, None));
            assert_eq!(b36pair(&b, s, e, s, e), (want, want));
            let mut two = b[s..e].to_vec();
            two.extend_from_slice(b"|0az19zz|");
            two.extend_from_slice(&b[s..e]);
            let m = two.len();
            assert_eq!(b36pair(&two, m - n, m, n + 1, n + 8), (want, crate::genid::b36(b"0az19zz")));
            assert_eq!(b36pair(&two, n + 2, n + 8, m - n, m), (crate::genid::b36(b"az19zz"), want));
        }
    }

    #[test]
    fn user_ids_round_trip() {
        let k = Keys { ek: 0x12_3456_789a, uk: 0xab_cdef_0123, ncap: 1 << 20, ucap: 1 << 12, shift: 12 };
        for un in [0u64, 1, 511, 512, 513, (1 << 21) - 1, 4095 << 9 | 400] {
            let mut b = [0u8; 9];
            let n = k.user_str(un, &mut b);
            assert_eq!(k.user(&b[..n]), Some(un));
            let mut up = b;
            up[..n].make_ascii_uppercase();
            assert_eq!(k.user(&up[..n]), None);
        }
        // the same answers straight from a person key
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let pool = b"0123456789abcdefghijklmnopqrstuvwxyzAZ_";
        for i in 0..300_000u64 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let mut s = Vec::new();
            if i % 3 != 0 {
                s.push(b'u');
            }
            let mut y = x;
            for _ in 0..(x >> 60) % 11 {
                s.push(pool[(y % if i % 5 == 0 { 39 } else { 36 }) as usize]);
                y /= 39;
            }
            let wide = Keys { ucap: 1 << 22, ..Keys { ek: k.ek, uk: k.uk, ncap: k.ncap, ucap: 0, shift: 12 } };
            let key = person_key(&s);
            if key & PTAG == 0 {
                assert_eq!(wide.user_of_key(key), wide.user(&s), "{:?}", s);
            } else {
                assert_eq!(wide.user_of_key(key), None);
            }
        }
        for un in [0u64, 1, 35, 36, 511, 512, 1 << 20, (1 << 21) + 77] {
            let mut b = [0u8; 9];
            let n = k.user_str(un, &mut b);
            assert_eq!(k.user_of_key(person_key(&b[..n])), k.user(&b[..n]));
        }
        let mut b = [0u8; 9];
        let n = k.user_str(1 << 39, &mut b);
        assert_eq!(k.user(&b[..n]), None);
        let n = k.user_str(4096 << 9, &mut b);
        assert_eq!(k.user(&b[..n]), None);
    }

    #[test]
    fn keys_come_back() {
        let (ek, uk) = (0x5a_1234_5678u64, 0x33_9876_5432u64);
        let es: Vec<u64> = (0..12u64).map(|i| half(scramble(i * 7919 + 3, ek))).collect();
        assert_eq!(find_key(&es, 200_000, 200_000, false, 3), Some(ek));
        let us: Vec<u64> = (0..12u64).map(|i| half(scramble(((i * 613 + 5) << 9) | (i % 3), uk))).collect();
        assert_eq!(find_key(&us, 20_000 * 8, 20_000 << 9, true, 2), Some(uk));
        // an anchor with a large alias is skipped
        let mut us2 = us.clone();
        us2[0] = half(scramble((77 << 9) | 300, uk));
        assert_eq!(find_key(&us2, 20_000 * 8, 20_000 << 9, true, 2), Some(uk));
        let junk: Vec<u64> = (1..13u64).map(|i| half(i.wrapping_mul(0x9E37_79B9_7F4A_7C15) & M40)).collect();
        assert_eq!(find_key(&junk, 200_000, 200_000, false, 2), None);
    }
}
