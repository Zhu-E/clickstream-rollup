// fast path: ids decode to counters, so dedup is a slot and order is free
use crate::genid::{half, scramble, unscramble, A, AINV, M40};
use crate::*;
use std::collections::HashMap;
use std::ops::Range;
use std::sync::atomic::{AtomicU32, AtomicU64};

const ALIAS: u64 = 511;
const DELTA_BITS: u32 = 17;
const DELTA_MASK: u64 = (1 << DELTA_BITS) - 1;
/// how far before its event an ingest may be and still fit: with 24 h after, 2^17 seconds
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
const NONE: u64 = u64::MAX;

const fn by_digits(what: u32) -> [u64; 9] {
    let mut t = [0u64; 9];
    let mut m = 1;
    let mut pow = 1u64;
    while m <= 8 {
        t[m] = match what {
            // the id's own bytes of the word that ends with it
            0 => !0u64 << (64 - 8 * m),
            // '0' in the bytes before it
            1 => if m == 8 { 0 } else { (L8 * 0x30) >> (8 * m) },
            // smallest value with m digits and no leading zero
            2 => if m == 1 { 0 } else { pow },
            // how far above that a 40-bit value can be
            _ => M40 - if m == 1 { 0 } else { pow },
        };
        pow *= 36;
        m += 1;
    }
    t
}

static KEEP: [u64; 9] = by_digits(0);
static FILL: [u64; 9] = by_digits(1);
static LEAST: [u64; 9] = by_digits(2);
static SPAN: [u64; 9] = by_digits(3);

/// eight base-36 digits, first in the low byte; checked by encoding back
#[cfg_attr(all(target_arch = "x86_64", target_feature = "sse4.1"), allow(dead_code))]
#[inline(always)]
fn swar36(w: u64) -> u64 {
    let alpha = (w >> 6) & L8;
    let v = (w & (L8 * 0x0f)) + alpha * 9 + (alpha & (w >> 4)) * 16;
    let ten = ((v + L8 * 118) >> 7) & L8;
    if v + L8 * 0x30 + ten * 0x27 != w || (v + L8 * 92) & (L8 * 0x80) != 0 {
        return NONE;
    }
    let v = (v & 0x00ff_00ff_00ff_00ff) * 36 + ((v >> 8) & 0x00ff_00ff_00ff_00ff);
    let v = (v & 0x0000_ffff_0000_ffff) * 1296 + ((v >> 16) & 0x0000_ffff_0000_ffff);
    (v & 0xffff_ffff) * 1_679_616 + (v >> 32)
}

/// two words of eight digits each; NONE for a word with a byte that is no digit
#[cfg(all(target_arch = "x86_64", target_feature = "sse4.1"))]
#[inline(always)]
fn pair36(w0: u64, w1: u64) -> (u64, u64) {
    use core::arch::x86_64::*;
    unsafe {
        let x = _mm_set_epi64x(w1 as i64, w0 as i64);
        let alpha = _mm_cmpgt_epi8(x, _mm_set1_epi8(0x60));
        let v = _mm_sub_epi8(x, _mm_add_epi8(_mm_set1_epi8(0x30), _mm_and_si128(alpha, _mm_set1_epi8(0x27))));
        let lim = _mm_add_epi8(_mm_set1_epi8(9), _mm_and_si128(alpha, _mm_set1_epi8(26)));
        let bad = _mm_movemask_epi8(_mm_cmpeq_epi8(_mm_min_epu8(v, lim), v)) as u32 ^ 0xffff;
        let p = _mm_maddubs_epi16(v, _mm_set1_epi16(0x0124));
        let q = _mm_madd_epi16(p, _mm_set1_epi32(0x0001_0510));
        let z0 = _mm_cvtsi128_si64(q) as u64;
        let z1 = _mm_extract_epi64(q, 1) as u64;
        let v0 = (z0 & 0xffff_ffff) * 1_679_616 + (z0 >> 32);
        let v1 = (z1 & 0xffff_ffff) * 1_679_616 + (z1 >> 32);
        (if bad & 0xff == 0 { v0 } else { NONE }, if bad >> 8 == 0 { v1 } else { NONE })
    }
}

#[cfg(not(all(target_arch = "x86_64", target_feature = "sse4.1")))]
#[inline(always)]
fn pair36(w0: u64, w1: u64) -> (u64, u64) {
    (swar36(w0), swar36(w1))
}

/// the word of digits for an id of `m` digits that ends at `e`; needs `e >= 8`
#[inline(always)]
unsafe fn digits_word(d: &[u8], e: usize, m: usize) -> u64 {
    debug_assert!(e >= 8 && e <= d.len() && m >= 1 && m <= 8);
    let w = u64::from_le((d.as_ptr().add(e - 8) as *const u64).read_unaligned());
    (w & *KEEP.get_unchecked(m)) | *FILL.get_unchecked(m)
}

impl Keys {
    /// `counter` and `user` of two ids in one row, the event id first; NONE where one does not decode
    #[inline(always)]
    fn event_at(&self, d: &[u8], es: usize, ee: usize, us: usize, ue: usize) -> (u64, u64) {
        let (me, mu) = ((ee - es).wrapping_sub(1), (ue - us).wrapping_sub(1));
        // the usual shape: a letter and 1 to 8 digits, not in the file's first bytes
        if (me.wrapping_sub(1) | mu.wrapping_sub(1)) > 7 || es < 8 || us < ee || ue > d.len() {
            return (self.counter(&d[es..ee]), self.user(&d[us..ue]).unwrap_or(NONE));
        }
        unsafe {
            let (ve, vu) = pair36(digits_word(d, ee, me), digits_word(d, ue, mu));
            // one compare each: no leading zero, and no more than 40 bits
            let oke = *d.get_unchecked(es) == b'e' && ve.wrapping_sub(*LEAST.get_unchecked(me)) <= *SPAN.get_unchecked(me);
            let oku = *d.get_unchecked(us) == b'u' && vu.wrapping_sub(*LEAST.get_unchecked(mu)) <= *SPAN.get_unchecked(mu);
            let c = unscramble(ve & M40, self.ek);
            let u = unscramble(vu & M40, self.uk);
            (if oke && c < self.ncap { c } else { NONE }, if oku && u < self.ucap << 9 { u } else { NONE })
        }
    }
    /// `user` for the id at `d[s..e]`; NONE when it does not decode
    #[inline(always)]
    fn user_at(&self, d: &[u8], s: usize, e: usize) -> u64 {
        let m = (e - s).wrapping_sub(1);
        if m.wrapping_sub(1) > 7 || s < 8 || e > d.len() {
            return self.user(&d[s..e]).unwrap_or(NONE);
        }
        unsafe {
            let w = digits_word(d, e, m);
            let v = pair36(w, w).0;
            let ok = *d.get_unchecked(s) == b'u' && v.wrapping_sub(*LEAST.get_unchecked(m)) <= *SPAN.get_unchecked(m);
            let u = unscramble(v & M40, self.uk);
            if ok && u < self.ucap << 9 {
                u
            } else {
                NONE
            }
        }
    }
    /// the counter an event id spells, by the byte loop; NONE when it does not decode
    fn counter(&self, eid: &[u8]) -> u64 {
        if eid.is_empty() || eid[0] != b'e' {
            return NONE;
        }
        match b36f(&eid[1..]) {
            Some(x) if unscramble(x, self.ek) < self.ncap => unscramble(x, self.ek),
            _ => NONE,
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

/// both keys from rows of the busiest users, whose numbers are smallest; none: search
fn quick_keys(both: &[(u64, u64)], es: &[u64], us: &[u64], ncap: u64, ucap: u64) -> Option<(u64, u64)> {
    let ulim = ucap << 9;
    let mut uk: Option<u64> = None;
    for &(_, hu) in both.iter().take(512) {
        for v in 0..64u64 {
            let key = hu ^ ((((v >> 3) << 9) | (v & 7)).wrapping_mul(A) & M40);
            if us.iter().all(|&h| ((h ^ key).wrapping_mul(AINV) & M40) < ulim) {
                match uk {
                    Some(seen) if seen != key => return None,
                    _ => uk = Some(key),
                }
            }
        }
    }
    let uk = uk?;
    let zero: Vec<u64> = both.iter().filter(|p| ((p.1 ^ uk).wrapping_mul(AINV) & M40) >> 9 == 0).map(|p| p.0).take(8).collect();
    if zero.len() < 3 {
        return None;
    }
    // no user has more than a fiftieth of the events
    let lim = ncap / 32 + 4096;
    let mut found = Vec::new();
    scan_keys(&zero, 0, lim, lim, false, &mut found);
    found.retain(|&key| es.iter().all(|&h| ((h ^ key).wrapping_mul(AINV) & M40) < ncap));
    found.sort_unstable();
    found.dedup();
    if found.len() == 1 {
        Some((found[0], uk))
    } else {
        None
    }
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
    // rows to look through for the busiest users
    const ROWS: usize = 2048;
    let mut both: Vec<(u64, u64)> = Vec::new();
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
            let ex = if e.len() > 1 && e[0] == b'e' { b36f(&e[1..]) } else { None };
            let ux = if u.len() > 1 && u[0] == b'u' { b36f(&u[1..]) } else { None };
            if let (Some(x), true) = (ex, es.len() < WANT) {
                es.push(half(x));
            }
            if let (Some(x), true) = (ux, us.len() < WANT) {
                us.push(half(x));
            }
            if let (Some(a), Some(b)) = (ex, ux) {
                both.push((half(a), half(b)));
            }
            if es.len() >= WANT && us.len() >= WANT && both.len() >= ROWS {
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
    let (ek, uk) = match quick_keys(&both, &es, &us, ncap, ucap) {
        Some(found) => found,
        None => (find_key(&es, ncap, ncap, false, nt)?, find_key(&us, ucap * 8, ucap << 9, true, nt)?),
    };
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
    lloc: Vec<Vec<LocalLink>>,
    lglob: Vec<GlobalLink>,
    maxc: u64,
    rows: usize,
}

struct Parsed {
    es: Vec<Vec<Blk<FRec>>>,
    cs: Vec<Vec<Blk<FC>>>,
    odd: Vec<OddEv>,
    esc: Vec<(u64, Esc)>,
    oddc: Vec<OddCl>,
    lloc: Vec<Vec<LocalLink>>,
    lglob: Vec<GlobalLink>,
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
        let g = ingest(fld(3), dc);
        let (ing_ms, ing) = (g.ms, g.sec);
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
            if ing_ms > ts.saturating_add(LATE_MS) {
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
        if c == NONE {
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
        maxc = maxc.max(c);
        let b = (c >> k.shift) as usize;
        let cl = c & low;
        if !valid {
            es.push(b, FRec { a: DEAD, b: ((ing as u64) << 32) | cl });
            return;
        }
        // not late, so at most 24 h after the event; this bounds it below
        match un {
            un if un != NONE && ing_ms + BIAS * 1000 >= ts => {
                es.push(
                    b,
                    FRec {
                        a: ((tsf as u64) << 33) | (un << 2) | LIVE,
                        b: ((pc as u64) << 32) | ((ing as u64 & DELTA_MASK) << MAX_SHIFT) | cl,
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
            un if un != NONE && len <= 15 && fr < 256 && off < (1 << 36) && camp < (1 << 16) => {
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

const LSHIFT: u32 = 12;

/// a link whose ids are two aliases of one user: user:22 | alias:9 | alias:9
type LocalLink = u64;
/// any other link, as `build_links` reads one: key and bytes of each side
type GlobalLink = (u64, u64, u64, u64);

/// row rules as in `build_links`; a row is local, global or (a self-link) nothing
fn parse_lk(ctx: &Ctx, k: &Keys, shared: &[AtomicU64], fi: usize, from: usize, to: usize, st: &mut PSt) {
    let simd = SIMD_OK.load(Ordering::Relaxed);
    let d = ctx.maps[fi].as_slice();
    let p = first_line_start(d, from);
    let PSt { lloc, lglob, ix, .. } = st;
    split::each_row::<2, _>(d, p, to, simd, ix, #[inline(always)] |lp, s, e| {
        let (a0, a1) = (lp + s[0] as usize, lp + e[0] as usize);
        let (b0, b1) = (lp + s[1] as usize, lp + e[1] as usize);
        if a0 == a1 || b0 == b1 {
            return;
        }
        let (ua, ub) = (k.user_at(d, a0, a1), k.user_at(d, b0, b1));
        if ua != NONE && ub != NONE && ua >> 9 == ub >> 9 {
            if ua != ub {
                lloc[(ua >> (9 + LSHIFT)) as usize].push((ua << 9) | (ub & ALIAS));
            }
            return;
        }
        let (a, b) = (&d[a0..a1], &d[b0..b1]);
        if a == b {
            return;
        }
        // a user that a global link touches is resolved through the link map
        for v in [ua, ub] {
            if v != NONE {
                shared[(v >> 15) as usize].fetch_or(1 << ((v >> 9) & 63), Ordering::Relaxed);
            }
        }
        lglob.push((person_key(a), sref_of(fi, a0, a.len()), person_key(b), sref_of(fi, b0, b.len())));
    });
}

/// One range of users from their local links: a table entry each, and the
/// links of users that need the link map after all.
const P36: [u64; 9] = [1, 36, 1_296, 46_656, 1_679_616, 60_466_176, 2_176_782_336, 78_364_164_096, 2_821_109_907_456];

/// orders like the bytes of `u` + base 36 of x
#[inline(always)]
fn id_order(x: u64) -> u64 {
    let mut nd = 1;
    while nd < 8 && x >= P36[nd] {
        nd += 1;
    }
    ((x * P36[8 - nd]) << 4) | nd as u64
}

/// One range of users from their local links; `mask` is a zeroed word per user of the range.
fn resolve_local(k: &Keys, rows: &mut [LocalLink], shared: &[AtomicU64], u: &[AtomicU32], moved: &mut Vec<GlobalLink>, mask: &mut [u64]) {
    if rows.is_empty() {
        return;
    }
    let n = mask.len();
    for &row in rows.iter() {
        let hi = ((row >> 9) & ALIAS).max(row & ALIAS);
        // bit 0: an alias too large for the word
        mask[((row >> 18) as usize) & (n - 1)] |= if hi < 64 { 1u64 << hi } else { 1 };
    }
    let base = (rows[0] >> 18) & !(n as u64 - 1);
    let mut left = false;
    for l in 0..n {
        let m = mask[l];
        if m == 0 {
            continue;
        }
        let ui = base | l as u64;
        let top = 63 - m.leading_zeros() as u64;
        // every alias from 1 to top is linked to a smaller one: one person, aliases 0..=top
        if m == (!0u64 >> (63 - top)) & !1 && shared[(ui >> 6) as usize].load(Ordering::Relaxed) >> (ui & 63) & 1 == 0 {
            let name = (0..=top).min_by_key(|&a| id_order(scramble((ui << 9) | a, k.uk))).unwrap();
            u[ui as usize].store(top as u32 | ((name as u32) << 9), Ordering::Relaxed);
            mask[l] = 0;
        } else {
            left = true;
        }
    }
    if left {
        let mut rest: Vec<LocalLink> = rows.iter().copied().filter(|&row| mask[((row >> 18) as usize) & (n - 1)] != 0).collect();
        resolve_local_any(k, &mut rest, shared, u, moved);
        for &row in rows.iter() {
            mask[((row >> 18) as usize) & (n - 1)] = 0;
        }
    }
}

/// the same for any shape of links, by union-find
fn resolve_local_any(k: &Keys, rows: &mut [LocalLink], shared: &[AtomicU64], u: &[AtomicU32], moved: &mut Vec<GlobalLink>) {
    fn find(par: &mut [u16; 512], mut x: u16) -> u16 {
        while par[x as usize] != x {
            par[x as usize] = par[par[x as usize] as usize];
            x = par[x as usize];
        }
        x
    }
    rows.sort_unstable();
    let mut par = [0u16; 512];
    let mut seen = [false; 512];
    let mut list: Vec<u16> = Vec::new();
    let key_of = |un: u64| {
        let mut nb = [0u8; 9];
        let n = k.user_str(un, &mut nb);
        person_key(&nb[..n])
    };
    let mut i = 0;
    while i < rows.len() {
        let ui = rows[i] >> 18;
        let mut j = i;
        while j < rows.len() && rows[j] >> 18 == ui {
            j += 1;
        }
        let mut entry = GENERAL;
        if shared[(ui >> 6) as usize].load(Ordering::Relaxed) >> (ui & 63) & 1 == 0 {
            list.clear();
            for &row in &rows[i..j] {
                let (a, b) = (((row >> 9) & ALIAS) as u16, (row & ALIAS) as u16);
                for v in [a, b] {
                    if !seen[v as usize] {
                        seen[v as usize] = true;
                        par[v as usize] = v;
                        list.push(v);
                    }
                }
                let (ra, rb) = (find(&mut par, a), find(&mut par, b));
                par[ra as usize] = rb;
            }
            let top = *list.iter().max().unwrap();
            let roots = list.iter().filter(|&&v| par[v as usize] == v).count();
            // one component, and it is exactly aliases 0..=top
            if roots == 1 && top as usize + 1 == list.len() {
                let name = (0..=top as u64).min_by_key(|&a| key_of((ui << 9) | a)).unwrap();
                entry = top as u32 | ((name as u32) << 9);
            }
            for &v in &list {
                seen[v as usize] = false;
            }
        }
        if entry == GENERAL {
            for &row in &rows[i..j] {
                moved.push((key_of((ui << 9) | ((row >> 9) & ALIAS)), 0, key_of((ui << 9) | (row & ALIAS)), 0));
            }
        }
        u[ui as usize].store(entry, Ordering::Relaxed);
        i = j;
    }
}

/// what `build_links` makes, from rows already read
fn links_from_rows(maps: &[Map], rows: &[GlobalLink]) -> Links {
    let cap = rows.len() * 2 + 16;
    let mut j = Joiner { maps, idx: Map64::with_capacity(cap), nodes: Blob::reserved(cap), srefs: Blob::reserved(cap), n: 0 };
    for &(ka, sa, kb, sb) in rows {
        let a = j.node(ka, sa);
        let b = j.node(kb, sb);
        j.union(a, b);
    }
    let n = j.n;
    let mut lbloom = Bloom::new(n + 16);
    let mut names = Map64::with_capacity(n / 2 + 16);
    let mut link = std::mem::replace(&mut j.idx, Map64::with_capacity(0));
    for s in 0..link.slots.len() {
        let (key, node) = link.slots[s];
        if key == 0 {
            continue;
        }
        let root = j.find(node as u32);
        link.slots[s].1 = j.nodes[root as usize].key;
        if root != node as u32 {
            lbloom.insert(key);
        } else if key & PTAG != 0 {
            names.insert(key, j.srefs[root as usize]);
        }
    }
    Links { link, lbloom, names }
}

/// `Ctx::person_of` against links that are not published yet
#[inline(always)]
fn person_in(lk: &Links, user: &[u8]) -> u64 {
    let key = person_key(user);
    if !lk.lbloom.maybe(key) {
        return key;
    }
    lk.link.get(key).unwrap_or(key)
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
    lk: &'a Links,
    k: &'a Keys,
    u: &'a [u32],
    eb: &'a [Vec<Blk<FRec>>],
    cg: &'a [CG],
    esc: &'a HashMap<u64, Esc>,
    /// rows to reserve in a worker's output
    out_rows: usize,
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
            // the one second in the event's window with these low bits
            let lo = (self.ctx.base + (r.a >> 33) as i64).div_euclid(1000) - BIAS;
            lo + ((((r.b >> MAX_SHIFT) & DELTA_MASK) as i64 - lo) & DELTA_MASK as i64)
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
    /// longest regrouped fold: nanoseconds, events; and all of them together
    slowest: (u128, usize),
    regroup_ns: u128,
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

impl<'a> Wk<'a> {
    fn new(sh: &Sh, arena: &'a Arena) -> Wk<'a> {
        let nbg = 1usize << sh.gbits;
        Wk {
            slots: Blob::zeroed(1 << sh.k.shift),
            run: Vec::new(),
            cl: Vec::new(),
            t: new_tmp(sh.ctx),
            o: Out::new(sh.out_rows, (sh.ctx.ncamp + 1) * (sh.ctx.ndays + 2)),
            gp: Sink::new(arena, nbg, 64),
            gc: Sink::new(arena, nbg, 64),
            frags: Vec::new(),
            xn: Vec::new(),
            g_un: u64::MAX,
            g_person: 0,
            hits: 0,
            inline_ev: 0,
            general_ev: 0,
            slowest: (0, 0),
            regroup_ns: 0,
        }
    }

    /// an event whose id is not part of its user's own person
    #[inline]
    fn general(&mut self, sh: &Sh, un: u64, ts: u32, pc: u32) {
        if un != self.g_un {
            let mut nb = [0u8; 9];
            let n = sh.k.user_str(un, &mut nb);
            self.g_un = un;
            self.hits += 1;
            self.g_person = person_in(sh.lk, &nb[..n]);
        }
        let person = self.g_person;
        self.general_ev += 1;
        self.gp.push(sh.gb(person), PRec { person, ts, pc });
    }

    /// an event whose user id is not the generator's: resolve the bytes
    fn general_str(&mut self, sh: &Sh, user: Span, ts: u32, pc: u32) {
        let person = person_in(sh.lk, user.bytes(sh.ctx));
        if person & PTAG != 0 && sh.lk.names.get(person).is_none() {
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
        // odd-id events sort last among a user's pieces
        let (slots, odd) = match frags.split_last() {
            Some((f, rest)) if f.at == u32::MAX => (rest, Some(f)),
            _ => (frags, None),
        };
        self.run.clear();
        // one allocation, not a doubling chain: big ones are mapped afresh
        self.run.reserve(frags.iter().map(|f| f.ev.len()).sum());
        for f in slots {
            self.run.extend_from_slice(&f.ev);
        }
        let unsorted = self.run.windows(2).any(|w| w[1].ts < w[0].ts);
        if let Some(f) = odd {
            if unsorted {
                self.run.extend_from_slice(&f.ev);
            } else {
                // a handful of events into a long sorted run: merge from the back
                let mut x = f.ev.clone();
                x.sort_unstable_by_key(|r| r.ts);
                let (mut i, mut j) = (self.run.len(), x.len());
                let mut w = i + j;
                self.run.resize(w, PRec { person: 0, ts: 0, pc: 0 });
                while j > 0 {
                    if i > 0 && self.run[i - 1].ts > x[j - 1].ts {
                        self.run[w - 1] = self.run[i - 1];
                        i -= 1;
                    } else {
                        self.run[w - 1] = x[j - 1];
                        j -= 1;
                    }
                    w -= 1;
                }
            }
        }
        self.finish(sh, frags[0].ui, unsorted);
        self.run.clear();
    }
}

// ------------------------------------------------------------------- driver

pub(crate) struct FastOut {
    pub(crate) pb: Vec<Vec<Blk<PRec>>>,
    pub(crate) cb: Vec<Vec<Blk<CRec>>>,
    /// one per worker, unwritten: the caller settles the column width
    pub(crate) outs: Vec<Out>,
    pub(crate) xn: Vec<(u64, u64)>,
}

/// some: `outs` hold the folded persons, `pb`/`cb` the rest; none: structure did not hold
pub(crate) fn run(
    ctx: &Ctx,
    k: &Keys,
    arena: &Arena,
    i_ev: Range<usize>,
    i_cl: Range<usize>,
    i_lk: Range<usize>,
    nt: usize,
) -> Option<FastOut> {
    let timing = std::env::var("SS_TIMING").is_ok();
    let t0 = std::time::Instant::now();
    // timestamps travel as 31-bit offsets from the click window's start
    if ctx.cl_hi - ctx.base >= (1 << 31) || ctx.cl_hi < ctx.base || ctx.base < 0 {
        return None;
    }
    // ingest seconds are kept as a u32
    if ctx.cl_hi >= (u32::MAX as i64 - 86_400) * 1000 {
        return None;
    }

    // ---- parse, with the links built alongside
    const CHUNK: usize = 1 << 20;
    let mut chunks: Vec<(u8, usize, usize, usize)> = Vec::new();
    for (kind, r) in [(2u8, i_lk.clone()), (0u8, i_ev.clone()), (1u8, i_cl.clone())] {
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
    let mut utab: Blob<u32> = Blob::zeroed(k.ucap as usize);
    // the same words, while several threads fill disjoint users
    let scratch: &[AtomicU32] = unsafe { std::slice::from_raw_parts(utab.as_mut_ptr() as *const AtomicU32, utab.len()) };
    let nb_l = ((k.ucap >> LSHIFT) + 1) as usize;
    let shared: Vec<AtomicU64> = (0..(k.ucap as usize + 63) / 64).map(|_| AtomicU64::new(0)).collect();
    let mut parts: Vec<Parsed> = {
        let cx: &Ctx = ctx;
        let shared = &shared[..];
        let work = || -> Parsed {
            let mut st = PSt {
                es: Sink::new(arena, nb_e, 512),
                cs: Sink::new(arena, nb_c, 128),
                odd: Vec::new(),
                esc: Vec::new(),
                oddc: Vec::new(),
                dc: DateCache::new(),
                ix: Box::new(split::Index::new()),
                lloc: (0..nb_l).map(|_| Vec::new()).collect(),
                lglob: Vec::new(),
                maxc: 0,
                rows: 0,
            };
            loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= chunks.len() {
                    break;
                }
                let (kind, fi, a, b) = chunks[i];
                match kind {
                    0 => parse_ev(cx, k, fi, a, b, &mut st),
                    1 => parse_cl(cx, k, i_cl.start, fi, a, b, &mut st),
                    _ => parse_lk(cx, k, shared, fi, a, b, &mut st),
                }
            }
            Parsed {
                es: st.es.finish(),
                cs: st.cs.finish(),
                odd: st.odd,
                esc: st.esc,
                oddc: st.oddc,
                lloc: st.lloc,
                lglob: st.lglob,
                maxc: st.maxc,
                rows: st.rows,
            }
        };
        std::thread::scope(|s| {
            let hs: Vec<_> = (1..nt).map(|_| s.spawn(work)).collect();
            let mut parts = vec![work()];
            for h in hs {
                parts.push(h.join().unwrap());
            }
            parts
        })
    };
    let t_rows = t0.elapsed();

    // ---- links: each user from its own rows, the link map for the rest
    let mut global: Vec<GlobalLink> = Vec::new();
    let mut local: Vec<Vec<Vec<LocalLink>>> = (0..nb_l).map(|_| Vec::new()).collect();
    for p in parts.iter_mut() {
        global.append(&mut p.lglob);
        for (r, v) in std::mem::take(&mut p.lloc).into_iter().enumerate() {
            if !v.is_empty() {
                local[r].push(v);
            }
        }
    }
    let (n_global, n_local) = (global.len(), local.iter().flatten().map(|v| v.len()).sum::<usize>());
    {
        let lnext = AtomicUsize::new(0);
        let (local, shared) = (&local, &shared[..]);
        std::thread::scope(|s| {
            let hs: Vec<_> = (0..nt)
                .map(|_| {
                    let lnext = &lnext;
                    s.spawn(move || {
                        let mut moved: Vec<GlobalLink> = Vec::new();
                        let mut rows: Vec<LocalLink> = Vec::new();
                        let mut mask = vec![0u64; 1 << LSHIFT];
                        loop {
                            let r = lnext.fetch_add(1, Ordering::Relaxed);
                            if r >= local.len() {
                                break;
                            }
                            rows.clear();
                            for v in &local[r] {
                                rows.extend_from_slice(v);
                            }
                            resolve_local(k, &mut rows, shared, scratch, &mut moved, &mut mask);
                        }
                        moved
                    })
                })
                .collect();
            for h in hs {
                global.extend(h.join().unwrap());
            }
        });
    }
    // users with a global link and no local one
    for (w, bits) in shared.iter().enumerate() {
        let mut m = bits.load(Ordering::Relaxed);
        while m != 0 {
            utab[w * 64 + m.trailing_zeros() as usize] = GENERAL;
            m &= m - 1;
        }
    }
    let links = links_from_rows(&ctx.maps, &global);
    let lk: &Links = &links;
    let n_moved = global.len() - n_global;
    let t_links = t0.elapsed() - t_rows;
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
    let t_merged = t0.elapsed();
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
                                    hits += 1;
                                    l_person = person_in(lk, &nb[..n]);
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
        let mut win: HashMap<(u64, u32), usize> = HashMap::new();
        for (i, r) in odd.iter().enumerate() {
            let e = win.entry((r.klo, r.khi)).or_insert(i);
            if r.ing < odd[*e].ing {
                *e = i;
            }
        }
        let sh = Sh { ctx, lk, k, u, eb: &eb, cg: &cg, esc: &esc, out_rows: 0, forced: &[], defer: &[], seen: &seen, bad: &bad, cl0, gbits };
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
                None => person_in(lk, bytes),
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
                None => person_in(lk, bytes),
            };
            if person & PTAG != 0 && lk.names.get(person).is_none() {
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
    let t_odd = t0.elapsed();
    // a fair share at one row per event: far more than needed, and untouched pages cost nothing
    let out_rows = rows / nt.max(1) + 4096;
    let sh = Sh { ctx, lk, k, u, eb: &eb, cg: &cg, esc: &esc, out_rows, forced: &forced, defer: &defer, seen: &seen, bad: &bad, cl0, gbits };
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
                        let (n, a, b) = groups[g];
                        let tg = std::time::Instant::now();
                        w.0.group(sh, &frags[a..b]);
                        let ns = tg.elapsed().as_nanos();
                        w.0.regroup_ns += ns;
                        if ns > w.0.slowest.0 {
                            w.0.slowest = (ns, n);
                        }
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

    // ---- hand the folded rows back unwritten
    let mut outs: Vec<Out> = Vec::new();
    let (mut n_inline, mut n_general) = (0usize, 0usize);
    let (mut slowest, mut regroup_ns) = ((0u128, 0usize), 0u128);
    for w in wks {
        let w = w.0;
        regroup_ns += w.regroup_ns;
        slowest = slowest.max(w.slowest);
        n_inline += w.inline_ev;
        n_general += w.general_ev;
        xn.extend_from_slice(&w.xn);
        gpp.push(w.gp.finish());
        gcp.push(w.gc.finish());
        outs.push(w.o);
    }
    let nb_per = 1usize << ctx.per_bits;
    let mut pb = merge_blocks(gpp, nbg);
    let mut cb = merge_blocks(gcp, nbg);
    pb.resize_with(nb_per, Vec::new);
    cb.resize_with(nb_per, Vec::new);
    if timing {
        eprintln!(
            "  fast: links after parse {:?}, rows local {} global {} moved {} | parse {:?} merge {:?} clicks {:?} odd {:?} walk {:?} regroup {:?} (thread time {:?}, longest {:?} for {} events) tail {:?} | rows {} odd {} esc {} odd clicks {} | folded here {} general {} groups {}",
            t_links,
            n_local,
            n_global,
            n_moved,
            t_rows,
            t_merged - t_parse,
            t_cg - t_merged,
            t_odd - t_cg,
            t_walk - t_odd,
            t_stitch - t_walk,
            std::time::Duration::from_nanos(regroup_ns as u64),
            std::time::Duration::from_nanos(slowest.0 as u64),
            slowest.1,
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
    // nothing below needs more than these links
    ctx.set_links(links);
    Some(FastOut { pb, cb, outs, xn })
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
    fn row_decoders_match_the_byte_loop() {
        let k = Keys { ek: 0x12_3456_789a, uk: 0xab_cdef_0123, ncap: 1 << 39, ucap: 1 << 22, shift: 12 };
        let chk = |b: &[u8], es: usize, ee: usize, us: usize, ue: usize| {
            let want = (k.counter(&b[es..ee]), k.user(&b[us..ue]).unwrap_or(NONE));
            assert_eq!(k.event_at(b, es, ee, us, ue), want, "{:?} {:?}", &b[es..ee], &b[us..ue]);
            if us < ue {
                assert_eq!(k.user_at(b, us, ue), want.1, "{:?}", &b[us..ue]);
            }
            for w in [(es + 1, ee), (us + 1, ue)] {
                if w.1 >= 8 && w.1 > w.0 && w.1 - w.0 <= 8 {
                    let word = unsafe { digits_word(b, w.1, w.1 - w.0) };
                    let lane = pair36(word, word);
                    assert_eq!(swar36(word), lane.0, "{:?}", &b[w.0..w.1]);
                    assert_eq!(lane.0, lane.1);
                }
            }
        };
        // every byte value at every position of every length
        for pre in [0usize, 3, 8, 11] {
            for ne in 1..=11usize {
                for nu in 0..=11usize {
                    let mut b = vec![b'x'; pre];
                    let es = b.len();
                    b.push(b'e');
                    b.extend(std::iter::repeat(b'7').take(ne - 1));
                    let ee = b.len();
                    b.push(b',');
                    let us = b.len();
                    if nu > 0 {
                        b.push(b'u');
                        b.extend(std::iter::repeat(b'z').take(nu - 1));
                    }
                    let ue = b.len();
                    b.extend_from_slice(b",tail");
                    chk(&b, es, ee, us, ue);
                    for pos in (es..ee).chain(us..ue) {
                        let keep = b[pos];
                        for c in 0..=255u8 {
                            b[pos] = c;
                            chk(&b, es, ee, us, ue);
                        }
                        b[pos] = keep;
                    }
                }
            }
        }
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let dig = b"0123456789abcdefghijklmnopqrstuvwxyz";
        for _ in 0..200_000 {
            let mut b = b"xxxxxxxxxx,".to_vec();
            let mut ends = [0usize; 4];
            for (i, lead) in [b'e', b'u'].into_iter().enumerate() {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                ends[2 * i] = b.len();
                b.push(lead);
                let mut y = x >> 8;
                for _ in 0..x % 9 {
                    b.push(dig[(y % 36) as usize]);
                    y /= 36;
                }
                ends[2 * i + 1] = b.len();
                b.push(b',');
            }
            chk(&b, ends[0], ends[1], ends[2], ends[3]);
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
