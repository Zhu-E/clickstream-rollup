// Shopping Sessions: sessionize ~60M messy click-stream rows and write two
// daily Parquet tables. Pipeline:
//   links  -> union-find, one person key per user id
//   parse  -> events into event-id buckets, clicks into person buckets
//   dedup  -> per event-id bucket, keep the earliest ingest; emit person buckets
//   fold   -> per person bucket: sort, sessionize, attribute, aggregate
//   write  -> Parquet
mod pq;
mod sys;
mod tbl;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use sys::*;
use tbl::*;

const WEEK_MS: i64 = 7 * 86_400_000;
const GAP_MS: u32 = 1_800_000;
const LATE_MS: i64 = 86_400_000;
const WEEK: u32 = 604_800_000;

// Shuffle fanout is chosen from the input size so a bucket's dedup table and
// person table stay inside L2 whatever the dataset size.
const ROWS_PER_BUCKET: usize = 24_000;
const BLK_E: usize = 512;
const BLK_P: usize = 512;

// one past the last category index: there are at most 255
const CAT_NONE: u32 = 255;

#[repr(C)]
#[derive(Copy, Clone)]
struct ERec {
    klo: u64,
    khi: u32,
    ing: u32,
    person: u64, // the user id itself when it fits in 63 bits, else a hash
    tsf: u32,    // ts offset from base, bit 31 = valid
    pc: u32,     // (cat << 24) | price, 0 when not a purchase
}

#[repr(C)]
#[derive(Copy, Clone)]
struct PRec {
    person: u64,
    ts: u32,
    pc: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct CRec {
    person: u64,
    sref: u64,
    ts: u32,
    camp: u32,
}

#[inline(always)]
fn sref_of(fi: usize, off: usize, len: usize) -> u64 {
    ((len.min(255) as u64) << 56) | ((fi as u64) << 40) | (off as u64)
}

struct Ctx {
    maps: Vec<Map>,
    ev_lo: i64,
    ev_hi: i64,
    cl_lo: i64,
    cl_hi: i64,
    base: i64, // window_start - 7 days, the zero point for ts offsets
    day0: i64,
    ndays: usize,
    link: Map64,
    lbloom: Bloom,
    names: Map64,
    prod: Vec<u8>, // product number -> cat + 1
    prod_extra: Option<Map64>,
    camp: Vec<u32>, // campaign number -> index + 1
    camp_extra: Option<Map64>,
    ncamp: usize,
    cats: Vec<Vec<u8>>,
    unknown_cat: u32,
    chan: Vec<u32>, // campaign index -> channel index
    chans: Vec<Vec<u8>>,
    eid_bits: u32,
    per_bits: u32,
}
unsafe impl Send for Ctx {}
unsafe impl Sync for Ctx {}

impl Ctx {
    #[inline(always)]
    fn bytes(&self, s: u64) -> &[u8] {
        let len = (s >> 56) as usize;
        let fi = ((s >> 40) & 0xffff) as usize;
        let off = (s & 0xff_ffff_ffff) as usize;
        let m = &self.maps[fi];
        unsafe { std::slice::from_raw_parts(m.ptr.add(off), len) }
    }
}

// ------------------------------------------------------------------ scanning

const SLO: u64 = 0x0101_0101_0101_0101;
const SHI: u64 = 0x8080_8080_8080_8080;
const SL7: u64 = 0x7f7f_7f7f_7f7f_7f7f;

/// High bit set in every byte of `w` that equals `c`. Carry-free, so (unlike
/// the usual `x - 0x01.. & !x & 0x80..`) every set bit is a real match and not
/// a borrow from the byte below it.
#[inline(always)]
fn hits(w: u64, c: u8) -> u64 {
    let x = w ^ SLO.wrapping_mul(c as u64);
    !(((x & SL7).wrapping_add(SL7)) | x) & SHI
}

/// Where a line ends, which of its bytes are commas, and which are quotes.
/// The masks are relative to the start of the line and only cover the first
/// `QLIM` bytes; a longer line sets `long` and is taken apart byte by byte,
/// which keeps the common case to one 128-bit mask per delimiter.
#[derive(Clone, Copy)]
struct Scan {
    nl: usize,
    nc: u32,
    cm: u128,
    qm: u128,
    long: bool,
}

const QLIM: usize = 128;

/// Commas, quotes and newlines in 16 bytes, one bit per byte. One definition
/// per architecture, so a target that has neither still compiles.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn blk(p: *const u8) -> (u16, u16, u16) {
    use core::arch::x86_64::*;
    let v = _mm_loadu_si128(p as *const __m128i);
    let m = |c: u8| -> u16 { _mm_movemask_epi8(_mm_cmpeq_epi8(v, _mm_set1_epi8(c as i8))) as u16 };
    (m(b','), m(b'"'), m(b'\n'))
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn blk(p: *const u8) -> (u16, u16, u16) {
    use core::arch::aarch64::*;
    const BITS: [u8; 16] = [1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128];
    let v = vld1q_u8(p);
    let bits = vld1q_u8(BITS.as_ptr());
    let m = |c: u8| -> u16 {
        let e = vandq_u8(vceqq_u8(v, vdupq_n_u8(c)), bits);
        vaddv_u8(vget_low_u8(e)) as u16 | ((vaddv_u8(vget_high_u8(e)) as u16) << 8)
    };
    (m(b','), m(b'"'), m(b'\n'))
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(always)]
unsafe fn blk(p: *const u8) -> (u16, u16, u16) {
    blk_sw(p)
}

/// The same, without vector instructions: eight bits are gathered out of a
/// SWAR byte match by one multiply.
#[inline(always)]
unsafe fn blk_sw(p: *const u8) -> (u16, u16, u16) {
    let lo = u64::from_le_bytes(*(p as *const [u8; 8]));
    let hi = u64::from_le_bytes(*(p.add(8) as *const [u8; 8]));
    #[inline(always)]
    fn gather(h: u64) -> u16 {
        // h has 0x80 set in matching bytes; fold those into the top byte.
        ((h >> 7).wrapping_mul(0x0102_0408_1020_4080) >> 56) as u16
    }
    let m = |c: u8| -> u16 { gather(hits(lo, c)) | (gather(hits(hi, c)) << 8) };
    (m(b','), m(b'"'), m(b'\n'))
}

/// Find the end of the line at `p` and its delimiter masks.
#[inline(always)]
fn scan_line_g<const SIMD: bool>(d: &[u8], p: usize) -> Scan {
    let n = d.len();
    // Two 64-bit halves rather than a u128: a variable 128-bit shift costs
    // about ten instructions, and this loop runs five times per line.
    let mut c0 = 0u64;
    let mut c1 = 0u64;
    let mut q0 = 0u64;
    let mut q1 = 0u64;
    let mut off = 0usize;
    macro_rules! put {
        ($c:expr, $q:expr) => {{
            let sh = off & 63;
            if off < 64 {
                c0 |= ($c as u64) << sh;
                q0 |= ($q as u64) << sh;
            } else {
                c1 |= ($c as u64) << sh;
                q1 |= ($q as u64) << sh;
            }
        }};
    }
    macro_rules! done {
        ($nl:expr, $long:expr) => {{
            let cm = (c0 as u128) | ((c1 as u128) << 64);
            let qm = (q0 as u128) | ((q1 as u128) << 64);
            return Scan {
                nl: $nl,
                nc: (c0.count_ones() + c1.count_ones()),
                cm,
                qm,
                long: $long,
            };
        }};
    }
    while off + 16 <= QLIM && p + off + 16 <= n {
        let (c, q, nm) = unsafe {
            let at = d.as_ptr().add(p + off);
            if SIMD {
                blk(at)
            } else {
                blk_sw(at)
            }
        };
        if nm != 0 {
            let stop = nm.trailing_zeros() as usize;
            let keep = (((1u32 << stop) - 1) & 0xffff) as u16;
            put!(c & keep, q & keep);
            done!(p + off + stop, false);
        }
        put!(c, q);
        off += 16;
    }
    // A short tail at the end of the file, or the start of an over-long line.
    let mut i = p + off;
    while i < n && i - p < QLIM {
        let b = unsafe { *d.get_unchecked(i) };
        if b == b'\n' {
            done!(i, false);
        }
        off = i - p;
        if b == b',' {
            put!(1u16, 0u16);
        } else if b == b'"' {
            put!(0u16, 1u16);
        }
        i += 1;
    }
    if i >= n {
        done!(n, false);
    }
    while i < n && unsafe { *d.get_unchecked(i) } != b'\n' {
        i += 1;
    }
    Scan { nl: i, nc: 0, cm: 0, qm: 0, long: true }
}

#[inline(always)]
fn scan_line(d: &[u8], p: usize, simd: bool) -> Scan {
    if simd {
        scan_line_g::<true>(d, p)
    } else {
        scan_line_g::<false>(d, p)
    }
}

fn unq(s: usize, e: usize, qm: u128) -> Option<(u32, u32)> {
    let w = e - s;
    let fm = (qm >> s) & ((1u128 << w) - 1);
    if fm == 0 {
        Some((s as u32, e as u32))
    } else if w >= 2 && fm == (1u128 | (1u128 << (w - 1))) {
        Some((s as u32 + 1, e as u32 - 1))
    } else {
        None
    }
}

fn unq_slow(line: &[u8], s: usize, e: usize) -> Option<(u32, u32)> {
    let f = &line[s..e];
    let q = f.iter().filter(|&&c| c == b'"').count();
    if q == 0 {
        Some((s as u32, e as u32))
    } else if q == 2 && f.len() >= 2 && f[0] == b'"' && f[f.len() - 1] == b'"' {
        Some((s as u32 + 1, e as u32 - 1))
    } else {
        None
    }
}

/// Field spans, with the quotes taken off. A field count that is not exactly
/// `N` makes the line malformed, as does a quote anywhere but around a whole
/// field.
#[inline(always)]
fn fields<const N: usize>(line: &[u8], sc: &Scan) -> Option<[(u32, u32); N]> {
    if sc.long {
        return fields_slow::<N>(line);
    }
    if sc.nc as usize != N - 1 {
        return None;
    }
    let mut out = [(0u32, 0u32); N];
    let mut m = sc.cm;
    let mut s = 0usize;
    for k in 0..N {
        let e = if k + 1 == N {
            line.len()
        } else {
            let b = m.trailing_zeros() as usize;
            m &= m - 1;
            b
        };
        out[k] = unq(s, e, sc.qm)?;
        s = e + 1;
    }
    Some(out)
}

/// Lines longer than `QLIM`: rare enough to walk byte by byte.
#[cold]
fn fields_slow<const N: usize>(line: &[u8]) -> Option<[(u32, u32); N]> {
    let mut pos = [0usize; N];
    let mut nc = 0usize;
    for (i, &b) in line.iter().enumerate() {
        if b == b',' {
            if nc < N - 1 {
                pos[nc] = i;
            }
            nc += 1;
            if nc >= N {
                return None;
            }
        }
    }
    if nc != N - 1 {
        return None;
    }
    let mut out = [(0u32, 0u32); N];
    let mut s = 0usize;
    for k in 0..N {
        let e = if k + 1 == N { line.len() } else { pos[k] };
        out[k] = unq_slow(line, s, e)?;
        s = e + 1;
    }
    Some(out)
}

#[inline(always)]
fn digits_u32(b: &[u8]) -> Option<u32> {
    if b.is_empty() || b.len() > 9 {
        return None;
    }
    let mut v = 0u32;
    for &c in b {
        let d = c.wrapping_sub(b'0');
        if d > 9 {
            return None;
        }
        v = v * 10 + d as u32;
    }
    Some(v)
}

/// A canonical decimal id suffix: digits with no leading zero (except "0").
#[inline(always)]
fn canon_num(b: &[u8]) -> Option<u32> {
    if b.len() > 1 && b[0] == b'0' {
        return None;
    }
    digits_u32(b)
}

impl Ctx {
    #[inline(always)]
    fn cat_of(&self, pid: &[u8]) -> u32 {
        if pid.len() >= 2 && pid[0] == b'p' {
            if let Some(v) = canon_num(&pid[1..]) {
                if (v as usize) < self.prod.len() {
                    let x = unsafe { *self.prod.get_unchecked(v as usize) };
                    if x != 0 {
                        return (x - 1) as u32;
                    }
                }
            }
        }
        if let Some(m) = &self.prod_extra {
            if let Some(c) = m.get(hash(pid)) {
                return c as u32;
            }
        }
        self.unknown_cat
    }
    #[inline(always)]
    fn camp_of(&self, cid: &[u8]) -> Option<u32> {
        if cid.len() >= 3 && cid[0] == b'c' && cid[1] == b'_' {
            if let Some(v) = canon_num(&cid[2..]) {
                if (v as usize) < self.camp.len() {
                    let x = unsafe { *self.camp.get_unchecked(v as usize) };
                    if x != 0 {
                        return Some(x - 1);
                    }
                }
            }
        }
        if let Some(m) = &self.camp_extra {
            if let Some(c) = m.get(hash(cid)) {
                return Some(c as u32);
            }
        }
        None
    }
    #[inline(always)]
    fn person_of(&self, user: &[u8], hits: &mut usize) -> u64 {
        let k = person_key(user);
        if !self.lbloom.maybe(k) {
            return k;
        }
        match self.link.get(k) {
            Some(r) => {
                *hits += 1;
                r
            }
            None => k,
        }
    }
}

// ------------------------------------------------------------------- parsing

#[inline(always)]
fn first_line_start(d: &[u8], start: usize) -> usize {
    if start == 0 {
        // skip the header
        let mut i = 0;
        while i < d.len() && d[i] != b'\n' {
            i += 1;
        }
        return (i + 1).min(d.len());
    }
    let mut i = start;
    if d[i - 1] == b'\n' {
        return i;
    }
    while i < d.len() && d[i] != b'\n' {
        i += 1;
    }
    (i + 1).min(d.len())
}

/// Cleared when the vector scanner disagrees with the scalar one, which
/// should never happen; see `check_simd`.
static SIMD_OK: AtomicBool = AtomicBool::new(true);

static LKH: AtomicUsize = AtomicUsize::new(0);
static NROW: AtomicUsize = AtomicUsize::new(0);
static NVAL: AtomicUsize = AtomicUsize::new(0);
static NS_EV: AtomicUsize = AtomicUsize::new(0);
static NS_CL: AtomicUsize = AtomicUsize::new(0);
static ACC: AtomicUsize = AtomicUsize::new(0);

/// `ABL` is a diagnostic: 0 is the real thing, higher levels stop early so the
/// cost of each parse step can be measured. It is a const, so only the level-0
/// code survives in the shipping call.
fn parse_events<const ABL: u32>(
    ctx: &Ctx,
    fi: usize,
    from: usize,
    to: usize,
    sink: &mut Sink<ERec>,
    dc: &mut DateCache,
    xn: &mut Vec<(u64, u64)>,
) {
    let simd = SIMD_OK.load(Ordering::Relaxed);
    let d = ctx.maps[fi].as_slice();
    let mut p = first_line_start(d, from);
    let mut acc = 0usize;
    let mut lkh = 0usize;
    let mut nrow = 0usize;
    let mut nval = 0usize;
    while p < to {
        let sc = scan_line(d, p, simd);
        let line = &d[p..sc.nl];
        let lp = p;
        p = sc.nl + 1;
        nrow += 1;
        if ABL == 1 {
            acc += sc.nc as usize ^ sc.nl ^ (sc.qm as usize);
            continue;
        }
        let f = match fields::<7>(line, &sc) {
            Some(f) => f,
            None => continue,
        };
        if ABL == 2 {
            acc += f[3].0 as usize ^ f[6].1 as usize;
            continue;
        }
        let eid = &line[f[0].0 as usize..f[0].1 as usize];
        if eid.is_empty() {
            continue;
        }
        let (klo, khi) = key96(eid);
        if ABL == 3 {
            acc += klo as usize ^ khi as usize;
            continue;
        }
        let ing_ms = parse_ts_c(&line[f[3].0 as usize..f[3].1 as usize], dc).unwrap_or(0);
        let ing = if ing_ms <= 0 { 0u32 } else { (ing_ms / 1000).min(u32::MAX as i64) as u32 };

        // Resolving a user to a person ends in a line of a link map far too
        // big to cache. The probe is started here and read after validation,
        // so the event timestamp covers the miss instead of waiting on it.
        let user = &line[f[1].0 as usize..f[1].1 as usize];
        let has_user = !user.is_empty();
        let mut pk = 0u64;
        let mut linked = false;
        if has_user && (ABL == 0 || ABL >= 6) {
            pk = person_key(user);
            linked = ctx.lbloom.maybe(pk);
            if linked {
                ctx.link.prefetch(pk);
            }
        }

        let mut tsf = 0u32;
        let mut pc = 0u32;
        let mut person = 0u64;
        loop {
            if !has_user {
                break;
            }
            let ts = match parse_ts_c(&line[f[2].0 as usize..f[2].1 as usize], dc) {
                Some(t) => t,
                None => break,
            };
            if ts < ctx.ev_lo || ts >= ctx.ev_hi {
                break;
            }
            if ABL == 4 {
                acc += ts as usize;
                break;
            }
            if ing_ms.saturating_sub(ts) > LATE_MS {
                break;
            }
            let ety = &line[f[4].0 as usize..f[4].1 as usize];
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
            let pid = &line[f[5].0 as usize..f[5].1 as usize];
            if pid.is_empty() {
                break;
            }
            if is_pur {
                let price = match digits_u32(&line[f[6].0 as usize..f[6].1 as usize]) {
                    Some(v) if v >= 1 && v <= 10_000_000 => v,
                    _ => break,
                };
                pc = (ctx.cat_of(pid) << 24) | price;
            }
            if ABL == 5 {
                acc += pid.len() ^ pc as usize;
                break;
            }
            person = if linked {
                match ctx.link.get(pk) {
                    Some(r) => {
                        lkh += 1;
                        r
                    }
                    None => pk,
                }
            } else {
                pk
            };
            if person & PTAG != 0 && ctx.names.get(person).is_none() {
                // An id too long or too odd to encode, and in no link: keep
                // track of where its bytes are so the name can be written out.
                xn.push((person, sref_of(fi, lp + f[1].0 as usize, (f[1].1 - f[1].0) as usize)));
            }
            tsf = (ts - ctx.base) as u32 | 0x8000_0000;
            nval += 1;
            break;
        }
        let b = (mix(klo ^ (khi as u64), 0x9e37_79b9_7f4a_7c15) >> (64 - ctx.eid_bits)) as usize;
        if ABL == 6 {
            acc += b ^ tsf as usize ^ pc as usize ^ person as usize ^ ing as usize;
            continue;
        }
        sink.push(b, ERec { klo, khi, ing, person, tsf, pc });
    }
    if ABL != 0 {
        ACC.fetch_add(acc, Ordering::Relaxed);
    }
    LKH.fetch_add(lkh, Ordering::Relaxed);
    NROW.fetch_add(nrow, Ordering::Relaxed);
    NVAL.fetch_add(nval, Ordering::Relaxed);
}

fn parse_clicks(ctx: &Ctx, fi: usize, from: usize, to: usize, sink: &mut Sink<CRec>, dc: &mut DateCache) {
    let simd = SIMD_OK.load(Ordering::Relaxed);
    let d = ctx.maps[fi].as_slice();
    let mut p = first_line_start(d, from);
    let mut lkh = 0usize;
    while p < to {
        let sc = scan_line(d, p, simd);
        let line = &d[p..sc.nl];
        let lp = p;
        p = sc.nl + 1;
        let f = match fields::<4>(line, &sc) {
            Some(f) => f,
            None => continue,
        };
        if f[0].0 == f[0].1 {
            continue; // empty click_id
        }
        let user = &line[f[1].0 as usize..f[1].1 as usize];
        if user.is_empty() {
            continue;
        }
        let ts = match parse_ts_c(&line[f[3].0 as usize..f[3].1 as usize], dc) {
            Some(t) => t,
            None => continue,
        };
        if ts < ctx.cl_lo || ts >= ctx.cl_hi {
            continue;
        }
        let camp = match ctx.camp_of(&line[f[2].0 as usize..f[2].1 as usize]) {
            Some(c) => c,
            None => continue,
        };
        let person = ctx.person_of(user, &mut lkh);
        let sref = sref_of(fi, lp + f[0].0 as usize, (f[0].1 - f[0].0) as usize);
        let b = (mix(person, 0xff51_afd7_ed55_8ccd) >> (64 - ctx.per_bits)) as usize;
        sink.push(b, CRec { person, sref, ts: (ts - ctx.base) as u32, camp });
    }
    LKH.fetch_add(lkh, Ordering::Relaxed);
}

#[inline(always)]
fn person_bucket(person: u64, bits: u32) -> usize {
    (mix(person, 0xff51_afd7_ed55_8ccd) >> (64 - bits)) as usize
}

// --------------------------------------------------------------- dedup stage

#[repr(C)]
#[derive(Copy, Clone)]
struct DEnt {
    klo: u64,
    khi: u32,
    ing: u32,
    ptr: *const ERec,
}

fn dedup_bucket(blocks: &[Blk<ERec>], tbl: &mut Vec<DEnt>, sink: &mut Sink<PRec>, per_bits: u32) {
    let n: usize = blocks.iter().map(|b| b.len as usize).sum();
    if n == 0 {
        return;
    }
    let cap = (n * 2).next_power_of_two().max(32);
    tbl.clear();
    tbl.resize(cap, DEnt { klo: 0, khi: 0, ing: 0, ptr: std::ptr::null() });
    let mask = cap - 1;
    for blk in blocks {
        for r in blk.as_slice() {
            let mut i = (mix(r.klo ^ ((r.khi as u64) << 32), 0xd6e8_feb8_6659_fd93) as usize) & mask;
            loop {
                let e = unsafe { tbl.get_unchecked_mut(i) };
                if e.khi == 0 {
                    *e = DEnt { klo: r.klo, khi: r.khi, ing: r.ing, ptr: r as *const ERec };
                    break;
                }
                if e.khi == r.khi && e.klo == r.klo {
                    if r.ing < e.ing {
                        e.ing = r.ing;
                        e.ptr = r as *const ERec;
                    }
                    break;
                }
                i = (i + 1) & mask;
            }
        }
    }
    for e in tbl.iter() {
        if e.khi != 0 {
            let r = unsafe { &*e.ptr };
            if r.tsf & 0x8000_0000 != 0 {
                sink.push(
                    person_bucket(r.person, per_bits),
                    PRec { person: r.person, ts: r.tsf & 0x7fff_ffff, pc: r.pc },
                );
            }
        }
    }
}

// ---------------------------------------------------------------- fold stage

#[derive(Copy, Clone, Default)]
struct CD {
    sessions: u32,
    purch: u32,
    assist: u32,
    rev: u64,
}

struct Out {
    cd: Vec<CD>,
    uid: Vec<u8>,
    day: Vec<i32>,
    sessions: Vec<i64>,
    events: Vec<i64>,
    rev: Vec<i64>,
    tcval: Vec<u8>,
    tcdef: Vec<u8>,
    tcn: i64,
}

struct Tmp {
    ss: Vec<u32>,
    sd: Vec<u8>,
    sr: Vec<u64>,
    sp: Vec<bool>,
    cum: Vec<u32>,
    cnt: Vec<u32>,
    iv: Vec<(u32, u32)>,
    mark: Vec<u32>,
    tc: Vec<u32>,
    gen: u32,
    catrev: Vec<u64>,
    touch: Vec<u32>,
}

#[inline]
fn lower_bound(v: &[u32], x: u32) -> usize {
    let mut lo = 0usize;
    let mut hi = v.len();
    while lo < hi {
        let m = (lo + hi) / 2;
        if v[m] < x {
            lo = m + 1;
        } else {
            hi = m;
        }
    }
    lo
}

#[inline]
fn upper_bound(v: &[u32], x: u32) -> usize {
    let mut lo = 0usize;
    let mut hi = v.len();
    while lo < hi {
        let m = (lo + hi) / 2;
        if v[m] <= x {
            lo = m + 1;
        } else {
            hi = m;
        }
    }
    lo
}

#[inline]
fn flush_assist(
    ss: &[u32],
    sd: &[u8],
    cum: &[u32],
    cd: &mut [CD],
    stride: usize,
    c: usize,
    a: u32,
    b: u32,
) {
    let (lo, hi) = if ss.len() <= 24 {
        let mut lo = 0usize;
        while lo < ss.len() && ss[lo] < a {
            lo += 1;
        }
        let mut hi = lo;
        while hi < ss.len() && ss[hi] <= b {
            hi += 1;
        }
        (lo, hi)
    } else {
        (lower_bound(ss, a), upper_bound(ss, b))
    };
    if hi <= lo {
        return;
    }
    if hi - lo <= 16 {
        for i in lo..hi {
            cd[c * stride + sd[i] as usize].assist += 1;
        }
    } else {
        let d0 = sd[lo] as usize;
        let d1 = sd[hi - 1] as usize;
        for d in d0..=d1 {
            let s = (cum[d] as usize).max(lo);
            let e = (cum[d + 1] as usize).min(hi);
            if e > s {
                cd[c * stride + d].assist += (e - s) as u32;
            }
        }
    }
}

fn emit_user(ctx: &Ctx, o: &mut Out, t: &mut Tmp, name: &[u8], day: u32, ns: u64, ne: u64, rev: u64, ntouch: usize) {
    let mut best = CAT_NONE;
    let mut bestv = 0u64;
    for x in 0..ntouch {
        let c = t.touch[x] as usize;
        let v = t.catrev[c];
        if v > bestv || (v == bestv && (c as u32) < best) {
            bestv = v;
            best = c as u32;
        }
        t.catrev[c] = 0;
    }
    pq::push_str(&mut o.uid, name);
    o.day.push((ctx.day0 + day as i64) as i32);
    o.sessions.push(ns as i64);
    o.events.push(ne as i64);
    o.rev.push(rev as i64);
    if best == CAT_NONE {
        o.tcdef.push(0);
    } else {
        o.tcdef.push(1);
        o.tcn += 1;
        pq::push_str(&mut o.tcval, &ctx.cats[best as usize]);
    }
}

fn process_person(ctx: &Ctx, ev: &[PRec], cl: &[CRec], t: &mut Tmp, o: &mut Out, name: &[u8]) {
    let stride = ctx.ndays + 2;
    t.ss.clear();
    t.sd.clear();
    t.sr.clear();
    t.sp.clear();
    let n = ev.len();
    let mut i = 0usize;
    let mut cur_day = u32::MAX;
    let mut dsess = 0u64;
    let mut dev = 0u64;
    let mut drev = 0u64;
    let mut ntouch = 0usize;
    while i < n {
        let start = ev[i].ts;
        let mut j = i + 1;
        while j < n && ev[j].ts - ev[j - 1].ts <= GAP_MS {
            j += 1;
        }
        let day = (((ctx.base + start as i64) / DAY_MS) - ctx.day0) as u32;
        if day != cur_day {
            if cur_day != u32::MAX {
                emit_user(ctx, o, t, name, cur_day, dsess, dev, drev, ntouch);
            }
            cur_day = day;
            dsess = 0;
            dev = 0;
            drev = 0;
            ntouch = 0;
        }
        let mut srev = 0u64;
        let mut pur = false;
        for k in i..j {
            let pc = ev[k].pc;
            if pc != 0 {
                let price = (pc & 0x00ff_ffff) as u64;
                let c = (pc >> 24) as usize;
                if t.catrev[c] == 0 {
                    t.touch[ntouch] = c as u32;
                    ntouch += 1;
                }
                t.catrev[c] += price;
                srev += price;
                pur = true;
            }
        }
        dsess += 1;
        dev += (j - i) as u64;
        drev += srev;
        t.ss.push(start);
        t.sd.push(day as u8);
        t.sr.push(srev);
        t.sp.push(pur);
        i = j;
    }
    if cur_day != u32::MAX {
        emit_user(ctx, o, t, name, cur_day, dsess, dev, drev, ntouch);
    }

    // sessions per day, as a prefix sum over the day index
    for d in 0..stride + 1 {
        t.cnt[d] = 0;
    }
    for &d in t.sd.iter() {
        t.cnt[d as usize] += 1;
    }
    let mut acc = 0u32;
    for d in 0..stride + 1 {
        t.cum[d] = acc;
        acc += t.cnt[d];
    }

    // credit: the latest click at or before the session start, within 7 days
    let m = cl.len();
    let organic = ctx.ncamp as u32;
    let mut hi = 0usize;
    let mut last_hi = usize::MAX;
    let mut last_g = 0usize;
    let mut last_t = 0u32;
    for si in 0..t.ss.len() {
        let start = t.ss[si];
        while hi < m && cl[hi].ts <= start {
            hi += 1;
        }
        // The newest click at or before the start; ties go to the smallest
        // click_id, which sorts first inside its timestamp group.
        let camp = if hi == 0 {
            organic
        } else {
            if hi != last_hi {
                last_hi = hi;
                last_t = cl[hi - 1].ts;
                let mut g = hi - 1;
                while g > 0 && cl[g - 1].ts == last_t {
                    g -= 1;
                }
                if hi - g > 1 {
                    // Several clicks share this millisecond: smallest id wins.
                    let mut best = g;
                    for k in g + 1..hi {
                        if ctx.bytes(cl[k].sref) < ctx.bytes(cl[best].sref) {
                            best = k;
                        }
                    }
                    g = best;
                }
                last_g = g;
            }
            if start - last_t <= WEEK {
                cl[last_g].camp
            } else {
                organic
            }
        };
        let e = &mut o.cd[camp as usize * stride + t.sd[si] as usize];
        e.sessions += 1;
        if t.sp[si] {
            e.purch += 1;
        }
        e.rev += t.sr[si];
    }

    // assists: merge each campaign's [click, click + 7 days] windows
    if m > 0 && !t.ss.is_empty() {
        t.gen += 1;
        let g0 = t.gen;
        let mut ntc = 0usize;
        for k in 0..m {
            let c = cl[k].camp as usize;
            let tt = cl[k].ts;
            if t.mark[c] != g0 {
                t.mark[c] = g0;
                t.iv[c] = (tt, tt.saturating_add(WEEK));
                if ntc < t.tc.len() {
                    t.tc[ntc] = c as u32;
                    ntc += 1;
                }
            } else {
                let (s, e) = t.iv[c];
                if tt <= e {
                    t.iv[c] = (s, tt.saturating_add(WEEK));
                } else {
                    flush_assist(&t.ss, &t.sd, &t.cum, &mut o.cd, stride, c, s, e);
                    t.iv[c] = (tt, tt.saturating_add(WEEK));
                }
            }
        }
        for x in 0..ntc {
            let c = t.tc[x] as usize;
            let (s, e) = t.iv[c];
            flush_assist(&t.ss, &t.sd, &t.cum, &mut o.cd, stride, c, s, e);
        }
    }
}

struct Fold {
    ev: Vec<PRec>,
    cl: Vec<CRec>,
    dense: Vec<u32>,
    cdense: Vec<u32>,
    persons: Vec<u64>,
    pslot: Vec<u32>,
    ecnt: Vec<u32>,
    ccnt: Vec<u32>,
    epos: Vec<u32>,
    cpos: Vec<u32>,
    cur: Vec<u32>,
    tbl: Vec<(u64, u32)>,
    t: Tmp,
    o: Out,
}

const NOPER: u32 = u32::MAX;

#[inline(always)]
fn tprobe(tbl: &[(u64, u32)], mask: usize, k: u64) -> usize {
    let mut i = (k as usize) & mask;
    loop {
        let s = unsafe { tbl.get_unchecked(i) };
        if s.0 == k || s.0 == 0 {
            return i;
        }
        i = (i + 1) & mask;
    }
}

#[inline]
fn sort_small_p(v: &mut [PRec]) {
    for i in 1..v.len() {
        let x = v[i];
        let mut j = i;
        while j > 0 && v[j - 1].ts > x.ts {
            v[j] = v[j - 1];
            j -= 1;
        }
        v[j] = x;
    }
}

#[inline]
fn sort_small_c(v: &mut [CRec]) {
    for i in 1..v.len() {
        let x = v[i];
        let mut j = i;
        while j > 0 && v[j - 1].ts > x.ts {
            v[j] = v[j - 1];
            j -= 1;
        }
        v[j] = x;
    }
}

/// One person bucket: group by person with a counting sort, order each
/// person's rows by timestamp, then sessionize and attribute.
fn fold_bucket(ctx: &Ctx, xn: &Map64, f: &mut Fold, evb: &[Blk<PRec>], clb: &[Blk<CRec>]) {
    let n: usize = evb.iter().map(|b| b.len as usize).sum();
    if n == 0 {
        return;
    }
    let Fold { ev, cl, dense, cdense, persons, pslot, ecnt, ccnt, epos, cpos, cur, tbl, t, o } = f;

    // ---- pass 1: intern person keys, count rows per person
    let mut want = (n / 2 + 8).next_power_of_two().max(64);
    if tbl.len() < want {
        tbl.resize(want, (0, 0));
    }
    let mut mask = want - 1;
    persons.clear();
    pslot.clear();
    ecnt.clear();
    dense.clear();
    dense.reserve(n);
    for blk in evb {
        for r in blk.as_slice() {
            let i = tprobe(tbl, mask, r.person);
            let d = if unsafe { tbl.get_unchecked(i) }.0 == 0 {
                let d = persons.len() as u32;
                tbl[i] = (r.person, d);
                persons.push(r.person);
                pslot.push(i as u32);
                ecnt.push(0);
                // keep the load factor under ~0.6
                if persons.len() * 5 > want * 3 {
                    let nw = want * 2;
                    if tbl.len() < nw {
                        tbl.resize(nw, (0, 0));
                    }
                    for s in tbl[..nw].iter_mut() {
                        *s = (0, 0);
                    }
                    want = nw;
                    mask = nw - 1;
                    pslot.clear();
                    for (k, &key) in persons.iter().enumerate() {
                        let j = tprobe(tbl, mask, key);
                        tbl[j] = (key, k as u32);
                        pslot.push(j as u32);
                    }
                }
                d
            } else {
                unsafe { tbl.get_unchecked(i) }.1
            };
            ecnt[d as usize] += 1;
            dense.push(d);
        }
    }
    let np = persons.len();

    // ---- clicks: look up the person, drop the ones with no events
    let nc: usize = clb.iter().map(|b| b.len as usize).sum();
    ccnt.clear();
    ccnt.resize(np, 0);
    cdense.clear();
    cdense.reserve(nc);
    let mut nck = 0usize;
    for blk in clb {
        for r in blk.as_slice() {
            let i = tprobe(tbl, mask, r.person);
            let s = unsafe { tbl.get_unchecked(i) };
            if s.0 == 0 {
                cdense.push(NOPER);
            } else {
                cdense.push(s.1);
                ccnt[s.1 as usize] += 1;
                nck += 1;
            }
        }
    }

    // ---- prefix sums
    epos.clear();
    epos.resize(np + 1, 0);
    cpos.clear();
    cpos.resize(np + 1, 0);
    let mut a = 0u32;
    for d in 0..np {
        epos[d] = a;
        a += ecnt[d];
    }
    epos[np] = a;
    let mut a = 0u32;
    for d in 0..np {
        cpos[d] = a;
        a += ccnt[d];
    }
    cpos[np] = a;

    // ---- pass 2: scatter into per-person runs
    // Write straight into reserved capacity: resize() would zero-fill the
    // whole buffer every bucket, and every slot is overwritten below.
    ev.clear();
    ev.reserve(n);
    cl.clear();
    cl.reserve(nck);
    let evp = ev.as_mut_ptr();
    let clp = cl.as_mut_ptr();
    cur.clear();
    cur.extend_from_slice(&epos[..np]);
    let mut k = 0usize;
    for blk in evb {
        for r in blk.as_slice() {
            let d = unsafe { *dense.get_unchecked(k) } as usize;
            k += 1;
            let at = unsafe { *cur.get_unchecked(d) } as usize;
            unsafe {
                *cur.get_unchecked_mut(d) = at as u32 + 1;
                evp.add(at).write(*r);
            }
        }
    }
    cur.clear();
    cur.extend_from_slice(&cpos[..np]);
    let mut k = 0usize;
    for blk in clb {
        for r in blk.as_slice() {
            let d = unsafe { *cdense.get_unchecked(k) };
            k += 1;
            if d == NOPER {
                continue;
            }
            let d = d as usize;
            let at = unsafe { *cur.get_unchecked(d) } as usize;
            unsafe {
                *cur.get_unchecked_mut(d) = at as u32 + 1;
                clp.add(at).write(*r);
            }
        }
    }
    unsafe {
        ev.set_len(n);
        cl.set_len(nck);
    }

    // ---- per person: order by timestamp, then fold
    for d in 0..np {
        let (es, ee) = (epos[d] as usize, epos[d + 1] as usize);
        if es == ee {
            continue;
        }
        let evs = &mut ev[es..ee];
        if evs.len() <= 24 {
            sort_small_p(evs);
        } else {
            evs.sort_unstable_by_key(|r| r.ts);
        }
        let (cs, ce) = (cpos[d] as usize, cpos[d + 1] as usize);
        if ce > cs {
            let cls = &mut cl[cs..ce];
            if cls.len() <= 24 {
                sort_small_c(cls);
            } else {
                cls.sort_unstable_by_key(|r| r.ts);
            }
        }
        let pkey = persons[d];
        let mut nbuf = [0u8; MAXENC];
        let name: &[u8] = if pkey & PTAG == 0 {
            let n = dec_name(pkey, &mut nbuf);
            &nbuf[..n]
        } else {
            // Hashed key: the bytes are in the link names or the side table.
            match ctx.names.get(pkey).or_else(|| xn.get(pkey)) {
                Some(x) => ctx.bytes(x),
                None => b"",
            }
        };
        process_person(ctx, &ev[es..ee], &cl[cs..ce], t, o, name);
    }

    // ---- leave the table empty for the next bucket. Clear the recorded
    // slots directly: probing again would stop at a slot already zeroed and
    // leave live entries behind.
    for &i in pslot.iter() {
        tbl[i as usize] = (0, 0);
    }
}

/// Bucket indices, fattest first.
fn order_by_size<T: Copy>(b: &[Vec<Blk<T>>]) -> Vec<usize> {
    let mut v: Vec<usize> = (0..b.len()).collect();
    let sz: Vec<u64> = b
        .iter()
        .map(|l| l.iter().map(|x| x.len as u64).sum())
        .collect();
    v.sort_unstable_by(|&x, &y| sz[y].cmp(&sz[x]));
    v
}

// ------------------------------------------------------------ input metadata

fn list_csv(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension().map(|x| x == "csv").unwrap_or(false)
                    && !p
                        .file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with('.'))
                        .unwrap_or(true)
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    v.sort();
    v
}

fn json_ts(s: &[u8], key: &str) -> i64 {
    let k = key.as_bytes();
    let mut i = 0;
    while i + k.len() <= s.len() {
        if &s[i..i + k.len()] == k {
            let mut j = i + k.len();
            while j < s.len() && s[j] != b':' {
                j += 1;
            }
            while j < s.len() && s[j] != b'"' {
                j += 1;
            }
            j += 1;
            let mut e = j;
            while e < s.len() && s[e] != b'"' {
                e += 1;
            }
            return parse_ts(&s[j..e]).expect("bad manifest timestamp");
        }
        i += 1;
    }
    panic!("manifest key {} missing", key);
}

/// Iterate the data lines of a small CSV, applying the dialect rules.
fn each_line<const N: usize, F: FnMut(&[u8], [(u32, u32); N])>(d: &[u8], mut f: F) {
    let simd = SIMD_OK.load(Ordering::Relaxed);
    let mut p = first_line_start(d, 0);
    while p < d.len() {
        let sc = scan_line(d, p, simd);
        let line = &d[p..sc.nl];
        p = sc.nl + 1;
        if let Some(fs) = fields::<N>(line, &sc) {
            f(line, fs);
        }
    }
}

// ----------------------------------------------------------------- main

struct Links {
    link: Map64,
    lbloom: Bloom,
    names: Map64,
}

fn build_links(maps: &[Map], range: std::ops::Range<usize>, nt: usize) -> Links {
    let mut parts: Vec<Vec<(u64, u64, u64, u64)>> = Vec::new();
    let next = AtomicUsize::new(0);
    let chunks: Vec<(usize, usize, usize)> = {
        let mut v = Vec::new();
        const C: usize = 1 << 20;
        for fi in range.clone() {
            let n = maps[fi].len;
            let mut a = 0;
            while a < n {
                v.push((fi, a, (a + C).min(n)));
                a += C;
            }
        }
        v
    };
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..nt)
            .map(|_| {
                let next = &next;
                let chunks = &chunks;
                s.spawn(move || {
                    let mut out: Vec<(u64, u64, u64, u64)> = Vec::new();
                    let simd = SIMD_OK.load(Ordering::Relaxed);
                    loop {
                        let k = next.fetch_add(1, Ordering::Relaxed);
                        if k >= chunks.len() {
                            break;
                        }
                        let (fi, a, b) = chunks[k];
                        let d = maps[fi].as_slice();
                        let mut p = first_line_start(d, a);
                        while p < b {
                            let sc = scan_line(d, p, simd);
                            let line = &d[p..sc.nl];
                            let lp = p;
                            p = sc.nl + 1;
                            if let Some(f) = fields::<2>(line, &sc) {
                                if f[0].0 == f[0].1 || f[1].0 == f[1].1 {
                                    continue;
                                }
                                let a1 = &line[f[0].0 as usize..f[0].1 as usize];
                                let b1 = &line[f[1].0 as usize..f[1].1 as usize];
                                out.push((
                                    person_key(a1),
                                    sref_of(fi, lp + f[0].0 as usize, a1.len()),
                                    person_key(b1),
                                    sref_of(fi, lp + f[1].0 as usize, b1.len()),
                                ));
                            }
                        }
                    }
                    out
                })
            })
            .collect();
        for h in hs {
            parts.push(h.join().unwrap());
        }
    });

    let t_rows = std::time::Instant::now();
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut keys: Vec<u64> = Vec::with_capacity(total * 2 / 3 + 16);
    let mut srefs: Vec<u64> = Vec::with_capacity(total * 2 / 3 + 16);
    let mut parent: Vec<u32> = Vec::with_capacity(total * 2 / 3 + 16);
    let mut rank: Vec<u8> = Vec::with_capacity(total * 2 / 3 + 16);
    // Grows as needed: the number of distinct ids is not known yet.
    let mut idx = Map64::with_capacity(total + 16);

    #[inline]
    fn find(parent: &mut [u32], mut x: u32) -> u32 {
        while parent[x as usize] != x {
            let p = parent[x as usize];
            parent[x as usize] = parent[p as usize];
            x = parent[x as usize];
        }
        x
    }

    let mut intern = |h: u64, s: u64, keys: &mut Vec<u64>, srefs: &mut Vec<u64>, parent: &mut Vec<u32>, rank: &mut Vec<u8>| -> u32 {
        let want = keys.len() as u64;
        let got = idx.get_or_insert(h, want);
        if got == want {
            keys.push(h);
            srefs.push(s);
            parent.push(want as u32);
            rank.push(0);
        }
        got as u32
    };

    for p in &parts {
        for &(ha, sa, hb, sb) in p {
            let a = intern(ha, sa, &mut keys, &mut srefs, &mut parent, &mut rank);
            let b = intern(hb, sb, &mut keys, &mut srefs, &mut parent, &mut rank);
            let mut ra = find(&mut parent, a);
            let mut rb = find(&mut parent, b);
            if ra == rb {
                continue;
            }
            if rank[ra as usize] < rank[rb as usize] {
                std::mem::swap(&mut ra, &mut rb);
            }
            parent[rb as usize] = ra;
            if rank[ra as usize] == rank[rb as usize] {
                rank[ra as usize] += 1;
            }
        }
    }
    drop(parts);
    let t_uf = t_rows.elapsed();

    let n = keys.len();
    let mut minnode: Vec<u32> = (0..n as u32).collect();
    let getb = |s: u64| -> &[u8] {
        let len = (s >> 56) as usize;
        let fi = ((s >> 40) & 0xffff) as usize;
        let off = (s & 0xff_ffff_ffff) as usize;
        unsafe { std::slice::from_raw_parts(maps[fi].ptr.add(off), len) }
    };
    for i in 0..n {
        let r = find(&mut parent, i as u32) as usize;
        let cur = minnode[r] as usize;
        if cur == i {
            continue;
        }
        // Encoded keys compare like their bytes do, so the common case needs
        // no reads back into the mapped files.
        let smaller = if (keys[i] | keys[cur]) & PTAG == 0 {
            keys[i] < keys[cur]
        } else {
            getb(srefs[i]) < getb(srefs[cur])
        };
        if smaller {
            minnode[r] = i as u32;
        }
    }
    let t_mn = t_rows.elapsed();
    let mut lbloom = Bloom::new(n + 16);
    let mut link = Map64::with_capacity(n + 16);
    let mut names = Map64::with_capacity(n / 2 + 16);
    for i in 0..n {
        let r = find(&mut parent, i as u32) as usize;
        let mn = minnode[r] as usize;
        if mn != i {
            lbloom.insert(keys[i]);
            link.insert(keys[i], keys[mn]);
        } else if keys[mn] & PTAG != 0 {
            // Only ids that do not fit the encoding need their bytes kept.
            names.insert(keys[mn], srefs[mn]);
        }
    }
    if std::env::var("SS_TIMING").is_ok() {
        eprintln!(
            "  links: rows {} nodes {} intern+uf {:?} minnode {:?} maps {:?}",
            total,
            n,
            t_uf,
            t_mn - t_uf,
            t_rows.elapsed() - t_mn
        );
    }
    Links { link, lbloom, names }
}

/// The vector scanner must agree with the scalar one on every byte pattern
/// that matters: delimiters at every offset, runs of them, lines shorter than
/// a block and lines longer than the mask. If it ever does not, the run falls
/// back to the scalar path rather than writing a wrong answer, and says so.
fn check_simd() -> bool {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut x = 0x243f_6a88_85a3_08d3u64;
    let pool = [b'a', b',', b'"', b'\n', b'0', b'\r', 0xffu8, b' '];
    for _ in 0..3600 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        buf.push(pool[(x & 7) as usize]);
    }
    // Every delimiter at every offset of a long run of plain bytes.
    for i in 0..200usize {
        buf.extend_from_slice(&[b'x'; 40]);
        let at = buf.len() - 1 - (i % 40);
        buf[at] = [b',', b'"', b'\n'][i % 3];
    }
    buf.extend_from_slice(b"\n");
    buf.extend_from_slice(&vec![b'z'; 300]);
    buf.extend_from_slice(b",a,b\n");
    let mut p = 0usize;
    while p < buf.len() {
        let a = scan_line_g::<true>(&buf, p);
        let b = scan_line_g::<false>(&buf, p);
        if (a.nl, a.nc, a.cm, a.qm, a.long) != (b.nl, b.nc, b.cm, b.qm, b.long) {
            return false;
        }
        p = a.nl + 1;
    }
    true
}

fn main() {
    let t0 = std::time::Instant::now();
    if std::env::var_os("SS_NOSIMD").is_some() {
        SIMD_OK.store(false, Ordering::Relaxed);
    } else if !check_simd() {
        SIMD_OK.store(false, Ordering::Relaxed);
        eprintln!("shopsess: vector scanner disagrees with the scalar one; using scalar");
    }
    let args: Vec<String> = std::env::args().collect();
    let data: PathBuf = args
        .get(1)
        .cloned()
        .or_else(|| std::env::var("DATA_DIR").ok())
        .unwrap_or_else(|| "/data".into())
        .into();
    let outdir: PathBuf = args
        .get(2)
        .cloned()
        .or_else(|| std::env::var("OUTPUT_DIR").ok())
        .unwrap_or_else(|| "/output".into())
        .into();
    let nt: usize = std::env::var("NCPU")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&x| x > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map(|x| x.get()).unwrap_or(8));

    let ev_files = list_csv(&data.join("events"));
    let cl_files = list_csv(&data.join("clicks"));
    let lk_files = list_csv(&data.join("links"));
    let mut paths: Vec<PathBuf> = Vec::new();
    paths.extend(ev_files.iter().cloned());
    let ev_n = ev_files.len();
    paths.extend(cl_files.iter().cloned());
    let cl_n = cl_files.len();
    paths.extend(lk_files.iter().cloned());
    let lk_n = lk_files.len();
    paths.push(data.join("products.csv"));
    paths.push(data.join("campaigns.csv"));
    // Opening and advising 80-odd files is slow enough to be worth threads:
    // MADV_WILLNEED starts the readahead for a couple of gigabytes.
    let maps: Vec<Map> = {
        let next = AtomicUsize::new(0);
        let raw: Vec<(usize, usize)> = {
            let mut got: Vec<Vec<(usize, usize, usize)>> = Vec::new();
            std::thread::scope(|s| {
                let hs: Vec<_> = (0..nt.min(paths.len().max(1)))
                    .map(|_| {
                        let next = &next;
                        let paths = &paths;
                        s.spawn(move || {
                            let mut out: Vec<(usize, usize, usize)> = Vec::new();
                            loop {
                                let k = next.fetch_add(1, Ordering::Relaxed);
                                if k >= paths.len() {
                                    break;
                                }
                                match Map::open(&paths[k]) {
                                    Ok(m) => out.push((k, m.ptr as usize, m.len)),
                                    Err(_) => out.push((k, 0, 0)),
                                }
                            }
                            out
                        })
                    })
                    .collect();
                for h in hs {
                    got.push(h.join().unwrap());
                }
            });
            let mut v = vec![(0usize, 0usize); paths.len()];
            for g in got {
                for (k, p, l) in g {
                    v[k] = (p, l);
                }
            }
            v
        };
        raw.into_iter()
            .map(|(p, l)| {
                if l == 0 {
                    Map { ptr: std::ptr::NonNull::<u8>::dangling().as_ptr(), len: 0 }
                } else {
                    Map { ptr: p as *mut u8, len: l }
                }
            })
            .collect()
    };
    let t_maps = t0.elapsed();
    let i_ev = 0..ev_n;
    let i_cl = ev_n..ev_n + cl_n;
    let i_lk = ev_n + cl_n..ev_n + cl_n + lk_n;
    let i_prod = ev_n + cl_n + lk_n;
    let i_camp = i_prod + 1;

    let manifest = std::fs::read(data.join("manifest.json")).expect("manifest.json");
    let ws = json_ts(&manifest, "window_start");
    let we = json_ts(&manifest, "window_end");

    // ---- products
    let mut cat_map = Map64::with_capacity(256);
    let mut cat_names: Vec<Vec<u8>> = Vec::new();
    let mut praw: Vec<(u64, u32)> = Vec::new();
    {
        let d = maps[i_prod].as_slice();
        each_line::<2, _>(d, |line, f| {
            let pid = &line[f[0].0 as usize..f[0].1 as usize];
            let cat = &line[f[1].0 as usize..f[1].1 as usize];
            if pid.is_empty() {
                return;
            }
            let want = cat_names.len() as u64;
            let ci = cat_map.get_or_insert(hash(cat), want);
            if ci == want {
                cat_names.push(cat.to_vec());
            }
            praw.push((
                sref_of(i_prod, line.as_ptr() as usize - d.as_ptr() as usize + f[0].0 as usize, pid.len()),
                ci as u32,
            ));
        });
    }
    if !cat_names.iter().any(|c| c == b"unknown") {
        cat_names.push(b"unknown".to_vec());
    }
    let mut order: Vec<u32> = (0..cat_names.len() as u32).collect();
    order.sort_by(|&a, &b| cat_names[a as usize].cmp(&cat_names[b as usize]));
    let mut remap = vec![0u32; cat_names.len()];
    for (newi, &old) in order.iter().enumerate() {
        remap[old as usize] = newi as u32;
    }
    let cats: Vec<Vec<u8>> = order.iter().map(|&o| cat_names[o as usize].clone()).collect();
    let unknown_cat = remap[cat_names.iter().position(|c| c == b"unknown").unwrap()];
    assert!(cats.len() <= 255, "too many categories");

    let getb = |s: u64| -> &[u8] {
        let len = (s >> 56) as usize;
        let fi = ((s >> 40) & 0xffff) as usize;
        let off = (s & 0xff_ffff_ffff) as usize;
        unsafe { std::slice::from_raw_parts(maps[fi].ptr.add(off), len) }
    };
    let pcap = praw.len() * 4 + 1024;
    let mut pmax = 0usize;
    for &(s, _) in &praw {
        let b = getb(s);
        if b.len() >= 2 && b[0] == b'p' {
            if let Some(v) = canon_num(&b[1..]) {
                if (v as usize) < pcap && v as usize > pmax {
                    pmax = v as usize;
                }
            }
        }
    }
    let mut prod = vec![0u8; pmax + 1];
    let mut pextra: Vec<(u64, u64)> = Vec::new();
    for &(s, c) in &praw {
        let b = getb(s);
        let nc = remap[c as usize] as u8 + 1;
        let mut placed = false;
        if b.len() >= 2 && b[0] == b'p' {
            if let Some(v) = canon_num(&b[1..]) {
                if (v as usize) <= pmax {
                    prod[v as usize] = nc;
                    placed = true;
                }
            }
        }
        if !placed {
            pextra.push((hash(b), (nc - 1) as u64));
        }
    }
    let prod_extra = if pextra.is_empty() {
        None
    } else {
        let mut m = Map64::with_capacity(pextra.len());
        for (k, v) in pextra {
            m.insert(k, v);
        }
        Some(m)
    };

    // ---- campaigns
    let mut chan_map = Map64::with_capacity(64);
    let mut chans: Vec<Vec<u8>> = Vec::new();
    let mut craw: Vec<(u64, u32)> = Vec::new();
    {
        let d = maps[i_camp].as_slice();
        each_line::<2, _>(d, |line, f| {
            let cid = &line[f[0].0 as usize..f[0].1 as usize];
            let ch = &line[f[1].0 as usize..f[1].1 as usize];
            if cid.is_empty() {
                return;
            }
            let want = chans.len() as u64;
            let hi = chan_map.get_or_insert(hash(ch), want);
            if hi == want {
                chans.push(ch.to_vec());
            }
            craw.push((
                sref_of(i_camp, line.as_ptr() as usize - d.as_ptr() as usize + f[0].0 as usize, cid.len()),
                hi as u32,
            ));
        });
    }
    let ncamp = craw.len();
    let ccap = ncamp * 4 + 1024;
    let mut cmax = 0usize;
    for &(s, _) in &craw {
        let b = getb(s);
        if b.len() >= 3 && b[0] == b'c' && b[1] == b'_' {
            if let Some(v) = canon_num(&b[2..]) {
                if (v as usize) < ccap && v as usize > cmax {
                    cmax = v as usize;
                }
            }
        }
    }
    let mut camp = vec![0u32; cmax + 1];
    let mut cextra: Vec<(u64, u64)> = Vec::new();
    let mut camp_name: Vec<u64> = Vec::with_capacity(ncamp);
    let mut chan: Vec<u32> = Vec::with_capacity(ncamp);
    for (i, &(s, ch)) in craw.iter().enumerate() {
        camp_name.push(s);
        chan.push(ch);
        let b = getb(s);
        let mut placed = false;
        if b.len() >= 3 && b[0] == b'c' && b[1] == b'_' {
            if let Some(v) = canon_num(&b[2..]) {
                if (v as usize) <= cmax {
                    camp[v as usize] = i as u32 + 1;
                    placed = true;
                }
            }
        }
        if !placed {
            cextra.push((hash(b), i as u64));
        }
    }
    let camp_extra = if cextra.is_empty() {
        None
    } else {
        let mut m = Map64::with_capacity(cextra.len());
        for (k, v) in cextra {
            m.insert(k, v);
        }
        Some(m)
    };

    // ---- links
    let t_pre = t0.elapsed();
    if std::env::var("SS_TIMING").is_ok() {
        eprintln!("  pre: maps {:?} meta {:?}", t_maps, t_pre - t_maps);
    }
    let links = build_links(&maps, i_lk.clone(), nt);
    if std::env::var("SS_TIMING").is_ok() {
        eprintln!("  pre {:?} links {:?}", t_pre, t0.elapsed() - t_pre);
    }

    let ev_bytes: usize = i_ev.clone().map(|i| maps[i].len).sum();
    let cl_bytes: usize = i_cl.clone().map(|i| maps[i].len).sum();
    let est_rows = ev_bytes / 70 + 1;
    let bits = {
        let mut b = 8u32;
        while b < 13 && (1usize << b) * ROWS_PER_BUCKET < est_rows {
            b += 1;
        }
        b
    };
    let envbits = |k: &str, d: u32| -> u32 {
        std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
    };
    let eid_bits = envbits("SS_EBITS", bits);
    let per_bits = envbits("SS_PBITS", bits.min(12));
    let nb_eid = 1usize << eid_bits;
    let nb_per = 1usize << per_bits;
    let day0 = ws.div_euclid(DAY_MS);
    let day_last = (we - 1).div_euclid(DAY_MS);
    let ndays = (day_last - day0 + 1) as usize;
    assert!(ndays < 250, "window too long");
    let ctx = Ctx {
        maps,
        ev_lo: ws,
        ev_hi: we,
        cl_lo: ws - WEEK_MS,
        cl_hi: we,
        base: ws - WEEK_MS,
        day0,
        ndays,
        link: links.link,
        lbloom: links.lbloom,
        names: links.names,
        prod,
        prod_extra,
        camp,
        camp_extra,
        ncamp,
        cats,
        unknown_cat,
        chan,
        chans,
        eid_bits,
        per_bits,
    };

    // Two arenas: the event-id shuffle is dropped as soon as dedup is done,
    // which halves peak memory and the page faults that go with it.
    let arena_e = Arena::new(ev_bytes + (ev_bytes >> 1) + (1 << 30));
    let arena = Arena::new(ev_bytes + cl_bytes + (1 << 30));

    // ---- optional parse micro-benchmark: SS_BENCH=<ablation level>
    if let Ok(lv) = std::env::var("SS_BENCH") {
        let lv: u32 = lv.parse().unwrap_or(0);
        const CH: usize = 1 << 20;
        let mut cks: Vec<(usize, usize, usize)> = Vec::new();
        let mut nb = 0usize;
        for fi in i_ev.clone() {
            let n = ctx.maps[fi].len;
            nb += n;
            let mut a = 0;
            while a < n {
                cks.push((fi, a, (a + CH).min(n)));
                a += CH;
            }
        }
        for _ in 0..3 {
            let ar = Arena::new(nb * 2 + (1 << 30));
            let next = AtomicUsize::new(0);
            let t = std::time::Instant::now();
            std::thread::scope(|s| {
                for _ in 0..nt {
                    let next = &next;
                    let cks = &cks;
                    let ctx = &ctx;
                    let ar = &ar;
                    s.spawn(move || {
                        let mut es = Sink::<ERec>::new(ar, nb_eid, BLK_E);
                        let mut dc = DateCache::new();
                        let mut xn: Vec<(u64, u64)> = Vec::new();
                        loop {
                            let k = next.fetch_add(1, Ordering::Relaxed);
                            if k >= cks.len() {
                                break;
                            }
                            let (fi, a, b) = cks[k];
                            match lv {
                                1 => parse_events::<1>(ctx, fi, a, b, &mut es, &mut dc, &mut xn),
                                2 => parse_events::<2>(ctx, fi, a, b, &mut es, &mut dc, &mut xn),
                                3 => parse_events::<3>(ctx, fi, a, b, &mut es, &mut dc, &mut xn),
                                4 => parse_events::<4>(ctx, fi, a, b, &mut es, &mut dc, &mut xn),
                                5 => parse_events::<5>(ctx, fi, a, b, &mut es, &mut dc, &mut xn),
                                6 => parse_events::<6>(ctx, fi, a, b, &mut es, &mut dc, &mut xn),
                                _ => parse_events::<0>(ctx, fi, a, b, &mut es, &mut dc, &mut xn),
                            }
                        }
                        std::mem::forget(es);
                    });
                }
            });
            let el = t.elapsed();
            eprintln!(
                "bench lv={} {:?}  {:.2} GB/s  acc {}",
                lv, el, nb as f64 / el.as_secs_f64() / 1e9, ACC.load(Ordering::Relaxed)
            );
        }
        return;
    }

    // ---- parse
    const CHUNK: usize = 1 << 20;
    let mut chunks: Vec<(u8, u32, usize, usize)> = Vec::new();
    for fi in i_ev.clone() {
        let n = ctx.maps[fi].len;
        let mut a = 0;
        while a < n {
            chunks.push((0, fi as u32, a, (a + CHUNK).min(n)));
            a += CHUNK;
        }
    }
    for fi in i_cl.clone() {
        let n = ctx.maps[fi].len;
        let mut a = 0;
        while a < n {
            chunks.push((1, fi as u32, a, (a + CHUNK).min(n)));
            a += CHUNK;
        }
    }
    let next = AtomicUsize::new(0);
    let mut eparts: Vec<Vec<Vec<Blk<ERec>>>> = Vec::new();
    let mut cparts: Vec<Vec<Vec<Blk<CRec>>>> = Vec::new();
    let mut xraw: Vec<(u64, u64)> = Vec::new();
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..nt)
            .map(|_| {
                let next = &next;
                let chunks = &chunks;
                let ctx = &ctx;
                let arena = &arena;
                let arena_e = &arena_e;
                s.spawn(move || {
                    let mut es = Sink::<ERec>::new(arena_e, nb_eid, BLK_E);
                    let mut cs = Sink::<CRec>::new(arena, nb_per, BLK_P);
                    let mut dc = DateCache::new();
                    let mut xn: Vec<(u64, u64)> = Vec::new();
                    loop {
                        let k = next.fetch_add(1, Ordering::Relaxed);
                        if k >= chunks.len() {
                            break;
                        }
                        let (kind, fi, a, b) = chunks[k];
                        let tc = std::time::Instant::now();
                        if kind == 0 {
                            parse_events::<0>(ctx, fi as usize, a, b, &mut es, &mut dc, &mut xn);
                            NS_EV.fetch_add(tc.elapsed().as_nanos() as usize, Ordering::Relaxed);
                        } else {
                            parse_clicks(ctx, fi as usize, a, b, &mut cs, &mut dc);
                            NS_CL.fetch_add(tc.elapsed().as_nanos() as usize, Ordering::Relaxed);
                        }
                    }
                    (es.finish(), cs.finish(), xn)
                })
            })
            .collect();
        for h in hs {
            let (e, c, x) = h.join().unwrap();
            eparts.push(e);
            cparts.push(c);
            xraw.extend_from_slice(&x);
        }
    });
    // Names of ids that could not be encoded: normally none at all.
    let mut xnames = Map64::with_capacity(xraw.len() + 16);
    for &(k, v) in xraw.iter() {
        xnames.insert(k, v);
    }
    let xnames = &xnames;
    let t_pp = t0.elapsed();
    let ebuckets = merge_blocks(eparts, nb_eid);
    let cbuckets = merge_blocks(cparts, nb_per);
    let t_parse = t0.elapsed();
    if std::env::var("SS_TIMING").is_ok() {
        eprintln!(
            "  parse-only {:?} merge {:?} ev-thread-ms {} cl-thread-ms {} xn {} rows {} valid {} linkhits {}",
            t_pp,
            t_parse - t_pp,
            NS_EV.load(Ordering::Relaxed) / 1_000_000,
            NS_CL.load(Ordering::Relaxed) / 1_000_000,
            xraw.len(),
            NROW.load(Ordering::Relaxed),
            NVAL.load(Ordering::Relaxed),
            LKH.load(Ordering::Relaxed)
        );
    }

    // ---- dedup. Process the fattest buckets first: one whale bucket at the
    // end of the queue would leave seven threads idle.
    let eorder = order_by_size(&ebuckets);
    let next = AtomicUsize::new(0);
    let mut pparts: Vec<Vec<Vec<Blk<PRec>>>> = Vec::new();
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..nt)
            .map(|_| {
                let next = &next;
                let ebuckets = &ebuckets;
                let eorder = &eorder;
                let arena = &arena;
                s.spawn(move || {
                    let mut sink = Sink::<PRec>::new(arena, nb_per, BLK_P);
                    let mut tbl: Vec<DEnt> = Vec::new();
                    let pb = per_bits;
                    loop {
                        let k = next.fetch_add(1, Ordering::Relaxed);
                        if k >= nb_eid {
                            break;
                        }
                        dedup_bucket(&ebuckets[eorder[k]], &mut tbl, &mut sink, pb);
                    }
                    sink.finish()
                })
            })
            .collect();
        for h in hs {
            pparts.push(h.join().unwrap());
        }
    });
    let pbuckets = merge_blocks(pparts, nb_per);
    drop(ebuckets);
    drop(arena_e);
    let porder = order_by_size(&pbuckets);
    let t_dedup = t0.elapsed();

    // ---- fold + write user_daily
    let ud = outdir.join("user_daily");
    let cdd = outdir.join("campaign_daily");
    std::fs::create_dir_all(&ud).unwrap();
    std::fs::create_dir_all(&cdd).unwrap();
    let stride = ctx.ndays + 2;
    let next = AtomicUsize::new(0);
    let mut cds: Vec<Vec<CD>> = Vec::new();
    let mut nrows_tot: usize = 0;
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..nt)
            .map(|t| {
                let next = &next;
                let pbuckets = &pbuckets;
                let cbuckets = &cbuckets;
                let porder = &porder;
                let ctx = &ctx;
                let ud = &ud;
                s.spawn(move || {
                    let mut f = Fold {
                        ev: Vec::new(),
                        cl: Vec::new(),
                        dense: Vec::new(),
                        cdense: Vec::new(),
                        persons: Vec::new(),
                        pslot: Vec::new(),
                        ecnt: Vec::new(),
                        ccnt: Vec::new(),
                        epos: Vec::new(),
                        cpos: Vec::new(),
                        cur: Vec::new(),
                        tbl: Vec::new(),
                        t: Tmp {
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
                        },
                        o: Out {
                            cd: vec![CD::default(); (ctx.ncamp + 1) * stride],
                            uid: Vec::new(),
                            day: Vec::new(),
                            sessions: Vec::new(),
                            events: Vec::new(),
                            rev: Vec::new(),
                            tcval: Vec::new(),
                            tcdef: Vec::new(),
                            tcn: 0,
                        },
                    };
                    loop {
                        let k = next.fetch_add(1, Ordering::Relaxed);
                        if k >= nb_per {
                            break;
                        }
                        let k = porder[k];
                        fold_bucket(ctx, xnames, &mut f, &pbuckets[k], &cbuckets[k]);
                    }
                    let n = f.o.day.len();
                    if n > 0 {
                        let cols = [
                            pq::Col { name: "user_id", kind: pq::Kind::Utf8, vals: &f.o.uid, defs: &[], nvals: n as i64 },
                            pq::Col { name: "day", kind: pq::Kind::Date, vals: pq::as_bytes(&f.o.day), defs: &[], nvals: n as i64 },
                            pq::Col { name: "sessions", kind: pq::Kind::I64, vals: pq::as_bytes(&f.o.sessions), defs: &[], nvals: n as i64 },
                            pq::Col { name: "events", kind: pq::Kind::I64, vals: pq::as_bytes(&f.o.events), defs: &[], nvals: n as i64 },
                            pq::Col { name: "revenue_cents", kind: pq::Kind::I64, vals: pq::as_bytes(&f.o.rev), defs: &[], nvals: n as i64 },
                            pq::Col { name: "top_category", kind: pq::Kind::Utf8Opt, vals: &f.o.tcval, defs: &f.o.tcdef, nvals: f.o.tcn },
                        ];
                        pq::write(&ud.join(format!("part-{:02}.parquet", t)), n as i64, &cols).unwrap();
                    }
                    (f.o.cd, n)
                })
            })
            .collect();
        for h in hs {
            let (cd, n) = h.join().unwrap();
            cds.push(cd);
            nrows_tot += n;
        }
    });
    let t_fold = t0.elapsed();

    // ---- campaign_daily
    let mut agg = cds.pop().unwrap();
    for c in &cds {
        for i in 0..agg.len() {
            agg[i].sessions += c[i].sessions;
            agg[i].purch += c[i].purch;
            agg[i].assist += c[i].assist;
            agg[i].rev += c[i].rev;
        }
    }
    let mut cid = Vec::new();
    let mut chv = Vec::new();
    let mut cday: Vec<i32> = Vec::new();
    let mut csess: Vec<i64> = Vec::new();
    let mut cpur: Vec<i64> = Vec::new();
    let mut crev: Vec<i64> = Vec::new();
    let mut cass: Vec<i64> = Vec::new();
    for ci in 0..=ctx.ncamp {
        for d in 0..stride {
            let e = agg[ci * stride + d];
            if e.sessions == 0 && e.purch == 0 && e.assist == 0 && e.rev == 0 {
                continue;
            }
            if ci == ctx.ncamp {
                pq::push_str(&mut cid, b"organic");
                pq::push_str(&mut chv, b"organic");
            } else {
                pq::push_str(&mut cid, ctx.bytes(camp_name[ci]));
                pq::push_str(&mut chv, &ctx.chans[ctx.chan[ci] as usize]);
            }
            cday.push((ctx.day0 + d as i64) as i32);
            csess.push(e.sessions as i64);
            cpur.push(e.purch as i64);
            crev.push(e.rev as i64);
            cass.push(e.assist as i64);
        }
    }
    let n = cday.len();
    let cols = [
        pq::Col { name: "campaign_id", kind: pq::Kind::Utf8, vals: &cid, defs: &[], nvals: n as i64 },
        pq::Col { name: "channel", kind: pq::Kind::Utf8, vals: &chv, defs: &[], nvals: n as i64 },
        pq::Col { name: "day", kind: pq::Kind::Date, vals: pq::as_bytes(&cday), defs: &[], nvals: n as i64 },
        pq::Col { name: "sessions", kind: pq::Kind::I64, vals: pq::as_bytes(&csess), defs: &[], nvals: n as i64 },
        pq::Col { name: "purchasing_sessions", kind: pq::Kind::I64, vals: pq::as_bytes(&cpur), defs: &[], nvals: n as i64 },
        pq::Col { name: "revenue_cents", kind: pq::Kind::I64, vals: pq::as_bytes(&crev), defs: &[], nvals: n as i64 },
        pq::Col { name: "assisted_sessions", kind: pq::Kind::I64, vals: pq::as_bytes(&cass), defs: &[], nvals: n as i64 },
    ];
    pq::write(&cdd.join("part-00.parquet"), n as i64, &cols).unwrap();
    if nrows_tot == 0 {
        let cols = [
            pq::Col { name: "user_id", kind: pq::Kind::Utf8, vals: &[], defs: &[], nvals: 0 },
            pq::Col { name: "day", kind: pq::Kind::Date, vals: &[], defs: &[], nvals: 0 },
            pq::Col { name: "sessions", kind: pq::Kind::I64, vals: &[], defs: &[], nvals: 0 },
            pq::Col { name: "events", kind: pq::Kind::I64, vals: &[], defs: &[], nvals: 0 },
            pq::Col { name: "revenue_cents", kind: pq::Kind::I64, vals: &[], defs: &[], nvals: 0 },
            pq::Col { name: "top_category", kind: pq::Kind::Utf8Opt, vals: &[], defs: &[], nvals: 0 },
        ];
        pq::write(&ud.join("part-00.parquet"), 0, &cols).unwrap();
    }

    if std::env::var("SS_TIMING").is_ok() {
        eprintln!(
            "parse {:?}  dedup {:?}  fold {:?}  total {:?}  rows {} / {}",
            t_parse,
            t_dedup - t_parse,
            t_fold - t_dedup,
            t0.elapsed(),
            nrows_tot,
            n
        );
    }
}
