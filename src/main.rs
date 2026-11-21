// Shopping Sessions: sessionize ~60M messy click-stream rows and write two
// daily Parquet tables. Pipeline:
//   links  -> union-find, one person key per user id
//   parse  -> events into event-id buckets, clicks into person buckets
//   dedup  -> per event-id bucket, keep the earliest ingest; emit person buckets
//   fold   -> per person bucket: sort, sessionize, attribute, aggregate
//   write  -> Parquet
mod cols;
mod fast;
mod genid;
mod pq;
mod split;
mod sys;
mod tbl;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};
use sys::*;
use tbl::*;

#[global_allocator]
static ALLOC: HugeAlloc = HugeAlloc;

const WEEK_MS: i64 = 7 * 86_400_000;
const GAP_MS: u32 = 1_800_000;
const LATE_MS: i64 = 86_400_000;
const WEEK: u32 = 604_800_000;

// Shuffle fanout is chosen from the input size so a bucket's dedup table and
// person table stay inside L2 whatever the dataset size.
const ROWS_PER_BUCKET: usize = 24_000;
const BLK_E: usize = 512;
const BLK_P: usize = 512;

const CAT_NONE: u32 = pq::NO_CODE as u32;

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
    links: OnceLock<Links>,
    no_links: Links, // empty: every user is its own person
    links_gate: Mutex<()>,
    links_cv: Condvar,
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
    #[inline(always)]
    fn links(&self) -> &Links {
        self.links.get().expect("links not built yet")
    }
    fn set_links(&self, l: Links) {
        let _ = self.links.set(l);
        let _g = self.links_gate.lock().unwrap();
        self.links_cv.notify_all();
    }
    // blocks until the link map is published
    fn wait_links(&self) {
        if self.links.get().is_some() {
            return;
        }
        let mut g = self.links_gate.lock().unwrap();
        while self.links.get().is_none() {
            g = self.links_cv.wait(g).unwrap();
        }
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
        // the usual shape, without the digit loop; the rest below is the rule
        if let Some(v) = c_num(cid) {
            if (v as usize) < self.camp.len() {
                let x = unsafe { *self.camp.get_unchecked(v as usize) };
                if x != 0 {
                    return Some(x - 1);
                }
            }
        }
        self.camp_any(cid)
    }
    #[inline(never)]
    fn camp_any(&self, cid: &[u8]) -> Option<u32> {
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
        let lk = self.links();
        let k = person_key(user);
        if !lk.lbloom.maybe(k) {
            return k;
        }
        match lk.link.get(k) {
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
/// should never happen; see `check_scan`.
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
    lk: &Links,
    fi: usize,
    from: usize,
    to: usize,
    sink: &mut Sink<ERec>,
    dc: &mut DateCache,
    ix: &mut split::Index,
    xn: &mut Vec<(u64, u64)>,
) {
    let simd = SIMD_OK.load(Ordering::Relaxed);
    let d = ctx.maps[fi].as_slice();
    let p = first_line_start(d, from);
    let mut acc = 0usize;
    let mut lkh = 0usize;
    let mut nrow = 0usize;
    let mut nval = 0usize;
    split::each_row::<7, _>(d, p, to, simd, ix, #[inline(always)] |lp, s, e| {
        let fld = |k: usize| -> &[u8] { unsafe { d.get_unchecked(lp + s[k] as usize..lp + e[k] as usize) } };
        nrow += 1;
        if ABL == 1 || ABL == 2 {
            acc += lp + s[3] as usize ^ e[6] as usize;
            return;
        }
        let eid = fld(0);
        if eid.is_empty() {
            return;
        }
        let (klo, khi) = key96(eid);
        if ABL == 3 {
            acc += klo as usize ^ khi as usize;
            return;
        }
        let g = ingest(fld(3), dc);
        let (ing_ms, ing) = (g.ms, g.sec);

        // Resolving a user to a person ends in a line of a link map far too
        // big to cache. The probe is started here and read after validation,
        // so the event timestamp covers the miss instead of waiting on it.
        let user = fld(1);
        let has_user = !user.is_empty();
        let mut pk = 0u64;
        let mut linked = false;
        if has_user && (ABL == 0 || ABL >= 6) {
            pk = person_key(user);
            linked = lk.lbloom.maybe(pk);
            if linked {
                lk.link.prefetch(pk);
            }
        }

        let mut tsf = 0u32;
        let mut pc = 0u32;
        let mut person = 0u64;
        loop {
            if !has_user {
                break;
            }
            let ts = match parse_ts_c(fld(2), dc) {
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
            // the same as ingest - ts > a day, without the two-sided clamp
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
            if ABL == 5 {
                acc += pid.len() ^ pc as usize;
                break;
            }
            person = if linked {
                match lk.link.get(pk) {
                    Some(r) => {
                        lkh += 1;
                        r
                    }
                    None => pk,
                }
            } else {
                pk
            };
            if person & PTAG != 0 && lk.names.get(person).is_none() {
                // An id too long or too odd to encode, and in no link: keep
                // track of where its bytes are so the name can be written out.
                xn.push((person, sref_of(fi, lp + s[1] as usize, (e[1] - s[1]) as usize)));
            }
            tsf = (ts - ctx.base) as u32 | 0x8000_0000;
            nval += 1;
            break;
        }
        let b = (mix(klo ^ (khi as u64), 0x9e37_79b9_7f4a_7c15) >> (64 - ctx.eid_bits)) as usize;
        if ABL == 6 {
            acc += b ^ tsf as usize ^ pc as usize ^ person as usize ^ ing as usize;
            return;
        }
        sink.push(b, ERec { klo, khi, ing, person, tsf, pc });
    });
    if ABL != 0 {
        ACC.fetch_add(acc, Ordering::Relaxed);
    }
    LKH.fetch_add(lkh, Ordering::Relaxed);
    NROW.fetch_add(nrow, Ordering::Relaxed);
    NVAL.fetch_add(nval, Ordering::Relaxed);
}

fn parse_clicks(
    ctx: &Ctx,
    fi: usize,
    from: usize,
    to: usize,
    sink: &mut Sink<CRec>,
    dc: &mut DateCache,
    ix: &mut split::Index,
) {
    let simd = SIMD_OK.load(Ordering::Relaxed);
    let d = ctx.maps[fi].as_slice();
    let p = first_line_start(d, from);
    let mut lkh = 0usize;
    split::each_row::<4, _>(d, p, to, simd, ix, #[inline(always)] |lp, s, e| {
        let fld = |k: usize| -> &[u8] { unsafe { d.get_unchecked(lp + s[k] as usize..lp + e[k] as usize) } };
        if s[0] == e[0] {
            return; // empty click_id
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
        let person = ctx.person_of(user, &mut lkh);
        let sref = sref_of(fi, lp + s[0] as usize, (e[0] - s[0]) as usize);
        let b = (mix(person, 0xff51_afd7_ed55_8ccd) >> (64 - ctx.per_bits)) as usize;
        sink.push(b, CRec { person, sref, ts: (ts - ctx.base) as u32, camp });
    });
    LKH.fetch_add(lkh, Ordering::Relaxed);
}

#[inline(always)]
fn person_bucket(person: u64, bits: u32) -> usize {
    (mix(person, 0xff51_afd7_ed55_8ccd) >> (64 - bits)) as usize
}

const RESOLVE_LAG: usize = 8;

// events parsed before the link map existed: turn their users into people
fn resolve_written(lk: &Links, sink: &mut Sink<ERec>) -> usize {
    let mut ring = [std::ptr::null_mut::<ERec>(); RESOLVE_LAG];
    let mut at = 0usize;
    let mut hits = 0usize;
    sink.each_mut(|rec| {
        let r = unsafe { &*rec };
        if r.tsf & 0x8000_0000 == 0 || !lk.lbloom.maybe(r.person) {
            return;
        }
        // the record waits in the ring while its link-map line is fetched
        lk.link.prefetch(r.person);
        let due = std::mem::replace(&mut ring[at], rec);
        at = (at + 1) & (RESOLVE_LAG - 1);
        hits += resolve_one(lk, due);
    });
    for due in ring {
        hits += resolve_one(lk, due);
    }
    hits
}

#[inline(always)]
fn resolve_one(lk: &Links, rec: *mut ERec) -> usize {
    if rec.is_null() {
        return 0;
    }
    unsafe {
        match lk.link.get((*rec).person) {
            Some(p) => {
                (*rec).person = p;
                1
            }
            None => 0,
        }
    }
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
    /// sessions credited per (campaign, day); those with purchases and their
    /// revenue apart, as few sessions have any
    cs: Vec<u32>,
    cp: Vec<u32>,
    cr: Vec<u64>,
    /// assisted sessions, apart: a campaign's days share a cache line
    asst: Vec<u32>,
    uid: Vec<u8>,
    day: Vec<i32>,
    sessions: Vec<i64>,
    events: Vec<i64>,
    rev: Vec<i64>,
    cat: Vec<u8>,
    // every count and sum or-ed together: they all fit an i32 if this does
    all_bits: u64,
}

impl Out {
    fn new(rows: usize, cd_len: usize) -> Out {
        Out {
            cs: vec![0; cd_len],
            cp: vec![0; cd_len],
            cr: vec![0; cd_len],
            asst: vec![0; cd_len],
            uid: Vec::with_capacity(rows * 16),
            day: Vec::with_capacity(rows),
            sessions: Vec::with_capacity(rows),
            events: Vec::with_capacity(rows),
            rev: Vec::with_capacity(rows),
            cat: Vec::with_capacity(rows),
            all_bits: 0,
        }
    }
    /// room for `n` more rows written in place: a name is at most 9 bytes behind its length
    fn reserve_rows(&mut self, n: usize) {
        self.uid.reserve(n * 13 + 16);
        self.day.reserve(n);
        self.sessions.reserve(n);
        self.events.reserve(n);
        self.rev.reserve(n);
        self.cat.reserve(n);
    }
    fn peek_campaign_days(&self) -> Vec<CD> {
        (0..self.cs.len()).map(|i| CD { sessions: self.cs[i], purch: self.cp[i], assist: self.asst[i], rev: self.cr[i] }).collect()
    }
    /// the campaign counts, taken out
    fn campaign_days(&mut self) -> Vec<CD> {
        let v = self.peek_campaign_days();
        self.cs = Vec::new();
        self.cp = Vec::new();
        self.cr = Vec::new();
        self.asst = Vec::new();
        v
    }
    /// one session with (revenue << 1 | purchased) `v` to a (campaign, day) cell
    #[inline(always)]
    fn credit(&mut self, cell: usize, v: u64) {
        self.cs[cell] += 1;
        if v != 0 {
            self.cp[cell] += 1;
            self.cr[cell] += v >> 1;
        }
    }
    fn fits_i32(all_bits: u64) -> bool {
        all_bits <= i32::MAX as u64
    }
    fn write(&self, path: &Path, cats: &[Vec<u8>], narrow: bool) -> std::io::Result<()> {
        let n = self.day.len() as i64;
        let int = if narrow { pq::Kind::I64As32 } else { pq::Kind::I64 };
        let col = |name, kind, vals| pq::Col { name, kind, vals, defs: &[], nvals: n };
        let cols = [
            col("user_id", pq::Kind::Utf8, &self.uid[..]),
            col("day", pq::Kind::Date, pq::as_bytes(&self.day)),
            col("sessions", int, pq::as_bytes(&self.sessions)),
            col("events", int, pq::as_bytes(&self.events)),
            col("revenue_cents", int, pq::as_bytes(&self.rev)),
            col("top_category", pq::Kind::Dict(cats), &self.cat[..]),
        ];
        pq::write(path, n, &cols)
    }
}

fn write_campaign_daily(ctx: &Ctx, camp_name: &[u64], mut cds: Vec<Vec<CD>>, path: &Path) -> usize {
    let stride = ctx.ndays + 2;
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
    pq::write(path, n as i64, &cols).unwrap();
    n
}

/// a person with at most this many sessions is attributed with bit masks
const SMALL: usize = 64;

struct Tmp {
    /// start, day and (revenue << 1 | purchased) of each session
    ss: Vec<u32>,
    sd: Vec<u8>,
    sv: Vec<u64>,
    /// first session and day of each run of sessions on one day
    df: Vec<u32>,
    pd: Vec<u8>,
    /// the run each session is in
    sx: Vec<u8>,
    /// the sessions of each such run, as bits
    dmask: [u64; SMALL],
    /// per session, the latest click at or before its start: time and index
    bkey: [u32; SMALL],
    bidx: [u32; SMALL],
    /// per campaign, the sessions its clicks reach
    cm: Vec<u64>,
    cum: Vec<u32>,
    iv: Vec<(u32, u32)>,
    mark: Vec<u32>,
    tc: Vec<u32>,
    gen: u32,
    catrev: Vec<u64>,
    touch: Vec<u32>,
}

impl Tmp {
    fn new(ctx: &Ctx) -> Tmp {
        Tmp {
            ss: Vec::new(),
            sd: Vec::new(),
            sv: Vec::new(),
            df: Vec::new(),
            pd: Vec::new(),
            sx: Vec::new(),
            dmask: [0; SMALL],
            bkey: [0; SMALL],
            bidx: [NO_CLICK; SMALL],
            cm: vec![0; ctx.ncamp + 1],
            cum: vec![0; ctx.ndays + 4],
            iv: vec![(0, 0); ctx.ncamp + 1],
            mark: vec![0; ctx.ncamp + 1],
            tc: vec![0; ctx.ncamp + 1],
            gen: 0,
            catrev: vec![0; ctx.cats.len() + 1],
            touch: vec![0; ctx.cats.len() + 1],
        }
    }
}

/// the category with the most revenue among the touched, which are cleared
#[inline]
fn top_cat(t: &mut Tmp, ntouch: usize) -> u8 {
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
    best as u8
}

fn emit_user(ctx: &Ctx, o: &mut Out, t: &mut Tmp, name: &[u8], day: u32, ns: u64, ne: u64, rev: u64, ntouch: usize) {
    let best = top_cat(t, ntouch);
    pq::push_str(&mut o.uid, name);
    o.day.push((ctx.day0 + day as i64) as i32);
    o.sessions.push(ns as i64);
    o.events.push(ne as i64);
    o.rev.push(rev as i64);
    o.all_bits |= ns | ne | rev;
    o.cat.push(best);
}

/// Cut `ev`, in time order, into sessions: the user's row for each day goes
/// out, and each session's start, day and revenue stay in `t`.
fn sessionize(ctx: &Ctx, ev: &[PRec], t: &mut Tmp, o: &mut Out, name: &[u8]) -> usize {
    let n = ev.len();
    t.ss.clear();
    t.sd.clear();
    t.sv.clear();
    t.df.clear();
    t.pd.clear();
    // a person has no more sessions than events; the starts are read 8 at a time
    t.ss.reserve(n + 8);
    t.sd.reserve(n);
    t.sv.reserve(n);
    t.sx.clear();
    t.sx.reserve(n);
    let (ssp, sdp, svp, sxp) = (t.ss.as_mut_ptr(), t.sd.as_mut_ptr(), t.sv.as_mut_ptr(), t.sx.as_mut_ptr());
    let mut nd = 0usize;
    let mut ns = 0usize;
    let mut cur_day = u32::MAX;
    // the first start that needs its day worked out again
    let mut day_end = i64::MIN;
    let mut dsess = 0u64;
    let mut dev = 0u64;
    let mut drev = 0u64;
    let mut ntouch = 0usize;
    let mut i = 0usize;
    while i < n {
        let start = unsafe { ev.get_unchecked(i) }.ts;
        if start as i64 >= day_end {
            let abs = ctx.base + start as i64;
            let q = abs / DAY_MS;
            let day = (q - ctx.day0) as u32;
            day_end = if abs >= 0 { (q + 1) * DAY_MS - ctx.base } else { i64::MIN };
            if day != cur_day {
                if cur_day != u32::MAX {
                    emit_user(ctx, o, t, name, cur_day, dsess, dev, drev, ntouch);
                }
                cur_day = day;
                dsess = 0;
                dev = 0;
                drev = 0;
                ntouch = 0;
                t.df.push(ns as u32);
                t.pd.push(day as u8);
                nd += 1;
            }
        }
        // the session runs until a gap of more than 30 minutes
        let mut srev = 0u64;
        let mut pur = 0u64;
        let mut prev = start;
        let mut j = i;
        loop {
            let pc = unsafe { ev.get_unchecked(j) }.pc;
            if pc != 0 {
                let price = (pc & 0x00ff_ffff) as u64;
                let c = (pc >> 24) as usize;
                if t.catrev[c] == 0 {
                    t.touch[ntouch] = c as u32;
                    ntouch += 1;
                }
                t.catrev[c] += price;
                srev += price;
                pur = 1;
            }
            j += 1;
            if j == n {
                break;
            }
            let ts = unsafe { ev.get_unchecked(j) }.ts;
            if ts.wrapping_sub(prev) > GAP_MS {
                break;
            }
            prev = ts;
        }
        dsess += 1;
        dev += (j - i) as u64;
        drev += srev;
        i = j;
        unsafe {
            *ssp.add(ns) = start;
            *sdp.add(ns) = cur_day as u8;
            *svp.add(ns) = (srev << 1) | pur;
            // only read for a person of at most `SMALL` sessions
            *sxp.add(ns) = (nd - 1) as u8;
        }
        ns += 1;
    }
    if cur_day != u32::MAX {
        emit_user(ctx, o, t, name, cur_day, dsess, dev, drev, ntouch);
    }
    unsafe {
        // the whole last group of 8 starts is readable
        for k in 0..8 {
            *ssp.add(ns + k) = 0;
        }
        t.ss.set_len(ns);
        t.sd.set_len(ns);
        t.sv.set_len(ns);
        t.sx.set_len(ns);
    }
    t.df.push(ns as u32);
    ns
}

/// Among the first `hi` clicks, all at or before a start, the one a session
/// starting then is credited to: the latest, and of several in its
/// millisecond the one with the smallest id.
#[inline(always)]
fn credited(ctx: &Ctx, cl: &[CRec], hi: usize, memo: &mut (usize, usize)) -> usize {
    let g = hi - 1;
    if g == 0 || cl[g - 1].ts != cl[g].ts {
        return g;
    }
    if memo.0 != hi {
        *memo = (hi, smallest_id(ctx, cl, hi));
    }
    memo.1
}

#[cold]
#[inline(never)]
fn smallest_id(ctx: &Ctx, cl: &[CRec], hi: usize) -> usize {
    let t = cl[hi - 1].ts;
    let mut g = hi - 1;
    while g > 0 && cl[g - 1].ts == t {
        g -= 1;
    }
    let mut best = g;
    for k in g + 1..hi {
        if ctx.bytes(cl[k].sref) < ctx.bytes(cl[best].sref) {
            best = k;
        }
    }
    best
}

/// the low `i` bits, for `i` up to 64
#[inline(always)]
fn low_bits(i: usize) -> u64 {
    if i >= 64 {
        !0
    } else {
        (1u64 << i) - 1
    }
}

/// a click as attribution reads it; `at` is what its kind needs to find the id
trait Click: Copy {
    fn ts(&self) -> u32;
    fn camp(&self) -> usize;
    fn id<'a>(&self, ctx: &'a Ctx, at: usize) -> &'a [u8];
}

impl Click for CRec {
    #[inline(always)]
    fn ts(&self) -> u32 {
        self.ts
    }
    #[inline(always)]
    fn camp(&self) -> usize {
        self.camp as usize
    }
    #[inline(always)]
    fn id<'a>(&self, ctx: &'a Ctx, _at: usize) -> &'a [u8] {
        ctx.bytes(self.sref)
    }
}

const NO_CLICK: u32 = u32::MAX;

/// 8 session starts, or their latest clicks, held in a register
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
type V8 = core::arch::x86_64::__m256i;
#[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
type V8 = [u32; 8];

#[inline(always)]
unsafe fn load8(p: *const u32) -> V8 {
    (p as *const V8).read_unaligned()
}

#[inline(always)]
unsafe fn store8(p: *mut u32, v: V8) {
    (p as *mut V8).write_unaligned(v)
}

/// Click `k` at time `lo` against 8 session starts. Bit i of the results:
/// `ss[i] >= lo`, `ss[i] <= hi`, and "the latest click so far for session i
/// is at this very time". Where the click is at or before the start and
/// later than the latest so far, it becomes the latest.
#[cfg_attr(all(target_arch = "x86_64", target_feature = "avx2"), allow(dead_code))]
#[inline(always)]
fn click8_plain(ss: &[u32; 8], bkey: &mut [u32; 8], bidx: &mut [u32; 8], lo: u32, hi: u32, k: u32) -> (u64, u64, u64) {
    let (mut ge, mut le, mut tie) = (0u64, 0u64, 0u64);
    for i in 0..8 {
        let x = ss[i];
        le |= ((x <= hi) as u64) << i;
        if x >= lo {
            ge |= 1 << i;
            if bidx[i] == NO_CLICK || lo > bkey[i] {
                bkey[i] = lo;
                bidx[i] = k;
            } else if lo == bkey[i] {
                tie |= 1 << i;
            }
        }
    }
    (ge, le, tie)
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[inline(always)]
fn click8(x: V8, bkey: &mut V8, bidx: &mut V8, lo: u32, hi: u32, k: u32) -> (u64, u64, u64) {
    use core::arch::x86_64::*;
    unsafe {
        let bits = |v: __m256i| _mm256_movemask_ps(_mm256_castsi256_ps(v)) as u32 as u64;
        let key = _mm256_set1_epi32(lo as i32);
        let ge = _mm256_cmpeq_epi32(_mm256_max_epu32(x, key), x);
        let le = _mm256_cmpeq_epi32(_mm256_min_epu32(x, _mm256_set1_epi32(hi as i32)), x);
        let (bk, bi) = (*bkey, *bidx);
        let none = _mm256_cmpeq_epi32(bi, _mm256_set1_epi32(-1));
        // a latest click that is no earlier than this one stays
        let stays = _mm256_andnot_si256(none, _mm256_cmpeq_epi32(_mm256_max_epu32(bk, key), bk));
        let takes = _mm256_andnot_si256(stays, ge);
        let tie = _mm256_and_si256(_mm256_andnot_si256(none, _mm256_cmpeq_epi32(bk, key)), ge);
        *bkey = _mm256_blendv_epi8(bk, key, takes);
        *bidx = _mm256_blendv_epi8(bi, _mm256_set1_epi32(k as i32), takes);
        (bits(ge), bits(le), bits(tie))
    }
}

#[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
#[inline(always)]
fn click8(x: V8, bkey: &mut V8, bidx: &mut V8, lo: u32, hi: u32, k: u32) -> (u64, u64, u64) {
    click8_plain(&x, bkey, bidx, lo, hi, k)
}

/// Credit and assists for a person of at most `SMALL` sessions, the clicks
/// in any order. Each click meets the session starts 8 at a time: it gets
/// the set of sessions it reaches as bits, and takes over as the latest
/// click of the sessions it precedes. Nothing here branches on how the
/// clicks and the sessions interleave.
fn attribute_small<C: Click>(ctx: &Ctx, cl: &[C], at: usize, t: &mut Tmp, o: &mut Out) {
    let ns = t.ss.len();
    let stride = ctx.ndays + 2;
    let organic = ctx.ncamp;
    let valid = low_bits(ns);
    let groups = (ns + 7) / 8;
    let ssp = t.ss.as_ptr();
    let (bkey, bidx) = (t.bkey.as_mut_ptr(), t.bidx.as_mut_ptr());
    // sessionize left the last group of 8 starts whole. The first group and
    // its latest clicks stay in registers while the clicks go by: no click
    // waits for the stores of the one before.
    let (ss0, mut key0, mut idx0) = unsafe { (load8(ssp), load8(bkey), load8(bidx)) };
    for (k, c) in cl.iter().enumerate() {
        let lo = c.ts();
        let hi = lo.saturating_add(WEEK);
        let (mut ge, mut le, mut tie) = click8(ss0, &mut key0, &mut idx0, lo, hi, k as u32);
        for g in 1..groups {
            let (a, b, e) = unsafe {
                let (mut bk, mut bi) = (load8(bkey.add(8 * g)), load8(bidx.add(8 * g)));
                let r = click8(load8(ssp.add(8 * g)), &mut bk, &mut bi, lo, hi, k as u32);
                store8(bkey.add(8 * g), bk);
                store8(bidx.add(8 * g), bi);
                r
            };
            ge |= a << (8 * g);
            le |= b << (8 * g);
            tie |= e << (8 * g);
        }
        t.cm[c.camp()] |= ge & le & valid;
        tie &= valid;
        if tie != 0 {
            // several clicks in one millisecond: the smallest id is the latest
            unsafe { store8(bidx, idx0) };
            while tie != 0 {
                let i = tie.trailing_zeros() as usize;
                tie &= tie - 1;
                if c.id(ctx, at) < cl[t.bidx[i] as usize].id(ctx, at) {
                    t.bidx[i] = k as u32;
                }
            }
            idx0 = unsafe { load8(bidx) };
        }
    }
    unsafe {
        store8(bkey, key0);
        store8(bidx, idx0);
    }

    // credit: the latest click, if it is within 7 days of the start
    let (sv, sd) = (&t.sv[..ns], &t.sd[..ns]);
    for i in 0..ns {
        let b = t.bidx[i];
        let camp = if b != NO_CLICK && t.ss[i] - t.bkey[i] <= WEEK { cl[b as usize].camp() } else { organic };
        o.credit(camp * stride + sd[i] as usize, sv[i]);
    }
    // the next person starts with no clicks
    for b in t.bidx[..groups * 8].iter_mut() {
        *b = NO_CLICK;
    }

    // assists: a campaign's sessions, counted day by day
    let nd = t.pd.len();
    for x in 0..nd {
        t.dmask[x] = low_bits(t.df[x + 1] as usize) & !low_bits(t.df[x] as usize);
    }
    let (pd, sx, dmask) = (&t.pd[..], &t.sx[..], &t.dmask[..nd]);
    for c in cl {
        let c = c.camp();
        // a campaign's later clicks find nothing left
        let reach = std::mem::take(&mut t.cm[c]);
        if reach == 0 {
            continue;
        }
        let row = &mut o.asst[c * stride..(c + 1) * stride];
        let first = sx[reach.trailing_zeros() as usize] as usize;
        let last = sx[63 - reach.leading_zeros() as usize] as usize;
        for (d, m) in pd[first..last + 1].iter().zip(&dmask[first..last + 1]) {
            row[*d as usize] += (reach & m).count_ones();
        }
    }
}

/// sessions before each day: `cum[d]..cum[d + 1]` are the sessions of day d
fn day_starts(sd: &[u8], cum: &mut [u32]) {
    for c in cum.iter_mut() {
        *c = 0;
    }
    for &d in sd {
        cum[d as usize + 1] += 1;
    }
    let mut acc = 0u32;
    for c in cum.iter_mut() {
        acc += *c;
        *c = acc;
    }
}

/// campaign `c` assists sessions `s..e`
#[inline]
fn flush_assist(sd: &[u8], cum: &mut [u32], have_cum: &mut bool, asst: &mut [u32], stride: usize, c: usize, s: usize, e: usize) {
    if e - s <= 16 {
        for i in s..e {
            asst[c * stride + sd[i] as usize] += 1;
        }
        return;
    }
    if !*have_cum {
        *have_cum = true;
        day_starts(sd, cum);
    }
    let (d0, d1) = (sd[s] as usize, sd[e - 1] as usize);
    for d in d0..=d1 {
        let lo = (cum[d] as usize).max(s);
        let hi = (cum[d + 1] as usize).min(e);
        if hi > lo {
            asst[c * stride + d] += (hi - lo) as u32;
        }
    }
}

/// Credit and assists for any number of sessions: two walks along the
/// clicks, one per session and one per click.
fn attribute_any(ctx: &Ctx, cl: &[CRec], t: &mut Tmp, o: &mut Out) {
    let ns = t.ss.len();
    let m = cl.len();
    let stride = ctx.ndays + 2;
    let organic = ctx.ncamp;
    let Tmp { ss, sd, sv, cum, iv, mark, tc, gen, .. } = t;
    let (ss, sd) = (&ss[..], &sd[..]);

    // credit: the latest click at or before the start, within 7 days
    let mut hi = 0usize;
    let mut memo = (usize::MAX, 0usize);
    for i in 0..ns {
        let start = ss[i];
        while hi < m && cl[hi].ts <= start {
            hi += 1;
        }
        let camp = if hi == 0 {
            organic
        } else {
            let g = credited(ctx, cl, hi, &mut memo);
            if start - cl[hi - 1].ts <= WEEK {
                cl[g].camp as usize
            } else {
                organic
            }
        };
        o.credit(camp * stride + sd[i] as usize, sv[i]);
    }

    // assists: click k reaches sessions a..b, and both ends only move forward,
    // so each campaign's reach is a few runs of sessions
    *gen += 1;
    let g0 = *gen;
    let mut have_cum = false;
    let mut ntc = 0usize;
    let (mut a, mut b) = (0usize, 0usize);
    for k in 0..m {
        let tt = cl[k].ts;
        while a < ns && ss[a] < tt {
            a += 1;
        }
        if a == ns {
            break;
        }
        let end = tt.saturating_add(WEEK);
        if b < a {
            b = a;
        }
        while b < ns && ss[b] <= end {
            b += 1;
        }
        if a == b {
            continue;
        }
        let c = cl[k].camp as usize;
        if mark[c] != g0 {
            mark[c] = g0;
            iv[c] = (a as u32, b as u32);
            tc[ntc] = c as u32;
            ntc += 1;
        } else {
            let (s, e) = iv[c];
            if a as u32 <= e {
                iv[c] = (s, b as u32);
            } else {
                flush_assist(sd, cum, &mut have_cum, &mut o.asst, stride, c, s as usize, e as usize);
                iv[c] = (a as u32, b as u32);
            }
        }
    }
    for x in 0..ntc {
        let c = tc[x] as usize;
        let (s, e) = iv[c];
        flush_assist(sd, cum, &mut have_cum, &mut o.asst, stride, c, s as usize, e as usize);
    }
}

/// every session of a person without clicks is organic
fn attribute_none(ctx: &Ctx, t: &mut Tmp, o: &mut Out) {
    let row = ctx.ncamp * (ctx.ndays + 2);
    for i in 0..t.ss.len() {
        o.credit(row + t.sd[i] as usize, t.sv[i]);
    }
}

/// One person: `ev` and `cl` in time order.
fn process_person(ctx: &Ctx, ev: &[PRec], cl: &[CRec], t: &mut Tmp, o: &mut Out, name: &[u8]) {
    let ns = sessionize(ctx, ev, t, o, name);
    if ns == 0 {
        return;
    }
    if cl.is_empty() {
        attribute_none(ctx, t, o);
    } else if ns <= SMALL {
        attribute_small(ctx, cl, 0, t, o);
    } else {
        attribute_any(ctx, cl, t, o);
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
            match ctx.links().names.get(pkey).or_else(|| xn.get(pkey)) {
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

#[repr(C)]
#[derive(Copy, Clone)]
struct LinkNode {
    key: u64,
    parent: u32,
}

// union-find where the smaller id is the root, so a root names its person
struct Joiner<'a> {
    maps: &'a [Map],
    idx: Map64, // id key -> node
    nodes: Blob<LinkNode>,
    srefs: Blob<u64>, // only filled for hashed keys
    n: usize,
}

impl<'a> Joiner<'a> {
    #[inline(always)]
    fn node(&mut self, key: u64, sref: u64) -> u32 {
        let want = self.n as u64;
        let got = self.idx.get_or_insert(key, want);
        if got == want {
            self.nodes[self.n] = LinkNode { key, parent: want as u32 };
            if key & PTAG != 0 {
                self.srefs[self.n] = sref;
            }
            self.n += 1;
        }
        got as u32
    }
    #[inline(always)]
    fn find(&mut self, mut x: u32) -> u32 {
        // every index stored in a node is below n
        unsafe {
            loop {
                let p = self.nodes.get_unchecked(x as usize).parent;
                if p == x {
                    return x;
                }
                let g = self.nodes.get_unchecked(p as usize).parent;
                self.nodes.get_unchecked_mut(x as usize).parent = g;
                x = g;
            }
        }
    }
    // decoded from the key, or read back from the file
    fn id_bytes<'b>(&'b self, node: u32, buf: &'b mut [u8; MAXENC]) -> &'b [u8] {
        let key = self.nodes[node as usize].key;
        if key & PTAG == 0 {
            let n = dec_name(key, buf);
            return &buf[..n];
        }
        let s = self.srefs[node as usize];
        let len = (s >> 56) as usize;
        let fi = ((s >> 40) & 0xffff) as usize;
        let off = (s & 0xff_ffff_ffff) as usize;
        unsafe { std::slice::from_raw_parts(self.maps[fi].ptr.add(off), len) }
    }
    // encoded keys sort like their bytes
    #[inline(always)]
    fn id_less(&self, a: u32, b: u32) -> bool {
        let (ka, kb) = (self.nodes[a as usize].key, self.nodes[b as usize].key);
        if (ka | kb) & PTAG == 0 {
            return ka < kb;
        }
        self.mixed_less(a, b)
    }
    #[cold]
    fn mixed_less(&self, a: u32, b: u32) -> bool {
        let mut ea = [0u8; MAXENC];
        let mut eb = [0u8; MAXENC];
        self.id_bytes(a, &mut ea) < self.id_bytes(b, &mut eb)
    }
    #[inline(always)]
    fn union(&mut self, a: u32, b: u32) {
        if a == b {
            return;
        }
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb {
            return;
        }
        if self.id_less(rb, ra) {
            self.nodes[ra as usize].parent = rb;
        } else {
            self.nodes[rb as usize].parent = ra;
        }
    }
}

const JOIN_LAG: usize = 8;
const NAME_AHEAD: usize = 16;

// runs on one worker while the others parse events
fn build_links(maps: &[Map], range: std::ops::Range<usize>) -> Links {
    let t_start = std::time::Instant::now();
    let simd = SIMD_OK.load(Ordering::Relaxed);
    let bytes: usize = range.clone().map(|fi| maps[fi].len).sum();
    // a row is at least four bytes and names at most two ids
    let max_nodes = bytes / 2 + 2;
    let mut j = Joiner {
        maps,
        idx: Map64::with_capacity(bytes / 12 + 16),
        nodes: Blob::reserved(max_nodes),
        srefs: Blob::reserved(max_nodes),
        n: 0,
    };

    // map slots are fetched at read time, nodes at intern time
    let mut read = [(0u64, 0u64, 0u64, 0u64); JOIN_LAG];
    let mut interned = [(0u32, 0u32); JOIN_LAG];
    let mut rows = 0usize;
    for fi in range {
        let d = maps[fi].as_slice();
        let mut p = first_line_start(d, 0);
        while p < d.len() {
            let sc = scan_line(d, p, simd);
            let line = &d[p..sc.nl];
            let lp = p;
            p = sc.nl + 1;
            let f = match fields::<2>(line, &sc) {
                Some(f) => f,
                None => continue,
            };
            if f[0].0 == f[0].1 || f[1].0 == f[1].1 {
                continue;
            }
            let a = &line[f[0].0 as usize..f[0].1 as usize];
            let b = &line[f[1].0 as usize..f[1].1 as usize];
            let row = (
                person_key(a),
                sref_of(fi, lp + f[0].0 as usize, a.len()),
                person_key(b),
                sref_of(fi, lp + f[1].0 as usize, b.len()),
            );
            j.idx.prefetch(row.0);
            j.idx.prefetch(row.2);
            let at = rows & (JOIN_LAG - 1);
            rows += 1;
            let due = std::mem::replace(&mut read[at], row);
            if due.0 == 0 {
                continue;
            }
            let pair = (j.node(due.0, due.1), j.node(due.2, due.3));
            prefetch(unsafe { j.nodes.as_ptr().add(pair.0 as usize) } as *const u8);
            prefetch(unsafe { j.nodes.as_ptr().add(pair.1 as usize) } as *const u8);
            let due = std::mem::replace(&mut interned[at], pair);
            j.union(due.0, due.1);
        }
    }
    for due in read {
        if due.0 != 0 {
            let pair = (j.node(due.0, due.1), j.node(due.2, due.3));
            j.union(pair.0, pair.1);
        }
    }
    for due in interned {
        j.union(due.0, due.1);
    }
    let t_join = t_start.elapsed();

    // the intern map becomes the link map; a root maps to itself
    let n = j.n;
    let mut lbloom = Bloom::new(n + 16);
    let mut names = Map64::with_capacity(n / 2 + 16);
    let mut link = std::mem::replace(&mut j.idx, Map64::with_capacity(0));
    let cap = link.slots.len();
    for s in 0..cap {
        // slots behind s already hold keys, so never look back around
        let ahead = if s + NAME_AHEAD < cap { link.slots[s + NAME_AHEAD].1 } else { 0 };
        prefetch(j.nodes.as_ptr().wrapping_add(ahead as usize) as *const u8);
        let (key, node) = link.slots[s];
        if key == 0 {
            continue;
        }
        let root = j.find(node as u32);
        link.slots[s].1 = j.nodes[root as usize].key;
        if root != node as u32 {
            lbloom.insert(key);
        } else if key & PTAG != 0 {
            // only unencodable names need their bytes kept
            names.insert(key, j.srefs[root as usize]);
        }
    }
    if std::env::var("SS_TIMING").is_ok() {
        eprintln!(
            "  links: rows {} nodes {} join {:?} maps {:?}",
            rows,
            n,
            t_join,
            t_start.elapsed() - t_join
        );
    }
    Links { link, lbloom, names }
}

/// The vector scanner must agree with the scalar one on every byte pattern
/// that matters: delimiters at every offset, runs of them, lines shorter than
/// a block and lines longer than the mask. If it ever does not, the run falls
/// back to the scalar path rather than writing a wrong answer, and says so.
fn check_scan() -> bool {
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
    sys::stage("start");
    // the scanner check gates the small files; the rest runs beside them
    let nosimd = std::env::var_os("SS_NOSIMD").is_some();
    let scan_ok = !nosimd && check_scan();
    if !scan_ok {
        SIMD_OK.store(false, Ordering::Relaxed);
    }
    let wide_check = std::thread::spawn(move || !scan_ok || (split::agrees() && fast::wide_ok()));
    sys::stage("simd");
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
    sys::stage("list");
    let mut paths: Vec<PathBuf> = Vec::new();
    paths.extend(ev_files.iter().cloned());
    let ev_n = ev_files.len();
    paths.extend(cl_files.iter().cloned());
    let cl_n = cl_files.len();
    paths.extend(lk_files.iter().cloned());
    let lk_n = lk_files.len();
    paths.push(data.join("products.csv"));
    paths.push(data.join("campaigns.csv"));
    let maps: Vec<Map> = paths
        .iter()
        .map(|p| Map::open(p).unwrap_or(Map { ptr: std::ptr::NonNull::<u8>::dangling().as_ptr(), len: 0 }))
        .collect();
    let t_maps = t0.elapsed();
    sys::stage("maps");
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

    let t_pre = t0.elapsed();
    if std::env::var("SS_TIMING").is_ok() {
        eprintln!("  pre: maps {:?} meta {:?}", t_maps, t_pre - t_maps);
    }
    sys::stage("meta");
    if !wide_check.join().unwrap() {
        SIMD_OK.store(false, Ordering::Relaxed);
    }
    if !nosimd && !SIMD_OK.load(Ordering::Relaxed) {
        eprintln!("shopsess: vector scanner disagrees with the scalar one; using scalar");
    }
    let fkeys = fast::probe(&maps[i_ev.clone()], nt);
    sys::stage("probe");

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
        links: OnceLock::new(),
        no_links: Links {
            link: Map64::with_capacity(0),
            lbloom: Bloom::new(0),
            names: Map64::with_capacity(0),
        },
        links_gate: Mutex::new(()),
        links_cv: Condvar::new(),
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
        ctx.set_links(build_links(&ctx.maps, i_lk.clone()));
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
                        let lk = ctx.links();
                        let mut es = Sink::<ERec>::new(ar, nb_eid, BLK_E);
                        let mut dc = DateCache::new();
                        let mut ix = Box::new(split::Index::new());
                        let mut xn: Vec<(u64, u64)> = Vec::new();
                        loop {
                            let k = next.fetch_add(1, Ordering::Relaxed);
                            if k >= cks.len() {
                                break;
                            }
                            let (fi, a, b) = cks[k];
                            match lv {
                                1 => parse_events::<1>(ctx, lk, fi, a, b, &mut es, &mut dc, &mut ix, &mut xn),
                                2 => parse_events::<2>(ctx, lk, fi, a, b, &mut es, &mut dc, &mut ix, &mut xn),
                                3 => parse_events::<3>(ctx, lk, fi, a, b, &mut es, &mut dc, &mut ix, &mut xn),
                                4 => parse_events::<4>(ctx, lk, fi, a, b, &mut es, &mut dc, &mut ix, &mut xn),
                                5 => parse_events::<5>(ctx, lk, fi, a, b, &mut es, &mut dc, &mut ix, &mut xn),
                                6 => parse_events::<6>(ctx, lk, fi, a, b, &mut es, &mut dc, &mut ix, &mut xn),
                                _ => parse_events::<0>(ctx, lk, fi, a, b, &mut es, &mut dc, &mut ix, &mut xn),
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

    // ---- fast path; the stages below then see only what it left over
    let fast_out = match &fkeys {
        Some(k) => fast::run(&ctx, k, &arena, i_ev.clone(), i_cl.clone(), i_lk.clone(), nt),
        None => None,
    };
    sys::stage("ret");
    // no general parse or dedup workers when the fast path did the work
    let nt_gen = if fast_out.is_some() { 0 } else { nt };

    // ---- links + parse: worker 0 joins links while the rest parse events
    let link_delay: u64 = std::env::var("SS_LINK_DELAY").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
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
        let hs: Vec<_> = (0..nt_gen)
            .map(|t| {
                let next = &next;
                let chunks = &chunks;
                let ctx = &ctx;
                let arena = &arena;
                let arena_e = &arena_e;
                let i_lk = i_lk.clone();
                s.spawn(move || {
                    if t == 0 && ctx.links.get().is_none() {
                        // test hook: makes the others parse everything first
                        std::thread::sleep(std::time::Duration::from_millis(link_delay));
                        let links = build_links(&ctx.maps, i_lk);
                        ctx.set_links(links);
                        if std::env::var("SS_TIMING").is_ok() {
                            eprintln!("  pre {:?} links {:?} (overlapped)", t_pre, t0.elapsed() - t_pre);
                        }
                    }
                    // until the link map exists, events are written as users
                    let mut as_users = t != 0;
                    let mut es = Sink::<ERec>::new(arena_e, nb_eid, BLK_E);
                    let mut cs = Sink::<CRec>::new(arena, nb_per, BLK_P);
                    let mut dc = DateCache::new();
                    let mut ix = Box::new(split::Index::new());
                    let mut xn: Vec<(u64, u64)> = Vec::new();
                    loop {
                        let k = next.fetch_add(1, Ordering::Relaxed);
                        if k >= chunks.len() {
                            break;
                        }
                        let (kind, fi, a, b) = chunks[k];
                        let tc = std::time::Instant::now();
                        if kind == 0 {
                            if as_users && ctx.links.get().is_some() {
                                LKH.fetch_add(resolve_written(ctx.links(), &mut es), Ordering::Relaxed);
                                as_users = false;
                            }
                            let lk = if as_users { &ctx.no_links } else { ctx.links() };
                            parse_events::<0>(ctx, lk, fi as usize, a, b, &mut es, &mut dc, &mut ix, &mut xn);
                            NS_EV.fetch_add(tc.elapsed().as_nanos() as usize, Ordering::Relaxed);
                        } else {
                            // clicks are scattered by person
                            ctx.wait_links();
                            let tc = std::time::Instant::now();
                            parse_clicks(ctx, fi as usize, a, b, &mut cs, &mut dc, &mut ix);
                            NS_CL.fetch_add(tc.elapsed().as_nanos() as usize, Ordering::Relaxed);
                        }
                    }
                    if as_users {
                        ctx.wait_links();
                        LKH.fetch_add(resolve_written(ctx.links(), &mut es), Ordering::Relaxed);
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
    if let Some(f) = &fast_out {
        xraw.extend_from_slice(&f.xn);
    }
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
        let hs: Vec<_> = (0..nt_gen)
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
    // fold threads write the fast path's rows: one barrier, one integer width
    let (pbuckets, cbuckets, mut fast_outs) = match fast_out {
        Some(f) => (f.pb, f.cb, f.outs.into_iter().map(Some).collect::<Vec<_>>()),
        None => (pbuckets, cbuckets, Vec::new()),
    };
    let porder = order_by_size(&pbuckets);
    let t_dedup = t0.elapsed();
    sys::stage("tail");

    // ---- fold + write user_daily
    let ud = outdir.join("user_daily");
    let cdd = outdir.join("campaign_daily");
    std::fs::create_dir_all(&ud).unwrap();
    std::fs::create_dir_all(&cdd).unwrap();
    let stride = ctx.ndays + 2;
    let next = AtomicUsize::new(0);
    let rows: usize = pbuckets.iter().flatten().map(|b| b.len as usize).sum();
    let rows_per_thread = rows / nt + 4096;
    let all_bits = std::sync::atomic::AtomicU64::new(0);
    let folded = std::sync::Barrier::new(nt + 1);
    let cds: std::sync::Mutex<Vec<Vec<CD>>> = std::sync::Mutex::new(Vec::new());
    let mut nrows_tot: usize = 0;
    let mut t_fold = t_dedup;
    let mut n = 0;
    std::thread::scope(|s| {
        let hs: Vec<_> = (0..nt)
            .map(|t| {
                let next = &next;
                let pbuckets = &pbuckets;
                let cbuckets = &cbuckets;
                let porder = &porder;
                let ctx = &ctx;
                let ud = &ud;
                let all_bits = &all_bits;
                let folded = &folded;
                let cds = &cds;
                let fast_o = fast_outs.get_mut(t).and_then(Option::take);
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
                        t: Tmp::new(ctx),
                        o: fast_o.unwrap_or_else(|| Out::new(rows_per_thread, (ctx.ncamp + 1) * stride)),
                    };
                    loop {
                        let k = next.fetch_add(1, Ordering::Relaxed);
                        if k >= nb_per {
                            break;
                        }
                        let k = porder[k];
                        fold_bucket(ctx, xnames, &mut f, &pbuckets[k], &cbuckets[k]);
                    }
                    // every file must use the same integer type, so agree on it
                    all_bits.fetch_or(f.o.all_bits, Ordering::Relaxed);
                    cds.lock().unwrap().push(f.o.campaign_days());
                    folded.wait();
                    let n = f.o.day.len();
                    if n > 0 {
                        let narrow = Out::fits_i32(all_bits.load(Ordering::Relaxed));
                        f.o.write(&ud.join(format!("part-{:02}.parquet", t)), &ctx.cats, narrow).unwrap();
                    }
                    n
                })
            })
            .collect();
        // campaign_daily is written while the threads write user_daily
        folded.wait();
        t_fold = t0.elapsed();
        let cds = std::mem::take(&mut *cds.lock().unwrap());
        n = write_campaign_daily(&ctx, &camp_name, cds, &cdd.join("part-00.parquet"));
        for h in hs {
            nrows_tot += h.join().unwrap();
        }
    });
    sys::stage("write");
    if nrows_tot == 0 {
        Out::new(0, 0).write(&ud.join("part-00.parquet"), &ctx.cats, true).unwrap();
    }

    if std::env::var("SS_TIMING").is_ok() {
        let total = t0.elapsed();
        eprintln!(
            "parse {:?}  dedup {:?}  fold {:?}  write {:?}  total {:?}  rows {} / {}",
            t_parse,
            t_dedup - t_parse,
            t_fold - t_dedup,
            total - t_fold,
            total,
            nrows_tot,
            n
        );
    }
    if std::env::var_os("SS_MEM").is_some() {
        if let Ok(s) = std::fs::read_to_string("/proc/self/smaps_rollup") {
            let kb = |k: &str| -> u64 {
                s.lines()
                    .find(|l| l.starts_with(k))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0)
            };
            let (anon, huge) = (kb("Anonymous:"), kb("AnonHugePages:"));
            eprintln!(
                "at exit: rss {} MB, anonymous {} MB of which 4K pages {} MB; {} huge blocks mapped, {} MB",
                kb("Rss:") >> 10,
                anon >> 10,
                (anon - huge.min(anon)) >> 10,
                HUGE_BLOCKS.load(Ordering::Relaxed),
                HUGE_BYTES.load(Ordering::Relaxed) >> 20
            );
        }
    }
    if std::env::var_os("SS_KEEPMAPS").is_none() {
        sys::drop_pages(&ctx.maps, nt);
    }
    // both tables are closed: let the kernel free everything at once
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    const NCAMP: usize = 6;
    const NCAT: usize = 4;

    fn rnd(x: &mut u64) -> u64 {
        *x ^= *x << 13;
        *x ^= *x >> 7;
        *x ^= *x << 17;
        *x
    }

    /// a 14-day window whose click ids are 6 bytes each in one buffer
    fn test_ctx(ids: &'static [u8]) -> Ctx {
        let ws = 20_000 * DAY_MS;
        let we = ws + 14 * DAY_MS;
        Ctx {
            maps: vec![Map { ptr: ids.as_ptr(), len: ids.len() }],
            ev_lo: ws,
            ev_hi: we,
            cl_lo: ws - WEEK_MS,
            cl_hi: we,
            base: ws - WEEK_MS,
            day0: ws / DAY_MS,
            ndays: 14,
            links: OnceLock::new(),
            no_links: Links { link: Map64::with_capacity(0), lbloom: Bloom::new(0), names: Map64::with_capacity(0) },
            links_gate: Mutex::new(()),
            links_cv: Condvar::new(),
            prod: Vec::new(),
            prod_extra: None,
            camp: Vec::new(),
            camp_extra: None,
            ncamp: NCAMP,
            cats: (0..NCAT).map(|c| vec![b'a' + c as u8]).collect(),
            unknown_cat: 0,
            chan: vec![0; NCAMP],
            chans: vec![b"x".to_vec()],
            eid_bits: 0,
            per_bits: 0,
        }
    }

    type Cells = BTreeMap<(usize, usize), (u32, u32, u64, u32)>;
    type Rows = Vec<(i32, i64, i64, i64, u8)>;

    /// the rules, one session and one click at a time
    fn by_the_rules(ctx: &Ctx, ev: &[PRec], cl: &[CRec]) -> (Cells, Rows) {
        let mut cells = Cells::new();
        let mut days: BTreeMap<i64, (i64, i64, i64, BTreeMap<u32, u64>)> = BTreeMap::new();
        let mut i = 0;
        while i < ev.len() {
            let mut j = i + 1;
            while j < ev.len() && ev[j].ts - ev[j - 1].ts <= GAP_MS {
                j += 1;
            }
            let start = ev[i].ts;
            let day = (ctx.base + start as i64).div_euclid(DAY_MS) - ctx.day0;
            let d = days.entry(day).or_default();
            d.0 += 1;
            d.1 += (j - i) as i64;
            let (mut rev, mut pur) = (0u64, 0u32);
            for e in &ev[i..j] {
                if e.pc != 0 {
                    rev += (e.pc & 0xff_ffff) as u64;
                    pur = 1;
                    *d.3.entry(e.pc >> 24).or_default() += (e.pc & 0xff_ffff) as u64;
                }
            }
            d.2 += rev as i64;
            let ok: Vec<&CRec> = cl.iter().filter(|c| c.ts <= start && start - c.ts <= WEEK).collect();
            let camp = match ok.iter().map(|c| c.ts).max() {
                None => ctx.ncamp,
                Some(t) => ok.iter().filter(|c| c.ts == t).min_by_key(|c| ctx.bytes(c.sref)).unwrap().camp as usize,
            };
            let e = cells.entry((camp, day as usize)).or_default();
            e.0 += 1;
            e.1 += pur;
            e.2 += rev;
            for c in ok.iter().map(|c| c.camp as usize).collect::<BTreeSet<_>>() {
                cells.entry((c, day as usize)).or_default().3 += 1;
            }
            i = j;
        }
        let rows = days
            .into_iter()
            .map(|(day, (s, e, r, cats))| {
                let top = cats.iter().map(|(&c, &v)| (v, std::cmp::Reverse(c))).max().map_or(CAT_NONE as u8, |(_, c)| c.0 as u8);
                ((ctx.day0 + day) as i32, s, e, r, top)
            })
            .collect();
        (cells, rows)
    }

    fn cells_of(ctx: &Ctx, o: &Out) -> Cells {
        let stride = ctx.ndays + 2;
        let mut cells = Cells::new();
        for (i, c) in o.peek_campaign_days().iter().enumerate() {
            let a = c.assist;
            if c.sessions != 0 || c.purch != 0 || c.rev != 0 || a != 0 {
                cells.insert((i / stride, i % stride), (c.sessions, c.purch, c.rev, a));
            }
        }
        cells
    }

    fn person(x: &mut u64, big: bool) -> (Vec<PRec>, Vec<CRec>) {
        let span = (21 * DAY_MS) as u64;
        let gap = GAP_MS as u64;
        let n = if big { 100 + rnd(x) % 500 } else { 1 + rnd(x) % 40 };
        let mut ev = Vec::new();
        let mut ts = WEEK as u64 + rnd(x) % (3 * DAY_MS as u64);
        for _ in 0..n {
            ts += match rnd(x) % 12 {
                0 | 1 => 0,
                2 => 1,
                3 | 4 => rnd(x) % 60_000,
                5 => gap - 1,
                6 | 7 => gap,
                8 => gap + 1,
                9 => 2 * gap + rnd(x) % (8 * gap),
                10 => rnd(x) % (if big { 3 * gap } else { 3 * DAY_MS as u64 }),
                _ => rnd(x) % (2 * gap),
            };
            if ts >= span {
                break;
            }
            let pc = if rnd(x) % 5 == 0 { (((rnd(x) % NCAT as u64) as u32) << 24) | (1 + rnd(x) % 3) as u32 * 100 } else { 0 };
            ev.push(PRec { person: 0, ts: ts as u32, pc });
        }
        let m = match rnd(x) % 8 {
            0 => 0,
            1 => 1,
            7 if big => 300 + rnd(x) % 300,
            _ => rnd(x) % 30,
        };
        let week = WEEK as i64;
        let mut cl = Vec::new();
        for _ in 0..m {
            let at = ev[(rnd(x) % ev.len() as u64) as usize].ts as i64;
            let t = at
                + match rnd(x) % 12 {
                    0 => 0,
                    1 => 1,
                    2 => -1,
                    3 => -week,
                    4 => -week - 1,
                    5 => -week + 1,
                    6 | 7 => -((rnd(x) % WEEK as u64) as i64),
                    8 => -((rnd(x) % (2 * WEEK as u64)) as i64),
                    9 => (rnd(x) % gap) as i64,
                    _ => -((rnd(x) % DAY_MS as u64) as i64),
                };
            let t = t.clamp(0, span as i64 - 1) as u32;
            // the id is 6 bytes of the buffer
            let id = (rnd(x) % 4096) as usize;
            cl.push(CRec { person: 0, sref: sref_of(0, id * 6, 6), ts: t, camp: (rnd(x) % NCAMP as u64) as u32 });
        }
        // a click id appears once
        let mut seen = BTreeSet::new();
        cl.retain(|c| seen.insert(c.sref));
        cl.sort_by_key(|c| c.ts);
        (ev, cl)
    }

    #[test]
    fn a_person_follows_the_rules() {
        // 4096 distinct ids in a scrambled order
        let mut ids = Vec::new();
        for i in 0..4096u32 {
            ids.extend_from_slice(format!("c{:05}", (i * 2731) % 4096 * 17).as_bytes());
        }
        let ctx = test_ctx(Box::leak(ids.into_boxed_slice()));
        let cd_len = (ctx.ncamp + 1) * (ctx.ndays + 2);
        let mut t = Tmp::new(&ctx);
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let (mut small, mut large, mut tied) = (0, 0, 0);
        for round in 0..6000 {
            let (ev, cl) = person(&mut x, round % 20 == 0);
            if ev.is_empty() {
                continue;
            }
            let (cells, rows) = by_the_rules(&ctx, &ev, &cl);
            let mut o = Out::new(64, cd_len);
            process_person(&ctx, &ev, &cl, &mut t, &mut o, b"u1");
            assert_eq!(cells_of(&ctx, &o), cells, "round {}", round);
            let got: Rows = (0..o.day.len()).map(|i| (o.day[i], o.sessions[i], o.events[i], o.rev[i], o.cat[i])).collect();
            assert_eq!(got, rows, "round {}", round);
            let ns = t.ss.len();
            if ns <= SMALL {
                small += 1;
            } else {
                large += 1;
            }
            tied += cl.windows(2).filter(|w| w[0].ts == w[1].ts).count();
            // the general walk agrees on a person the masks took
            if !cl.is_empty() {
                let mut o2 = Out::new(64, cd_len);
                assert_eq!(sessionize(&ctx, &ev, &mut t, &mut o2, b"u1"), ns);
                attribute_any(&ctx, &cl, &mut t, &mut o2);
                assert_eq!(cells_of(&ctx, &o2), cells, "round {} by the general walk", round);
            }
            // and the masks do not need the clicks in order
            if !cl.is_empty() && ns <= SMALL {
                let mut mixed = cl.clone();
                for i in (1..mixed.len()).rev() {
                    mixed.swap(i, (rnd(&mut x) % (i as u64 + 1)) as usize);
                }
                let mut o3 = Out::new(64, cd_len);
                assert_eq!(sessionize(&ctx, &ev, &mut t, &mut o3, b"u1"), ns);
                attribute_small(&ctx, &mixed, 0, &mut t, &mut o3);
                assert_eq!(cells_of(&ctx, &o3), cells, "round {} with the clicks out of order", round);
            }
            assert!(t.cm.iter().all(|&m| m == 0) && t.bidx.iter().all(|&b| b == NO_CLICK), "round {} left state behind", round);
        }
        assert!(small > 1000 && large > 100 && tied > 1000, "{} {} {}", small, large, tied);
    }

    #[test]
    fn click_against_eight_starts() {
        let mut x = 0x1234_5678_9abc_def1u64;
        let pick = |x: &mut u64| match rnd(x) % 4 {
            0 => (rnd(x) % 8) as u32,
            1 => u32::MAX - (rnd(x) % 8) as u32,
            2 => 0x7fff_fffcu32 + (rnd(x) % 8) as u32,
            _ => rnd(x) as u32,
        };
        for _ in 0..50_000 {
            let mut ss = [0u32; 8];
            for e in ss.iter_mut() {
                *e = pick(&mut x);
            }
            // a few clicks in a row over the same state, both ways
            let (mut ka, mut ia) = ([0u32; 8], [NO_CLICK; 8]);
            let (mut kb, mut ib) = (ka, ia);
            for k in 0..6u32 {
                let (lo, hi) = (pick(&mut x), pick(&mut x));
                let a = unsafe {
                    let (mut bk, mut bi) = (load8(ka.as_ptr()), load8(ia.as_ptr()));
                    let r = click8(load8(ss.as_ptr()), &mut bk, &mut bi, lo, hi, k);
                    store8(ka.as_mut_ptr(), bk);
                    store8(ia.as_mut_ptr(), bi);
                    r
                };
                let b = click8_plain(&ss, &mut kb, &mut ib, lo, hi, k);
                assert_eq!(a, b, "{:?} {} {}", ss, lo, hi);
                assert_eq!((ka, ia), (kb, ib), "{:?} {} {}", ss, lo, hi);
                let ge: u64 = (0..8).map(|i| ((ss[i] >= lo) as u64) << i).sum();
                let le: u64 = (0..8).map(|i| ((ss[i] <= hi) as u64) << i).sum();
                assert_eq!((a.0, a.1), (ge, le));
            }
        }
    }
}
