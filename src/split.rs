// Row splitting in two passes. The first turns a stretch of input into the
// offsets of its commas and newlines plus two bit streams (which delimiters
// are newlines, which fields open with a quote), 64 bytes at a time and with
// no branch that depends on the data. The second lifts whole rows off that
// index: one test for "exactly N fields", one vector add for all the spans.
//
// Quote rules are settled in the first pass too. A quote is in order only
// next to exactly one delimiter, and a field that opens with one must close
// with one; a block where either fails is noted, and every line touching a
// noted block goes through `scan_line` and `fields`, which stay the
// definition of the dialect. So do the last lines of a file, and everything
// when the target lacks AVX2 and BMI2 or the startup check disagrees.
use crate::{fields, scan_line};

/// Blocks per batch: 8 KiB of input, so the index stays in L1.
const NBLK: usize = 128;
const NPOS: usize = NBLK * 64 + 24;
const NBIT: usize = NBLK + 4;

#[cfg_attr(not(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "bmi2")), allow(dead_code))]
pub struct Index {
    pos: [u32; NPOS],     // pos[0] is a sentinel; delimiter k is at pos[k + 1]
    qs: [u64; NBIT],      // bit k: the field after delimiter k - 1 opens with a quote
    ns: [u64; NBIT],      // bit k: delimiter k - 1 is a newline
    bad: [u32; NBLK + 1], // blocks with a misplaced quote, then u32::MAX
    nd: usize,            // delimiters indexed
}

impl Index {
    #[inline(always)]
    pub fn new() -> Index {
        Index { pos: [0; NPOS], qs: [0; NBIT], ns: [0; NBIT], bad: [u32::MAX; NBLK + 1], nd: 0 }
    }
}

/// One line through the reference splitter; returns where the next starts.
#[cfg_attr(
    all(target_arch = "x86_64", target_feature = "avx2", target_feature = "bmi2"),
    inline(never)
)]
fn one_line<const N: usize, F: FnMut(usize, &[u32; 8], &[u32; 8])>(
    d: &[u8],
    p: usize,
    simd: bool,
    f: &mut F,
) -> usize {
    let sc = scan_line(d, p, simd);
    let line = &d[p..sc.nl];
    if let Some(fs) = fields::<N>(line, &sc) {
        let mut st = [0u32; 8];
        let mut en = [0u32; 8];
        for k in 0..N {
            st[k] = fs[k].0;
            en[k] = fs[k].1;
        }
        f(p, &st, &en);
    }
    sc.nl + 1
}

/// Calls `f(base, starts, ends)` for every well-formed `N`-field line that
/// starts in `[p, to)`; field `k` is `d[base + starts[k]..base + ends[k]]`
/// with its quotes already off. `p` must be the start of a line.
#[inline(always)]
pub fn each_row<const N: usize, F: FnMut(usize, &[u32; 8], &[u32; 8])>(
    d: &[u8],
    mut p: usize,
    to: usize,
    simd: bool,
    ix: &mut Index,
    mut f: F,
) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "bmi2"))]
    if simd && N >= 2 && N <= 8 {
        while p < to {
            // one block past the batch is read for lookahead and has to exist
            let room = (d.len() - p) / 64;
            if room < 2 {
                break;
            }
            let want = (to - p + 63) / 64 + 2;
            let nblk = want.min(NBLK).min(room - 1);
            let used = unsafe {
                fast::index(d.as_ptr().add(p), nblk, ix);
                fast::rows::<N, F>(d, p, to, ix, &mut f)
            };
            p = if used == 0 { one_line::<N, F>(d, p, simd, &mut f) } else { p + used };
        }
    }
    let _ = &ix;
    while p < to {
        p = one_line::<N, F>(d, p, simd, &mut f);
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "bmi2"))]
mod fast {
    use super::*;
    use core::arch::x86_64::*;

    /// Delimiters, quotes and newlines in 64 bytes, one bit per byte.
    #[cfg(not(all(target_feature = "avx512bw", target_feature = "avx512vl")))]
    #[inline(always)]
    unsafe fn masks(p: *const u8) -> (u64, u64, u64) {
        let a = _mm256_loadu_si256(p as *const __m256i);
        let b = _mm256_loadu_si256(p.add(32) as *const __m256i);
        let m = |c: u8| -> u64 {
            let k = _mm256_set1_epi8(c as i8);
            let lo = _mm256_movemask_epi8(_mm256_cmpeq_epi8(a, k)) as u32 as u64;
            let hi = _mm256_movemask_epi8(_mm256_cmpeq_epi8(b, k)) as u32 as u64;
            lo | (hi << 32)
        };
        let n = m(b'\n');
        (m(b',') | n, m(b'"'), n)
    }

    /// The same with compares that write mask registers, still 256 bits
    /// wide: the halves are joined there and cross to a general register once.
    #[cfg(all(target_feature = "avx512bw", target_feature = "avx512vl"))]
    #[inline(always)]
    unsafe fn masks(p: *const u8) -> (u64, u64, u64) {
        let a = _mm256_loadu_si256(p as *const __m256i);
        let b = _mm256_loadu_si256(p.add(32) as *const __m256i);
        let (kc, kq, kn) = (_mm256_set1_epi8(b',' as i8), _mm256_set1_epi8(b'"' as i8), _mm256_set1_epi8(b'\n' as i8));
        let (n0, n1) = (_mm256_cmpeq_epi8_mask(a, kn), _mm256_cmpeq_epi8_mask(b, kn));
        let d0 = _kor_mask32(_mm256_cmpeq_epi8_mask(a, kc), n0);
        let d1 = _kor_mask32(_mm256_cmpeq_epi8_mask(b, kc), n1);
        let (q0, q1) = (_mm256_cmpeq_epi8_mask(a, kq), _mm256_cmpeq_epi8_mask(b, kq));
        (
            _cvtmask64_u64(_mm512_kunpackd(d1 as __mmask64, d0 as __mmask64)),
            _cvtmask64_u64(_mm512_kunpackd(q1 as __mmask64, q0 as __mmask64)),
            _cvtmask64_u64(_mm512_kunpackd(n1 as __mmask64, n0 as __mmask64)),
        )
    }

    /// Index `nblk` blocks from `base`, which must follow a newline. Reads
    /// one block further. Kept out of line so its vector constants are not
    /// live, and reloaded, across the row loop.
    #[inline(never)]
    pub unsafe fn index(base: *const u8, nblk: usize, ix: &mut Index) {
        let pos = ix.pos.as_mut_ptr();
        let qs = ix.qs.as_mut_ptr();
        let ns = ix.ns.as_mut_ptr();
        let bad = ix.bad.as_mut_ptr();
        *qs = 0;
        *ns = 0;
        // Each turn loads one block and finishes the one before it, which
        // needs the first bit of its successor. The turn before the first
        // block finishes the newline that precedes `base`, as a block with
        // only its last byte set: that writes the sentinel and the first
        // field's quote bit with no code of its own.
        let (mut d, mut q, mut n) = (1u64 << 63, 0u64, 1u64 << 63);
        let mut open = 0u64; // the last delimiter is followed by a quote
        let mut dprev = 0u64; // the byte before this block is a delimiter
        let mut qprev = 0u64; // ... is a quote
        let mut nd = 0usize;
        let mut nbad = 0usize;
        let mut at = base;
        let end = base.add(nblk * 64);
        let mut off = 0u32.wrapping_sub(64);
        loop {
            let (d1, q1, n1) = masks(at);
            let opens = d & ((q >> 1) | (q1 << 63));
            let closes = d & ((q << 1) | qprev);
            let after = (d << 1) | dprev;
            let before = (d >> 1) | (d1 << 63);
            let stray = q & !(after ^ before);
            qprev = q >> 63;
            dprev = d >> 63;
            let cnt = d.count_ones() as usize;
            // one bit per delimiter from here on
            let a = _pext_u64(opens, d);
            let b = _pext_u64(closes, d);
            let nlb = _pext_u64(n, d);
            // bit cnt of x is the last delimiter's, or the old one with none
            let x = (a << 1) | open;
            let unpaired = _bzhi_u64(x ^ b, cnt as u32);
            open = x >> (cnt & 63);
            if cnt == 64 {
                open = a >> 63;
            }
            let w = nd >> 6;
            let sh = nd & 63;
            *qs.add(w) |= a << sh;
            *qs.add(w + 1) = (a >> 1) >> (63 - sh);
            *ns.add(w) |= nlb << sh;
            *ns.add(w + 1) = (nlb >> 1) >> (63 - sh);
            if (stray | unpaired) != 0 {
                *bad.add(nbad) = off;
                nbad += 1;
            }
            // volatile keeps these eight scalar: left alone they are packed
            // into a 512-bit vector, which costs more and lowers the clock
            let out = pos.add(nd);
            let mut m = d;
            for k in 0..8 {
                out.add(k).write_volatile(off.wrapping_add(m.trailing_zeros()));
                m &= m.wrapping_sub(1);
            }
            if cnt > 8 {
                let mut k = 8;
                while m != 0 {
                    *out.add(k) = off + m.trailing_zeros();
                    m &= m - 1;
                    k += 1;
                }
            }
            nd += cnt;
            d = d1;
            q = q1;
            n = n1;
            if at == end {
                break;
            }
            at = at.add(64);
            off = off.wrapping_add(64);
        }
        // rows read the streams eight bytes at a time, a little past the end
        let w = nd >> 6;
        *qs.add(w + 1) = 0;
        *ns.add(w + 1) = 0;
        *bad.add(nbad) = u32::MAX;
        ix.nd = nd - 1;
    }

    /// The first newline at or after delimiter `i`.
    #[cold]
    #[inline(never)]
    fn next_newline(ix: &Index, i: usize) -> Option<usize> {
        let mut j = i;
        while j < ix.nd {
            if (ix.ns[(j + 1) >> 6] >> ((j + 1) & 63)) & 1 != 0 {
                return Some(j);
            }
            j += 1;
        }
        None
    }

    /// Hand out the rows of the batch indexed at `p`; returns the bytes used.
    #[inline(always)]
    pub unsafe fn rows<const N: usize, F: FnMut(usize, &[u32; 8], &[u32; 8])>(
        d: &[u8],
        p: usize,
        to: usize,
        ix: &Index,
        f: &mut F,
    ) -> usize {
        let pos = ix.pos.as_ptr();
        let qs = ix.qs.as_ptr() as *const u8;
        let ns = ix.ns.as_ptr() as *const u8;
        let bad = ix.bad.as_ptr();
        let lim = (to - p).min(u32::MAX as usize) as u32;
        let mut bi = 0usize;
        let mut next_bad = *bad;
        let mut i = 0usize; // the line's first delimiter
        let mut ls = 0u32; // and its first byte
        let mut st = [0u32; 8];
        let mut en = [0u32; 8];
        let bits = _mm256_setr_epi32(1, 2, 4, 8, 16, 32, 64, 128);
        let ones = _mm256_set1_epi32(-1);
        while ls < lim {
            let o = i >> 3;
            let sh = (i & 7) as u32;
            let nw = (std::ptr::read_unaligned(ns.add(o) as *const u64) >> sh) >> 1;
            if nw.trailing_zeros() as usize != N - 1 {
                // wrong field count, or the line runs out of the batch
                match next_newline(ix, i) {
                    Some(e) => {
                        i = e + 1;
                        ls = (*pos.add(i)).wrapping_add(1);
                        continue;
                    }
                    None => break,
                }
            }
            let e = i + N;
            let nl = *pos.add(e);
            if nl >= next_bad {
                one_line::<N, F>(d, p + ls as usize, true, f);
                // a block that reaches past this line taints the next one too
                while next_bad != u32::MAX && next_bad + 64 <= nl + 1 {
                    bi += 1;
                    next_bad = *bad.add(bi);
                }
                i = e;
                ls = nl + 1;
                continue;
            }
            let pv = _mm256_loadu_si256(pos.add(i) as *const __m256i);
            let ev = _mm256_loadu_si256(pos.add(i + 1) as *const __m256i);
            let qw = (std::ptr::read_unaligned(qs.add(o) as *const u64) >> sh) as i32;
            // one past the delimiter before, two past it behind a quote
            #[cfg(all(target_feature = "avx512f", target_feature = "avx512vl"))]
            let (sv, ee) = {
                let _ = bits;
                let k = qw as u8;
                let sv = _mm256_sub_epi32(pv, ones);
                (_mm256_mask_sub_epi32(sv, k, sv, ones), _mm256_mask_add_epi32(ev, k, ev, ones))
            };
            #[cfg(not(all(target_feature = "avx512f", target_feature = "avx512vl")))]
            let (sv, ee) = {
                let qm = _mm256_cmpeq_epi32(_mm256_and_si256(_mm256_set1_epi32(qw), bits), bits);
                (_mm256_sub_epi32(_mm256_sub_epi32(pv, ones), qm), _mm256_add_epi32(ev, qm))
            };
            _mm256_storeu_si256(st.as_mut_ptr() as *mut __m256i, sv);
            _mm256_storeu_si256(en.as_mut_ptr() as *mut __m256i, ee);
            f(p, &st, &en);
            i = e;
            ls = nl + 1;
        }
        ls as usize
    }
}

// ---------------------------------------------------------- one row at a time

/// bytes a row reader may touch, counted from the row start
#[allow(dead_code)]
pub const REACH: usize = 128;

/// one line through the reference splitter; returns where the next starts
#[inline(always)]
pub fn line<const N: usize, F: FnMut(usize, &[u32; 8], &[u32; 8])>(d: &[u8], p: usize, simd: bool, f: &mut F) -> usize {
    one_line::<N, F>(d, p, simd, f)
}

/// content starts and ends of the fields in a 64-byte window, a bit each
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub struct Win {
    pub s: u64,
    pub e: u64,
}

impl Win {
    /// the span of the next field
    #[allow(dead_code)]
    #[inline(always)]
    pub fn next(&mut self) -> (usize, usize) {
        let r = (self.s.trailing_zeros() as usize, self.e.trailing_zeros() as usize);
        self.s &= self.s.wrapping_sub(1);
        self.e &= self.e.wrapping_sub(1);
        r
    }
}

/// none unless every quote in `q` wraps a whole field ended by a bit of `d`
#[allow(dead_code)]
#[inline(always)]
fn wrap(d: u64, q: u64) -> Option<Win> {
    let after = (d << 1) | 1;
    let open = q & after;
    // the borrow of an opening quote clears its field's delimiter
    let close = (d & !d.wrapping_sub(open)) >> 1;
    if open.wrapping_add(close) != q {
        return None;
    }
    Some(Win { s: after.wrapping_add(open), e: d.wrapping_sub(close) })
}

/// the fields the first `K` commas close, and where the last comma is
#[allow(dead_code)]
#[inline(always)]
pub fn head<const K: usize>(c: u64, q: u64, n: u64) -> Option<(Win, usize)> {
    let mut t = c;
    for _ in 1..K {
        t &= t.wrapping_sub(1);
    }
    if t == 0 {
        return None;
    }
    let upto = t ^ t.wrapping_sub(1);
    if n & upto != 0 {
        return None;
    }
    let w = wrap(c & upto, q & upto)?;
    Some((w, t.trailing_zeros() as usize))
}

/// the fields up to a newline that exactly `K` commas precede, and where it is
#[allow(dead_code)]
#[inline(always)]
pub fn tail<const K: u32>(c: u64, q: u64, n: u64) -> Option<(Win, usize)> {
    if n == 0 {
        return None;
    }
    let upto = n ^ n.wrapping_sub(1);
    if (c & upto).count_ones() != K {
        return None;
    }
    let w = wrap((c | n) & upto, q & upto)?;
    Some((w, n.trailing_zeros() as usize))
}

/// two 32-bit compare masks as one word, the first in the low half
#[cfg(all(target_arch = "x86_64", target_feature = "avx512bw", target_feature = "avx512vl"))]
#[inline(always)]
unsafe fn join(lo: u32, hi: u32) -> u64 {
    // spelled out: left to the compiler the two compares become one on a 512-bit register
    let m: u64;
    core::arch::asm!("kunpckdq {m}, {hi}, {lo}", m = lateout(kreg) m, hi = in(kreg) hi, lo = in(kreg) lo, options(pure, nomem, nostack, preserves_flags));
    m
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "bmi1", target_feature = "bmi2"))]
#[inline(always)]
unsafe fn eq2(a: core::arch::x86_64::__m256i, b: core::arch::x86_64::__m256i, k: core::arch::x86_64::__m256i) -> (u32, u32) {
    use core::arch::x86_64::*;
    #[cfg(all(target_feature = "avx512bw", target_feature = "avx512vl"))]
    return (_mm256_cmpeq_epi8_mask(a, k), _mm256_cmpeq_epi8_mask(b, k));
    #[cfg(not(all(target_feature = "avx512bw", target_feature = "avx512vl")))]
    return (_mm256_movemask_epi8(_mm256_cmpeq_epi8(a, k)) as u32, _mm256_movemask_epi8(_mm256_cmpeq_epi8(b, k)) as u32);
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "bmi1", target_feature = "bmi2", not(all(target_feature = "avx512bw", target_feature = "avx512vl"))))]
#[inline(always)]
unsafe fn join(lo: u32, hi: u32) -> u64 {
    lo as u64 | ((hi as u64) << 32)
}

/// comma, quote and newline, each spread over a vector
#[cfg(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "bmi1", target_feature = "bmi2"))]
#[derive(Clone, Copy)]
pub struct Cut(core::arch::x86_64::__m256i, core::arch::x86_64::__m256i, core::arch::x86_64::__m256i);

#[cfg(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "bmi1", target_feature = "bmi2"))]
impl Cut {
    /// hidden from the compiler, which would rebuild a known constant at every use
    #[inline(always)]
    pub fn new() -> Cut {
        use core::arch::x86_64::*;
        let f = |c: u8| std::hint::black_box(unsafe { _mm256_set1_epi8(c as i8) });
        Cut(f(b','), f(b'"'), f(b'\n'))
    }
}

/// commas, quotes and newlines of 64 bytes, a bit each
#[cfg(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "bmi1", target_feature = "bmi2"))]
#[inline(always)]
pub unsafe fn masks(p: *const u8, k: &Cut) -> (u64, u64, u64) {
    use core::arch::x86_64::*;
    let a = _mm256_loadu_si256(p as *const __m256i);
    let b = _mm256_loadu_si256(p.add(32) as *const __m256i);
    let m = |k: __m256i| -> u64 {
        let (lo, hi) = eq2(a, b, k);
        join(lo, hi)
    };
    (m(k.0), m(k.1), m(k.2))
}

/// the same, but every bit of the last is set when any byte is a newline
#[cfg(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "bmi1", target_feature = "bmi2"))]
#[inline(always)]
pub unsafe fn masks_any(p: *const u8, k: &Cut) -> (u64, u64, u64) {
    use core::arch::x86_64::*;
    let a = _mm256_loadu_si256(p as *const __m256i);
    let b = _mm256_loadu_si256(p.add(32) as *const __m256i);
    let m = |k: __m256i| -> u64 {
        let (lo, hi) = eq2(a, b, k);
        join(lo, hi)
    };
    let (lo, hi) = eq2(a, b, k.2);
    #[cfg(all(target_feature = "avx512bw", target_feature = "avx512vl"))]
    let none = _kortestz_mask32_u8(lo, hi) != 0;
    #[cfg(not(all(target_feature = "avx512bw", target_feature = "avx512vl")))]
    let none = lo | hi == 0;
    (m(k.0), m(k.1), if none { 0 } else { !0 })
}

/// the same masks a byte at a time, for checking the vector ones
#[allow(dead_code)]
pub fn masks_sw(b: &[u8]) -> (u64, u64, u64) {
    let (mut c, mut q, mut n) = (0u64, 0u64, 0u64);
    for (i, &x) in b.iter().take(64).enumerate() {
        c |= ((x == b',') as u64) << i;
        q |= ((x == b'"') as u64) << i;
        n |= ((x == b'\n') as u64) << i;
    }
    (c, q, n)
}

/// spans of a seven-field row: three fields from `p`, four from past the third comma
#[allow(dead_code)]
#[inline(always)]
pub fn row7(w0: (u64, u64, u64), w1: impl FnOnce(usize) -> (u64, u64, u64)) -> Option<(Win, Win, usize, usize)> {
    let (a, p3) = head::<3>(w0.0, w0.1, w0.2)?;
    let m = w1(p3 + 1);
    let (b, nl) = tail::<3>(m.0, m.1, m.2)?;
    Some((a, b, p3 + 1, nl))
}

/// rows as the fast path takes them: windows where they fit, the reference elsewhere
#[allow(dead_code)]
fn collect_win<const N: usize>(d: &[u8], cuts: &[usize], vector: bool) -> Vec<[usize; 16]> {
    let mut out = Vec::new();
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "bmi1", target_feature = "bmi2"))]
    let cut = Cut::new();
    let mk = |at: usize| -> (u64, u64, u64) {
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "bmi1", target_feature = "bmi2"))]
        if vector {
            return unsafe { masks(d.as_ptr().add(at), &cut) };
        }
        let _ = vector;
        masks_sw(&d[at..])
    };
    // the first window of a long row only says whether it holds a newline
    let mk0 = |at: usize| -> (u64, u64, u64) {
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "bmi1", target_feature = "bmi2"))]
        if vector {
            return unsafe { masks_any(d.as_ptr().add(at), &cut) };
        }
        let m = masks_sw(&d[at..]);
        (m.0, m.1, if m.2 != 0 { !0 } else { 0 })
    };
    for w in cuts.windows(2) {
        let mut p = crate::first_line_start(d, w[0]);
        while p < w[1] {
            let mut r = [0usize; 16];
            let mut next = 0;
            if p + REACH <= d.len() {
                if N == 7 {
                    if let Some((mut a, mut b, at, nl)) = row7(mk0(p), |o| mk(p + o)) {
                        for k in 0..7 {
                            let (base, (s, e)) = if k < 3 { (p, a.next()) } else { (p + at, b.next()) };
                            r[2 * k] = base + s;
                            r[2 * k + 1] = base + e;
                        }
                        next = p + at + nl + 1;
                    }
                } else if N == 4 {
                    let m = mk(p);
                    if let Some((mut a, nl)) = tail::<3>(m.0, m.1, m.2) {
                        for k in 0..4 {
                            let (s, e) = a.next();
                            r[2 * k] = p + s;
                            r[2 * k + 1] = p + e;
                        }
                        next = p + nl + 1;
                    }
                }
            }
            if next != 0 {
                out.push(r);
                p = next;
                continue;
            }
            p = line::<N, _>(d, p, true, &mut |lp, s, e| {
                let mut r = [0usize; 16];
                for k in 0..N {
                    r[2 * k] = lp + s[k] as usize;
                    r[2 * k + 1] = lp + e[k] as usize;
                }
                out.push(r);
            });
        }
    }
    out
}

fn collect<const N: usize>(d: &[u8], cuts: &[usize], simd: bool) -> Vec<[usize; 16]> {
    let mut out = Vec::new();
    let mut ix = Index::new();
    for w in cuts.windows(2) {
        let p = crate::first_line_start(d, w[0]);
        each_row::<N, _>(d, p, w[1], simd, &mut ix, |lp, s, e| {
            let mut r = [0usize; 16];
            for k in 0..N {
                r[2 * k] = lp + s[k] as usize;
                r[2 * k + 1] = lp + e[k] as usize;
            }
            out.push(r);
        });
    }
    out
}

/// Lines with every kind of field, good and damaged, and every field count.
fn sample(seed: u64, lines: usize, long: usize) -> Vec<u8> {
    const PLAIN: &[u8] = b"ab01 -_:.\r\xffZ";
    let mut x = seed | 1;
    let mut r = move |n: usize| -> usize {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        ((x >> 11) % n as u64) as usize
    };
    let mut b: Vec<u8> = b"header\n".to_vec();
    for li in 0..lines {
        let nf = match r(16) {
            0 => r(12),
            1 => 2,
            2 => 8,
            3 => 6,
            4 => 5,
            5 => 50 + r(30),
            6 | 7 | 8 => 4,
            _ => 7,
        };
        for k in 0..nf {
            if k > 0 {
                b.push(b',');
            }
            let len = match r(40) {
                0 => 50 + r(150),
                1 | 2 | 3 => 0,
                _ => r(14),
            };
            let len = if li + 1 == long && k == 1 { 9000 + r(9000) } else { len };
            let kind = r(64);
            if kind <= 13 {
                b.push(b'"');
            }
            for j in 0..len {
                b.push(PLAIN[r(PLAIN.len())]);
                if kind == 15 && j == len / 2 {
                    b.push(b'"');
                }
            }
            if kind <= 12 || kind == 14 {
                b.push(b'"');
            }
            if kind == 16 {
                b.extend_from_slice(b"\"\"\"");
            }
        }
        b.push(b'\n');
    }
    if r(2) == 0 {
        b.extend_from_slice(b"a,\"b\",c,d,e,f,g");
    }
    b
}

/// Four-field lines of exactly 128 bytes, so every one starts on a block
/// boundary, with a quote or a delimiter on each side of the next boundary:
/// the cases where one block needs a bit from its neighbour.
fn edges() -> Vec<u8> {
    // (the first field opens with a quote, what follows it); five are good
    const TAILS: [(bool, &[u8]); 12] = [
        (false, b",\"b,c,d"),
        (false, b",\"b\",c,d"),
        (false, b",\",c,d"),
        (false, b",\"\",c,d"),
        (false, b"\",b,c,d"),
        (true, b"\",b,c,d"),
        (true, b",b,c,d"),
        (true, b"\"\",b,c,d"),
        (false, b",b\",c,d"),
        (false, b",,\"c\",d"),
        (false, b",\"b\"\",c,d"),
        (true, b"\",\"b\",\"c\",d"),
    ];
    let mut b: Vec<u8> = vec![b'h', 10];
    for pre in 56..72usize {
        for &(quoted, tail) in TAILS.iter() {
            let at = b.len();
            if quoted {
                b.push(b'"');
            }
            b.resize(at + pre, b'x');
            b.extend_from_slice(tail);
            b.resize(at + 127, b'y');
            b.push(10);
        }
    }
    b
}

/// The two-pass splitter must hand out exactly the rows the reference one
/// does, for every field count in use; checked once at startup.
pub fn agrees() -> bool {
    let d = sample(0x243f_6a88_85a3_08d3, 400, 200);
    let mut cuts: Vec<usize> = (0..d.len()).step_by(2500).collect();
    cuts.push(d.len());
    let e = edges();
    collect::<7>(&d, &cuts, true) == collect::<7>(&d, &cuts, false)
        && collect::<4>(&d, &cuts, true) == collect::<4>(&d, &cuts, false)
        && collect::<2>(&d, &cuts, true) == collect::<2>(&d, &cuts, false)
        && collect::<4>(&e, &[0, e.len()], true) == collect::<4>(&e, &[0, e.len()], false)
        && wins_agree()
}

/// the vector windows against the reference splitter, at startup
fn wins_agree() -> bool {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "bmi1", target_feature = "bmi2"))]
    {
        let d = sample_rows(0x1319_8a2e_0370_7344, 800);
        let cuts = [0, d.len() / 3, d.len()];
        if collect_win::<7>(&d, &cuts, true) != collect::<7>(&d, &cuts, false) || collect_win::<4>(&d, &cuts, true) != collect::<4>(&d, &cuts, false) {
            return false;
        }
    }
    true
}

/// rows of four and seven fields sized to straddle the 64-byte windows
#[allow(dead_code)]
fn sample_rows(seed: u64, lines: usize) -> Vec<u8> {
    const PLAIN: &[u8] = b"ab01 -_:.\r\xffZ";
    let mut x = seed | 1;
    let mut r = move |n: usize| -> usize {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        ((x >> 11) % n as u64) as usize
    };
    let mut b: Vec<u8> = b"header\n".to_vec();
    for _ in 0..lines {
        let nf = match r(12) {
            0 => 1 + r(9),
            1 | 2 | 3 | 4 => 4,
            _ => 7,
        };
        let width = [6, 14, 24, 34][r(4)];
        for k in 0..nf {
            if k > 0 {
                b.push(b',');
            }
            let len = match r(16) {
                0 => 0,
                1 => 20 + r(50),
                _ => r(width),
            };
            let kind = r(160);
            if kind <= 40 {
                b.push(b'"');
            }
            for j in 0..len {
                b.push(PLAIN[r(PLAIN.len())]);
                if kind == 43 && j == len / 2 {
                    b.push(b'"');
                }
            }
            if kind <= 39 || kind == 41 {
                b.push(b'"');
            }
            if kind == 42 {
                b.extend_from_slice(b"\"\"");
            }
        }
        if r(80) != 0 {
            b.push(b'\n');
        }
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_match_the_reference_splitter() {
        let mut total = 0usize;
        for seed in 1..=400u64 {
            let long = if seed % 8 == 0 { 30 } else { 0 };
            let d = sample(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15), 300 + (seed as usize % 7) * 100, long);
            // chunk boundaries anywhere, including inside a line
            let mut cuts = vec![0usize];
            let mut x = seed;
            while *cuts.last().unwrap() < d.len() {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let step = 1 + ((x >> 33) as usize % if seed % 3 == 0 { 300 } else { 40_000 });
                cuts.push((cuts.last().unwrap() + step).min(d.len()));
            }
            for n in [2usize, 4, 7, 8] {
                let (a, b) = match n {
                    2 => (collect::<2>(&d, &cuts, true), collect::<2>(&d, &[0, d.len()], false)),
                    4 => (collect::<4>(&d, &cuts, true), collect::<4>(&d, &[0, d.len()], false)),
                    7 => (collect::<7>(&d, &cuts, true), collect::<7>(&d, &[0, d.len()], false)),
                    _ => (collect::<8>(&d, &cuts, true), collect::<8>(&d, &[0, d.len()], false)),
                };
                assert_eq!(a.len(), b.len(), "seed {} n {}", seed, n);
                assert!(a == b, "seed {} n {}", seed, n);
                total += a.len();
            }
        }
        assert!(total > 100_000, "the sample has too few good rows: {}", total);
    }

    /// `SS_SPLIT_DIR=<dataset> cargo test --release rows_match_on_files`
    /// runs the comparison over real files, cut where the pipeline cuts.
    #[test]
    fn rows_match_on_files() {
        let dir = match std::env::var("SS_SPLIT_DIR") {
            Ok(d) => d,
            Err(_) => return,
        };
        for (sub, n) in [("events", 7usize), ("clicks", 4), ("links", 2)] {
            let mut names: Vec<_> = std::fs::read_dir(format!("{}/{}", dir, sub)).unwrap().map(|e| e.unwrap().path()).collect();
            names.sort();
            for path in names {
                let d = std::fs::read(&path).unwrap();
                let mut cuts: Vec<usize> = (0..d.len()).step_by(1 << 20).collect();
                cuts.push(d.len());
                let (a, b) = match n {
                    7 => (collect::<7>(&d, &cuts, true), collect::<7>(&d, &cuts, false)),
                    4 => (collect::<4>(&d, &cuts, true), collect::<4>(&d, &cuts, false)),
                    _ => (collect::<2>(&d, &cuts, true), collect::<2>(&d, &cuts, false)),
                };
                match n {
                    7 => assert!(collect_win::<7>(&d, &cuts, true) == b, "{:?}: windows", path),
                    4 => assert!(collect_win::<4>(&d, &cuts, true) == b, "{:?}: windows", path),
                    _ => {}
                }
                if a != b {
                    let k = (0..a.len().min(b.len())).find(|&k| a[k] != b[k]).unwrap_or(a.len().min(b.len()));
                    let show = |r: Option<&[usize; 16]>| match r {
                        Some(r) => {
                            let s = d[..r[0]].iter().rposition(|&c| c == b'\n').map_or(0, |x| x + 1);
                            let e = d[s..].iter().position(|&c| c == b'\n').map_or(d.len(), |x| s + x);
                            format!("@{} {:?} {:?}", s, &r[..2 * n], String::from_utf8_lossy(&d[s.saturating_sub(120)..(e + 120).min(d.len())]))
                        }
                        None => "none".to_string(),
                    };
                    panic!("{:?}: rows {} vs {}, first difference at {}\n fast {}\n slow {}", path, a.len(), b.len(), k, show(a.get(k)), show(b.get(k)));
                }
            }
        }
    }

    /// Not a test: `SS_SPLIT_DIR=<dataset> SS_KIND=events|clicks SS_N=<passes>`
    /// under `perf stat`, differenced between two pass counts, gives the
    /// splitter's instructions per row with a callback that only adds.
    #[test]
    #[ignore]
    fn bench_split() {
        let dir = std::env::var("SS_SPLIT_DIR").unwrap();
        let kind = std::env::var("SS_KIND").unwrap_or("events".to_string());
        let n: usize = std::env::var("SS_N").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
        let mut names: Vec<_> = std::fs::read_dir(format!("{}/{}", dir, kind)).unwrap().map(|e| e.unwrap().path()).collect();
        names.sort();
        let files: Vec<Vec<u8>> = names.iter().map(|p| std::fs::read(p).unwrap()).collect();
        let mut ix = Box::new(Index::new());
        let (mut rows, mut acc) = (0usize, 0usize);
        for _ in 0..n {
            for d in &files {
                let mut from = 0usize;
                while from < d.len() {
                    let to = (from + (1 << 20)).min(d.len());
                    let p = crate::first_line_start(d, from);
                    if kind == "events" {
                        each_row::<7, _>(d, p, to, true, &mut ix, #[inline(always)] |lp, s, e| {
                            rows += 1;
                            acc += lp + (s[0] ^ e[0] ^ s[1] ^ e[1] ^ s[2] ^ e[2] ^ s[3] ^ e[3] ^ s[4] ^ e[4] ^ s[5] ^ e[5] ^ s[6] ^ e[6]) as usize;
                        });
                    } else {
                        each_row::<4, _>(d, p, to, true, &mut ix, #[inline(always)] |lp, s, e| {
                            rows += 1;
                            acc += lp + (s[0] ^ e[0] ^ s[1] ^ e[1] ^ s[2] ^ e[2] ^ s[3] ^ e[3]) as usize;
                        });
                    }
                    from = to;
                }
            }
        }
        println!("rows {} acc {}", rows, std::hint::black_box(acc));
    }

    #[test]
    fn windows_match_the_reference_splitter() {
        let mut total = 0usize;
        let mut check = |d: &[u8], cuts: &[usize]| {
            let want7 = collect::<7>(d, &[0, d.len()], false);
            let want4 = collect::<4>(d, &[0, d.len()], false);
            for vector in [false, true] {
                assert!(collect_win::<7>(d, cuts, vector) == want7);
                assert!(collect_win::<4>(d, cuts, vector) == want4);
            }
            total += want7.len() + want4.len();
        };
        for seed in 1..=600u64 {
            let d = sample_rows(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15), 1500);
            let mut cuts = vec![0usize];
            let mut x = seed;
            while *cuts.last().unwrap() < d.len() {
                x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let step = 1 + ((x >> 33) as usize % if seed % 3 == 0 { 300 } else { 40_000 });
                cuts.push((cuts.last().unwrap() + step).min(d.len()));
            }
            check(&d, &cuts);
        }
        for seed in 1..=100u64 {
            let d = sample(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15), 600, if seed % 8 == 0 { 30 } else { 0 });
            check(&d, &[0, d.len() / 2, d.len()]);
        }
        let e = edges();
        check(&e, &[0, e.len()]);
        assert!(total > 400_000, "the sample has too few good rows: {}", total);
    }

    #[test]
    fn windows_match_on_dense_input() {
        // mostly delimiters and quotes, so every mask pattern turns up
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut good = 0usize;
        for round in 0..400 {
            let pool: &[u8] = if round % 2 == 0 { b"aa,,\"\n" } else { b"aaaaaaaaaa,,,,\"\"\n" };
            let mut d = b"h\n".to_vec();
            for _ in 0..20_000 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                d.push(pool[((x >> 11) % pool.len() as u64) as usize]);
            }
            let cuts = [0, d.len() / 2, d.len()];
            let want7 = collect::<7>(&d, &[0, d.len()], false);
            let want4 = collect::<4>(&d, &[0, d.len()], false);
            for vector in [false, true] {
                assert!(collect_win::<7>(&d, &cuts, vector) == want7);
                assert!(collect_win::<4>(&d, &cuts, vector) == want4);
            }
            good += want7.len() + want4.len();
        }
        assert!(good > 20_000, "too few good rows: {}", good);
    }

    /// what `wrap` decides, by the reference rule for one field
    fn wrap_ref(d: u64, q: u64) -> Option<(Vec<usize>, Vec<usize>)> {
        let (mut ss, mut es) = (Vec::new(), Vec::new());
        let mut s = 0usize;
        for e in 0..64 {
            if d >> e & 1 == 0 {
                continue;
            }
            let (a, b) = crate::unq(s, e, q as u128)?;
            ss.push(a as usize);
            es.push(b as usize);
            s = e + 1;
        }
        Some((ss, es))
    }

    #[test]
    fn wrap_matches_the_field_rule() {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let (mut some, mut none) = (0usize, 0usize);
        for i in 0..3_000_000u64 {
            // sparse delimiters, and quotes mostly where they are legal
            let mut d = next() & next() & next();
            if i % 3 == 0 {
                d &= next();
            }
            if d == 0 {
                continue;
            }
            let top = 63 - d.leading_zeros();
            let upto = if top == 63 { !0u64 } else { (1u64 << (top + 1)) - 1 };
            let after = (d << 1) | 1;
            let mut q = match i % 4 {
                0 => 0,
                1 => next() & next() & next() & next(),
                _ => (after & next()) | ((d >> 1) & next()),
            };
            if i % 16 == 5 {
                q |= 1 << (next() % 64);
            }
            q &= upto & !d;
            let got = wrap(d, q).map(|mut w| {
                let (mut ss, mut es) = (Vec::new(), Vec::new());
                for _ in 0..d.count_ones() {
                    let (s, e) = w.next();
                    ss.push(s);
                    es.push(e);
                }
                (ss, es)
            });
            let want = wrap_ref(d, q);
            assert_eq!(got, want, "d {:#x} q {:#x}", d, q);
            if want.is_some() {
                some += 1;
            } else {
                none += 1;
            }
        }
        assert!(some > 300_000 && none > 300_000, "{} {}", some, none);
    }

    /// Not a test: as `bench_split`, for the window splitter.
    #[test]
    #[ignore]
    fn bench_win() {
        let dir = std::env::var("SS_SPLIT_DIR").unwrap();
        let kind = std::env::var("SS_KIND").unwrap_or("events".to_string());
        let n: usize = std::env::var("SS_N").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
        let mut names: Vec<_> = std::fs::read_dir(format!("{}/{}", dir, kind)).unwrap().map(|e| e.unwrap().path()).collect();
        names.sort();
        let files: Vec<Vec<u8>> = names.iter().map(|p| std::fs::read(p).unwrap()).collect();
        let (mut rows, mut acc, mut slow) = (0usize, 0usize, 0usize);
        #[cfg(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "bmi1", target_feature = "bmi2"))]
        for _ in 0..n {
            let cut = Cut::new();
            for d in &files {
                let mut p = crate::first_line_start(d, 0);
                while p + REACH <= d.len() {
                    let at = unsafe { d.as_ptr().add(p) };
                    if kind == "events" {
                        if let Some((mut a, mut b, o, nl)) = row7(unsafe { masks_any(at, &cut) }, |o| unsafe { masks(at.add(o), &cut) }) {
                            for _ in 0..3 {
                                let (s, e) = a.next();
                                acc += s ^ e;
                            }
                            for _ in 0..4 {
                                let (s, e) = b.next();
                                acc += s ^ e;
                            }
                            rows += 1;
                            p += o + nl + 1;
                            continue;
                        }
                    } else {
                        let m = unsafe { masks(at, &cut) };
                        if let Some((mut a, nl)) = tail::<3>(m.0, m.1, m.2) {
                            for _ in 0..4 {
                                let (s, e) = a.next();
                                acc += s ^ e;
                            }
                            rows += 1;
                            p += nl + 1;
                            continue;
                        }
                    }
                    slow += 1;
                    while d[p] != b'\n' {
                        p += 1;
                    }
                    p += 1;
                }
            }
        }
        let _ = (n, &files);
        println!("rows {} slow {} acc {}", rows, slow, std::hint::black_box(acc));
    }

    #[test]
    fn rows_match_at_block_edges() {
        let e = edges();
        let a = collect::<4>(&e, &[0, e.len()], true);
        assert!(a == collect::<4>(&e, &[0, e.len()], false));
        assert_eq!(a.len(), 16 * 5);
        assert!(agrees());
    }

    #[test]
    fn rows_match_on_dense_and_degenerate_input() {
        let mut cases: Vec<Vec<u8>> = vec![
            b"h\n".to_vec(),
            b"h".to_vec(),
            b"".to_vec(),
            b"h\n\n\n\n".to_vec(),
            b"h\na,b,c,d".to_vec(),
        ];
        for pat in [&b","[..], b"\n", b"\"", b"\"\",", b",\n", b"\"a\",", b"a,b,c,d\n", b"\"\n", b"\",\"", b"a,b,c,\"d\"\n"] {
            for pre in 0..70usize {
                let mut v = b"h\n".to_vec();
                v.extend(std::iter::repeat(b'x').take(pre));
                v.push(b'\n');
                for _ in 0..(20_000 / pat.len()) {
                    v.extend_from_slice(pat);
                }
                cases.push(v);
            }
        }
        for d in &cases {
            let cuts = [0, d.len() / 2, d.len()];
            assert!(collect::<4>(d, &cuts, true) == collect::<4>(d, &[0, d.len()], false));
            assert!(collect::<7>(d, &cuts, true) == collect::<7>(d, &[0, d.len()], false));
            assert!(collect::<2>(d, &cuts, true) == collect::<2>(d, &[0, d.len()], false));
            for vector in [false, true] {
                assert!(collect_win::<4>(d, &cuts, vector) == collect::<4>(d, &[0, d.len()], false));
                assert!(collect_win::<7>(d, &cuts, vector) == collect::<7>(d, &[0, d.len()], false));
            }
        }
    }
}
