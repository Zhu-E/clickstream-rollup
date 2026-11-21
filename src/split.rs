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

    /// Commas, quotes and newlines in 64 bytes, one bit per byte.
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
        (m(b','), m(b'"'), m(b'\n'))
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
        let (mut c, mut q, mut n) = (0u64, 0u64, 1u64 << 63);
        let mut open = 0u64; // the last delimiter is followed by a quote
        let mut dprev = 0u64; // the byte before this block is a delimiter
        let mut qprev = 0u64; // ... is a quote
        let mut nd = 0usize;
        let mut nbad = 0usize;
        for t in 0..=nblk {
            let (c1, q1, n1) = masks(base.add(t * 64));
            let off = (t as u32).wrapping_sub(1).wrapping_mul(64);
            let d = c | n;
            let d1 = c1 | n1;
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
            let unpaired = _bzhi_u64(((a << 1) | open) ^ b, cnt as u32);
            if cnt != 0 {
                open = (a >> (cnt - 1)) & 1;
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
            c = c1;
            q = q1;
            n = n1;
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
            let qm = _mm256_cmpeq_epi32(_mm256_and_si256(_mm256_set1_epi32(qw), bits), bits);
            let sv = _mm256_sub_epi32(_mm256_sub_epi32(pv, ones), qm);
            let ee = _mm256_add_epi32(ev, qm);
            _mm256_storeu_si256(st.as_mut_ptr() as *mut __m256i, sv);
            _mm256_storeu_si256(en.as_mut_ptr() as *mut __m256i, ee);
            f(p, &st, &en);
            i = e;
            ls = nl + 1;
        }
        ls as usize
    }
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

/// The two-pass splitter must hand out exactly the rows the reference one
/// does, for every field count in use; checked once at startup.
pub fn agrees() -> bool {
    let d = sample(0x243f_6a88_85a3_08d3, 400, 200);
    let cuts = [0, d.len() / 3, d.len() / 2, d.len()];
    collect::<7>(&d, &cuts, true) == collect::<7>(&d, &cuts, false)
        && collect::<4>(&d, &cuts, true) == collect::<4>(&d, &cuts, false)
        && collect::<2>(&d, &cuts, true) == collect::<2>(&d, &cuts, false)
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
        }
    }
}
