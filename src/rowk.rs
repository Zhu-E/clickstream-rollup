// Rows read through tables indexed by raw field lengths. A quoted field is
// just another length, so its table row expects the quotes where they must
// be; every byte of every field but the last two is compared or range
// checked, all checks meet in one vector, and a row the tables do not fully
// vouch for is left to the callers' older paths.
use super::Keys;
#[cfg(not(all(target_feature = "avx512dq", target_feature = "avx512vl")))]
use crate::genid::unscramble;
use crate::genid::{AINV, M40};
use core::arch::x86_64::*;

// ------------------------------------------------------------------- tables

/// both ids of an event row: digits to bytes 0..8 of each half, letter and quotes after
#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct IdRow {
    ctrl: [u8; 32],
    subv: [u8; 32],
    lz: [u8; 32],
    pad: [u8; 32],
}

/// one id of `raw` bytes: plain with 1 to 8 digits, or quoted with 7 or 8
const fn id_half(letter: u8, raw: usize) -> ([u8; 16], [u8; 16], [u8; 16]) {
    let mut ctrl = [0x80u8; 16];
    let mut subv = [0u8; 16];
    let mut lz = [0u8; 16];
    let (q, nd) = if raw >= 2 && raw <= 9 {
        (0, raw - 1)
    } else if raw == 10 || raw == 11 {
        (1, raw - 3)
    } else {
        // never zero: no such id
        subv[8] = 1;
        return (ctrl, subv, lz);
    };
    let mut j = 0;
    while j < nd {
        ctrl[8 - nd + j] = (1 + q + j) as u8;
        subv[8 - nd + j] = b'0';
        j += 1;
    }
    ctrl[8] = q as u8;
    subv[8] = letter;
    if q == 1 {
        ctrl[9] = 0;
        subv[9] = b'"';
        ctrl[10] = (raw - 1) as u8;
        subv[10] = b'"';
    }
    if nd > 1 {
        lz[8 - nd] = 1;
    }
    (ctrl, subv, lz)
}

const fn id_rows(a: u8, b: u8) -> [IdRow; 4096] {
    let mut t = [IdRow { ctrl: [0; 32], subv: [0; 32], lz: [0; 32], pad: [0; 32] }; 4096];
    let mut ra = 0;
    while ra < 64 {
        let x = id_half(a, ra);
        let mut rb = 0;
        while rb < 64 {
            let y = id_half(b, rb);
            let r = &mut t[ra * 64 + rb];
            let mut i = 0;
            while i < 16 {
                r.ctrl[i] = x.0[i];
                r.subv[i] = x.1[i];
                r.lz[i] = x.2[i];
                r.ctrl[16 + i] = y.0[i];
                r.subv[16 + i] = y.1[i];
                r.lz[16 + i] = y.2[i];
                i += 1;
            }
            rb += 1;
        }
        ra += 1;
    }
    t
}

/// one id by itself, in the low half
const fn id1_rows(a: u8) -> [IdRow; 64] {
    let mut t = [IdRow { ctrl: [0x80; 32], subv: [0; 32], lz: [0; 32], pad: [0; 32] }; 64];
    let mut ra = 0;
    while ra < 64 {
        let x = id_half(a, ra);
        let mut i = 0;
        while i < 16 {
            t[ra].ctrl[i] = x.0[i];
            t[ra].subv[i] = x.1[i];
            t[ra].lz[i] = x.2[i];
            i += 1;
        }
        ra += 1;
    }
    t
}

/// two timestamps: the low half any form by its raw length, the high half `...Z`
#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct TsRow {
    ctrl: [u8; 32],
    base: [u8; 32],
    lim: [u8; 32],
    w1: [i8; 32],
    w2: [i16; 16],
    w3: [i16; 16],
    limv: [i32; 8],
    kmask: [u8; 32],
    ka: [i64; 4],
    kb: [i64; 4],
    ksel: [u8; 32],
    /// bits of the date that pick its cache slot; none for a form with no date
    pm: u64,
    /// where the date's key starts, from the byte before the field
    koff: u64,
    pad: [u64; 18],
}

const _: () = assert!(std::mem::size_of::<TsRow>() == 512);

const NO_TS: TsRow = TsRow {
    ctrl: [0x80; 32],
    base: [0; 32],
    lim: [0; 32],
    w1: [0; 32],
    w2: [0; 16],
    w3: [0; 16],
    // nothing is below this: the row accepts no field
    limv: [-1; 8],
    kmask: [0; 32],
    ka: [0; 4],
    kb: [0; 4],
    ksel: [0; 32],
    pm: 0,
    koff: 0,
    pad: [0; 18],
};

/// month parity, two bits of the day's tens, four of its units: as `tbl::slot`
const DATE_BITS: u64 = (1 << 24) | (3 << 40) | (0xf << 48);

/// `HH:MM:SS` then `Z` or an offset, quoted or not, into half `h` of `r`; `raw` is the field's length
const fn ts_time(r: &mut TsRow, h: usize, raw: usize, offset: bool, q: bool) {
    let o = 16 * h;
    // the sixteen bytes that end the field hold everything after the date
    let from = 11 + q as usize;
    let mut i = 0;
    while i < 16 {
        r.ctrl[o + i] = if from + i < raw { (from + i + 16 - raw) as u8 } else { 0x80 };
        i += 1;
    }
    let text = *b"00:00:00";
    let lim = [2u8, 9, 0, 5, 9, 0, 5, 9];
    let w1 = [10i8, 1, 0, 10, 1, 0, 10, 1];
    let mut i = 0;
    while i < 8 {
        r.base[o + i] = text[i];
        r.lim[o + i] = lim[i];
        r.w1[o + i] = w1[i];
        i += 1;
    }
    let mut next = 9;
    if offset {
        let text = *b"+00:00";
        // a sign is `+` or two above it
        let lim = [2u8, 2, 9, 0, 5, 9];
        let w1 = [0i8, 10, 1, 0, 10, 1];
        let mut i = 0;
        while i < 6 {
            r.base[o + 8 + i] = text[i];
            r.lim[o + 8 + i] = lim[i];
            r.w1[o + 8 + i] = w1[i];
            i += 1;
        }
        next = 14;
    } else {
        r.base[o + 8] = b'Z';
    }
    if q {
        r.base[o + next] = b'"';
    }
    // minutes of the day less the last digit, that digit and the seconds, offset hours, offset minutes
    let w2 = [60i16, 1, 60, 1, 1, 1, 1, 0];
    let mut i = 0;
    while i < 8 {
        r.w2[8 * h + i] = w2[i];
        i += 1;
    }
    r.limv[4 * h] = 1430;
    r.limv[4 * h + 1] = i32::MAX;
    r.limv[4 * h + 2] = 23;
    r.limv[4 * h + 3] = i32::MAX;
    let mut i = if q { 0 } else { 1 };
    while i < 12 {
        r.kmask[o + i] = 0xff;
        i += 1;
    }
    if h == 0 {
        // seconds of the day and minutes of offset, in the upper words
        r.w3[4] = 60;
        r.w3[5] = 1;
        r.w3[6] = 60;
        r.w3[7] = 1;
        r.ka[1] = 1000;
        r.kb[1] = 60_000;
        // taken off unless the sign is `-`
        r.ksel[8] = 2;
        r.pm = DATE_BITS;
        r.koff = q as u64;
    } else {
        // seconds of the day twice: for the seconds and for the milliseconds
        r.w3[8] = 60;
        r.w3[9] = 1;
        r.w3[12] = 60;
        r.w3[13] = 1;
        r.ka[2] = 1;
        r.ka[3] = 1000;
    }
}

/// thirteen digits, quoted or not, into the low half
const fn ts_epoch(r: &mut TsRow, q: bool) {
    let mut i = 3;
    while i < 16 {
        r.ctrl[i] = (i - q as usize) as u8;
        r.base[i] = b'0';
        r.lim[i] = 9;
        r.w1[i] = if i % 2 == 0 { 10 } else { 1 };
        i += 1;
    }
    if q {
        r.ctrl[0] = 15;
        r.ctrl[1] = 1;
        r.base[0] = b'"';
        r.base[1] = b'"';
    }
    let mut i = 0;
    while i < 4 {
        r.w2[2 * i] = 100;
        r.w2[2 * i + 1] = 1;
        r.limv[i] = i32::MAX;
        i += 1;
    }
    // five digits and eight
    r.w3[4] = 10_000;
    r.w3[5] = 1;
    r.w3[6] = 10_000;
    r.w3[7] = 1;
    r.ka[1] = 100_000_000;
    // always taken off, so it adds
    r.kb[1] = -1;
}

/// row `raw * 2 + q3`: `ts` of `raw` bytes, `ingest_ts` quoted or not
const fn ts_rows() -> [TsRow; 128] {
    let mut t = [NO_TS; 128];
    let mut j = 0;
    while j < 128 {
        let (raw, q3) = (j / 2, j % 2 == 1);
        let mut r = NO_TS;
        r.limv = [i32::MAX; 8];
        let ok = match raw {
            13 | 15 => {
                ts_epoch(&mut r, raw == 15);
                true
            }
            20 | 22 => {
                ts_time(&mut r, 0, raw, false, raw == 22);
                true
            }
            25 | 27 => {
                ts_time(&mut r, 0, raw, true, raw == 27);
                true
            }
            _ => false,
        };
        if ok {
            ts_time(&mut r, 1, 20 + 2 * q3 as usize, false, q3);
            t[j] = r;
        }
        j += 1;
    }
    t
}

/// one timestamp of a click row, in the low half; row `raw`
const fn ts1_rows() -> [TsRow; 64] {
    let mut t = [NO_TS; 64];
    let mut raw = 0;
    while raw < 64 {
        let mut r = NO_TS;
        r.limv = [i32::MAX; 8];
        let ok = match raw {
            13 | 15 => {
                ts_epoch(&mut r, raw == 15);
                true
            }
            20 | 22 => {
                ts_time(&mut r, 0, raw, false, raw == 22);
                true
            }
            25 | 27 => {
                ts_time(&mut r, 0, raw, true, raw == 27);
                true
            }
            _ => false,
        };
        if ok {
            t[raw] = r;
        }
        raw += 1;
    }
    t
}

/// an event type by its raw length and the low bit of its fourth byte
#[repr(C, align(32))]
#[derive(Clone, Copy)]
struct KindRow {
    cand: [u8; 16],
    mask: [u8; 16],
}

const fn kind_row(text: &[u8]) -> KindRow {
    let mut r = KindRow { cand: [0; 16], mask: [0; 16] };
    let mut i = 0;
    while i < text.len() {
        r.cand[i] = text[i];
        r.mask[i] = 0xff;
        i += 1;
    }
    r
}

const fn kind_rows() -> [KindRow; 128] {
    // a field has no newline in it and a short one is followed by a comma
    let mut t = [KindRow { cand: [b'\n'; 16], mask: [0xff; 16] }; 128];
    t[4 * 2] = kind_row(b"cart");
    t[4 * 2 + 1] = kind_row(b"view");
    t[6 * 2] = kind_row(b"\"cart\"");
    t[6 * 2 + 1] = kind_row(b"\"view\"");
    t[8 * 2] = kind_row(b"purchase");
    t[8 * 2 + 1] = kind_row(b"purchase");
    t[10 * 2] = kind_row(b"\"purchase\"");
    t[10 * 2 + 1] = kind_row(b"\"purchase\"");
    t
}

/// the quotes allowed in the last two fields, by their raw lengths
#[repr(C, align(32))]
#[derive(Clone, Copy)]
struct TailRow {
    /// where a quote may open: each field's first byte
    sel: u32,
    /// the bytes of both fields and the comma between
    m: u32,
    /// by which fields open with a quote: every quote there must then be
    pat: [u32; 4],
    pad: [u32; 2],
}

const NO_PAT: u32 = u32::MAX;

/// row `a * 64 + b`; with `need`, a first field that is empty is refused
const fn tail_rows(need: bool) -> [TailRow; 4096] {
    let mut t = [TailRow { sel: 0, m: 0, pat: [NO_PAT; 4], pad: [0; 2] }; 4096];
    let mut a = 0;
    while a < 64 {
        let mut b = 0;
        while b < 64 {
            if a + 1 + b <= 31 {
                // a quoted field is two quotes around something, or around nothing
                let least = if need { 3 } else { 2 };
                let pa = if a >= least { 1 | 1u32 << (a - 1) } else { NO_PAT };
                let pb = if b >= 2 { (1 | 1u32 << (b - 1)) << (a + 1) } else { NO_PAT };
                let both = if pa != NO_PAT && pb != NO_PAT { pa | pb } else { NO_PAT };
                let none = if need && a == 0 { NO_PAT } else { 0 };
                let pb = if need && a == 0 { NO_PAT } else { pb };
                t[a * 64 + b] = TailRow { sel: 1 | 1 << (a + 1), m: (1u32 << (a + 1 + b)) - 1, pat: [none, pa, pb, both], pad: [0; 2] };
            }
            b += 1;
        }
        a += 1;
    }
    t
}

#[repr(C, align(64))]
struct Tables {
    ts: [TsRow; 128],
    ts1: [TsRow; 64],
    kind: [KindRow; 128],
    tail: [TailRow; 4096],
    id: [IdRow; 4096],
    uid: [IdRow; 64],
}

static T: Tables = Tables { ts: ts_rows(), ts1: ts1_rows(), kind: kind_rows(), tail: tail_rows(true), id: id_rows(b'e', b'u'), uid: id1_rows(b'u') };

// --------------------------------------------------------------- date cache

/// a date as text behind a quote, and its midnight in seconds and milliseconds
#[repr(C, align(32))]
#[derive(Clone, Copy)]
pub struct Day {
    key: [u8; 16],
    sec: i64,
    ms: i64,
}

/// `"YYYY-MM-DDT` -> midnight; slot 0 is never filled and reads as no date at all
pub struct Days {
    e: [Day; 128],
}

impl Days {
    pub fn new() -> Days {
        Days { e: [Day { key: [0; 16], sec: 0, ms: 0 }; 128] }
    }
    pub fn as_ptr(&self) -> *const Day {
        self.e.as_ptr()
    }
    /// take in the date `b` opens with, if it is one
    pub fn learn(&mut self, b: &[u8]) {
        if b.len() < 11 {
            return;
        }
        let i = unsafe { _pext_u64(u64::from_le_bytes([b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10]]), DATE_BITS) } as usize;
        if i == 0 || self.e[i].key[1..12] == b[..11] {
            return;
        }
        if let Some(d) = crate::tbl::cache_day(b) {
            let mut key = [0u8; 16];
            key[0] = b'"';
            key[1..12].copy_from_slice(&b[..11]);
            self.e[i] = Day { key, sec: d * 86_400, ms: d * crate::tbl::DAY_MS };
        }
    }
}

// ------------------------------------------------------------------ helpers

#[inline(always)]
unsafe fn ld(p: *const u8) -> __m128i {
    _mm_loadu_si128(p as *const __m128i)
}

#[inline(always)]
unsafe fn ld2(p: *const u8) -> __m256i {
    _mm256_loadu_si256(p as *const __m256i)
}

/// two sixteen-byte loads side by side
#[inline(always)]
unsafe fn two(lo: *const u8, hi: *const u8) -> __m256i {
    _mm256_inserti128_si256::<1>(_mm256_castsi128_si256(ld(lo)), ld(hi))
}

#[inline(always)]
unsafe fn rd64(p: *const u8) -> u64 {
    (p as *const u64).read_unaligned()
}

#[inline(always)]
unsafe fn eq(a: __m256i, k: __m256i) -> u32 {
    #[cfg(all(target_feature = "avx512bw", target_feature = "avx512vl"))]
    return _mm256_cmpeq_epi8_mask(a, k);
    #[cfg(not(all(target_feature = "avx512bw", target_feature = "avx512vl")))]
    return _mm256_movemask_epi8(_mm256_cmpeq_epi8(a, k)) as u32;
}

/// a | b | c
#[inline(always)]
unsafe fn or3(a: __m256i, b: __m256i, c: __m256i) -> __m256i {
    #[cfg(all(target_feature = "avx512f", target_feature = "avx512vl"))]
    return _mm256_ternarylogic_epi64::<0xfe>(a, b, c);
    #[cfg(not(all(target_feature = "avx512f", target_feature = "avx512vl")))]
    return _mm256_or_si256(_mm256_or_si256(a, b), c);
}

/// a | (b & c)
#[inline(always)]
unsafe fn or_and(a: __m256i, b: __m256i, c: __m256i) -> __m256i {
    #[cfg(all(target_feature = "avx512f", target_feature = "avx512vl"))]
    return _mm256_ternarylogic_epi64::<0xf8>(a, b, c);
    #[cfg(not(all(target_feature = "avx512f", target_feature = "avx512vl")))]
    return _mm256_or_si256(a, _mm256_and_si256(b, c));
}

/// t - f in the words where `d` has none of the bits of `sel`, t + f in the rest
#[inline(always)]
unsafe fn add_or_sub(t: __m256i, f: __m256i, d: __m256i, sel: __m256i) -> __m256i {
    #[cfg(all(target_feature = "avx512f", target_feature = "avx512vl"))]
    return _mm256_mask_sub_epi64(_mm256_add_epi64(t, f), _mm256_testn_epi64_mask(d, sel), t, f);
    #[cfg(not(all(target_feature = "avx512f", target_feature = "avx512vl")))]
    {
        let none = _mm256_cmpeq_epi64(_mm256_and_si256(d, sel), _mm256_setzero_si256());
        return _mm256_blendv_epi8(_mm256_add_epi64(t, f), _mm256_sub_epi64(t, f), none);
    }
}

/// whether any bit is set
#[inline(always)]
unsafe fn any(v: __m256i) -> bool {
    #[cfg(all(target_feature = "avx512f", target_feature = "avx512vl"))]
    {
        // spelled out: left to the compiler this is five instructions of folding
        let z: u8;
        core::arch::asm!("vptest {v}, {v}", "setne {z}", v = in(ymm_reg) v, z = lateout(reg_byte) z, options(pure, nomem, nostack));
        return z != 0;
    }
    #[cfg(not(all(target_feature = "avx512f", target_feature = "avx512vl")))]
    return _mm256_testz_si256(v, v) == 0;
}

/// words 0 and 2 as plain registers, which keeps what is built from them out of vectors
#[inline(always)]
unsafe fn words02(v: __m256i) -> (u64, u64) {
    #[cfg(all(target_feature = "avx512f", target_feature = "avx512vl"))]
    {
        let (a, b): (u64, u64);
        core::arch::asm!("vmovq {a}, {v:x}", "vextracti128 {t}, {v}, 1", "vmovq {b}, {t}", v = in(ymm_reg) v, t = out(xmm_reg) _, a = lateout(reg) a, b = lateout(reg) b, options(pure, nomem, nostack, preserves_flags));
        return (a, b);
    }
    #[cfg(not(all(target_feature = "avx512f", target_feature = "avx512vl")))]
    return (_mm256_extract_epi64::<0>(v) as u64, _mm256_extract_epi64::<2>(v) as u64);
}

/// words 1, 2 and 3
#[inline(always)]
unsafe fn words123(v: __m256i) -> (i64, i64, i64) {
    #[cfg(all(target_feature = "avx512f", target_feature = "avx512vl"))]
    {
        let (a, b, c): (i64, i64, i64);
        core::arch::asm!("vpextrq {a}, {v:x}, 1", "vextracti128 {t}, {v}, 1", "vmovq {b}, {t}", "vpextrq {c}, {t}, 1", v = in(ymm_reg) v, t = out(xmm_reg) _, a = lateout(reg) a, b = lateout(reg) b, c = lateout(reg) c, options(pure, nomem, nostack, preserves_flags));
        return (a, b, c);
    }
    #[cfg(not(all(target_feature = "avx512f", target_feature = "avx512vl")))]
    return (_mm256_extract_epi64::<1>(v), _mm256_extract_epi64::<2>(v), _mm256_extract_epi64::<3>(v));
}

/// inverse of the generator's second multiplier mod 2^40; the row checks hold it to `unscramble`
const BINV: u64 = {
    let b = 0xD6E8_FEB8_6659u64;
    let mut x = b;
    let mut i = 0;
    while i < 6 {
        x = x.wrapping_mul(2u64.wrapping_sub(b.wrapping_mul(x)));
        i += 1;
    }
    x & M40
};

/// `unscramble` of words 0 and 2 under their keys; nonzero where one is not under its cap
#[cfg(all(target_feature = "avx512dq", target_feature = "avx512vl"))]
#[inline(always)]
unsafe fn unscr(v: __m256i, k: &Kern) -> (__m256i, __m256i) {
    let m40 = _mm256_set1_epi64x(M40 as i64);
    let m = _mm256_and_si256(_mm256_mullo_epi64(v, _mm256_set1_epi64x(BINV as i64)), m40);
    let h = _mm256_xor_si256(_mm256_xor_si256(m, _mm256_srli_epi64::<17>(m)), _mm256_srli_epi64::<34>(m));
    let r = _mm256_and_si256(_mm256_mullo_epi64(_mm256_xor_si256(h, k.keys), _mm256_set1_epi64x(AINV as i64)), m40);
    (r, _mm256_cmpgt_epi64(r, k.caps))
}

#[cfg(not(all(target_feature = "avx512dq", target_feature = "avx512vl")))]
#[inline(always)]
unsafe fn unscr(v: __m256i, k: &Kern) -> (__m256i, __m256i) {
    let key = |i: i32| match i {
        0 => _mm256_extract_epi64::<0>(k.keys) as u64,
        _ => _mm256_extract_epi64::<2>(k.keys) as u64,
    };
    let a = unscramble(_mm256_extract_epi64::<0>(v) as u64 & M40, key(0));
    let b = unscramble(_mm256_extract_epi64::<2>(v) as u64 & M40, key(2));
    let r = _mm256_set_epi64x(0, b as i64, 0, a as i64);
    (r, _mm256_cmpgt_epi64(r, k.caps))
}

/// base-36 digits in bytes 0..8 of each half and bytes that must be zero after them:
/// the two numbers in words 0 and 2, and nonzero for anything out of order
#[inline(always)]
unsafe fn ids36(x: __m256i, r: &IdRow) -> (__m256i, __m256i) {
    let v = _mm256_sub_epi8(_mm256_shuffle_epi8(x, ld2(r.ctrl.as_ptr())), ld2(r.subv.as_ptr()));
    let notdig = _mm256_subs_epu8(v, _mm256_set1_epi8(9));
    let notlet = _mm256_subs_epu8(_mm256_sub_epi8(v, _mm256_set1_epi8(49)), _mm256_set1_epi8(25));
    let val = _mm256_min_epu8(v, _mm256_sub_epi8(v, _mm256_set1_epi8(39)));
    // a first digit of several may not be zero
    let lz = _mm256_subs_epu8(ld2(r.lz.as_ptr()), val);
    let cls = or_and(_mm256_min_epu8(notdig, notlet), v, _mm256_set_epi64x(-1, 0, -1, 0));
    let m1 = _mm256_maddubs_epi16(val, _mm256_set1_epi16(0x0124));
    let m2 = _mm256_madd_epi16(m1, _mm256_set1_epi32(0x0001_0510));
    let n = _mm256_add_epi64(_mm256_mul_epu32(m2, _mm256_set1_epi64x(1_679_616)), _mm256_srli_epi64::<32>(m2));
    (n, or3(cls, lz, _mm256_srli_epi64::<40>(n)))
}

// ------------------------------------------------------------------- events

/// what a thread reads rows against
pub struct Kern {
    comma: __m256i,
    nl: __m256i,
    quote: __m256i,
    /// event key, 0, user key, 0
    keys: __m256i,
    /// the largest counter and the largest user number, each followed by no limit
    caps: __m256i,
    days: *const Day,
}

impl Kern {
    #[inline(always)]
    pub fn new(k: &Keys, days: *const Day) -> Kern {
        unsafe {
            let f = |c: u8| _mm256_set1_epi8(c as i8);
            Kern {
                comma: f(b','),
                nl: f(b'\n'),
                quote: f(b'"'),
                keys: _mm256_set_epi64x(0, k.uk as i64, 0, k.ek as i64),
                caps: _mm256_set_epi64x(i64::MAX, (k.ucap << 9) as i64 - 1, i64::MAX, k.ncap as i64 - 1),
                days,
            }
        }
    }
}

/// an event row the tables vouch for: valid ids under their caps, valid times, a type, a product
#[derive(Clone, Copy)]
pub struct Ev {
    pub c: u64,
    pub un: u64,
    pub ts: i64,
    pub ing_sec: i64,
    pub ing_ms: i64,
    /// bytes to the next row
    pub next: usize,
    /// the last two fields: see `Tail`
    pub tail: u64,
}

/// the last three fields of a row at `p`, unpacked
pub struct Tail {
    pub pur: bool,
    pub prod: *const u8,
    pub nprod: usize,
    pub price: *const u8,
    pub nprice: usize,
}

impl Tail {
    /// from `Ev::tail`: z, the two raw lengths, which are quoted, the type's length; a byte each
    #[inline(always)]
    pub unsafe fn of(p: *const u8, t: u64) -> Tail {
        let f = |i: u32| ((t >> (8 * i)) & 255) as usize;
        let (z, r5, r6, qi, r4) = (f(0), f(1), f(2), f(3), f(4));
        let (qa, qb) = (qi & 1, qi >> 1);
        Tail { pur: r4 & 8 != 0, prod: p.add(32 + 63 - z - r5 + qa), nprod: r5 - 2 * qa, price: p.add(32 + 64 - z + qb), nprice: r6 - 2 * qb }
    }
}

/// commas of bytes 0..64, commas of 32..96, newlines of 32..96
#[inline(always)]
unsafe fn masks3(p: *const u8, k: &Kern) -> (u64, u64, u64) {
    let (a, b, c) = (ld2(p), ld2(p.add(32)), ld2(p.add(64)));
    let (ca, cb, cc) = (eq(a, k.comma), eq(b, k.comma), eq(c, k.comma));
    let (nb, nc) = (eq(b, k.nl), eq(c, k.nl));
    (crate::split::join(ca, cb), crate::split::join(cb, cc), crate::split::join(nb, nc))
}

/// The row at `p`, which needs 16 readable bytes before it and `split::REACH` from it. None says
/// nothing about the row: only that some byte of it is not what the tables expect.
#[inline(always)]
pub unsafe fn ev(p: *const u8, k: &Kern) -> Option<Ev> {
    let pb = p.add(32);
    let (w1c, wbc, wn) = masks3(p, k);
    // three commas from the front
    let c0 = w1c.trailing_zeros() as usize;
    let t = w1c & w1c.wrapping_sub(1);
    let c1 = t.trailing_zeros() as usize;
    let t = t & t.wrapping_sub(1);
    let c2 = t.trailing_zeros() as usize;
    // three back from the newline: the lengths of the last three fields
    let m = wn.trailing_zeros() as usize;
    let tb = _bzhi_u64(wbc, m as u32);
    let z = tb.leading_zeros() as usize;
    let t = tb.wrapping_shl(z as u32) << 1;
    let r5 = t.leading_zeros() as usize;
    let t = t.wrapping_shl(r5 as u32) << 1;
    let r4 = t.leading_zeros() as usize;
    let zr = z + r5;
    // the type starts here, from byte 32; before it an ingest of 20 bytes or 22
    let i4 = 62usize.wrapping_sub(zr + r4);
    let u3 = (i4 + 10).wrapping_sub(c2);
    if (m > 63) | (c2 > 63) | (r4 > 63) | (u3 & !2 != 0) {
        return None;
    }
    let q3 = u3 >> 1;
    let r6 = (m + z).wrapping_sub(64);
    debug_assert!(c0 < c1 && c1 < c2 && r5 < 64 && r6 < 64 && i4 < 64);

    // quotes of the last two fields: only around a whole field
    let tr = T.tail.get_unchecked((r5 << 6) | r6);
    let q32 = eq(ld2(p.add(m)), k.quote);
    let qw = q32.wrapping_shr(!(m + zr) as u32) & tr.m;
    let qi = _pext_u32(qw, tr.sel) as usize;
    let tail_bad = qw != *tr.pat.get_unchecked(qi);

    let rs4 = pb.add(i4);
    let kr = T.kind.get_unchecked((r4 << 1) | (*rs4.add(3) & 1) as usize);
    let bad_kind = _mm_and_si128(_mm_xor_si128(ld(rs4), ld(kr.cand.as_ptr())), ld(kr.mask.as_ptr()));

    let (n, bad_n) = ids36(two(p, p.add(c0 + 1)), T.id.get_unchecked((c0 << 6) | (c1 - c0 - 1)));
    let (cu, bad_cap) = unscr(n, k);

    let tj = T.ts.get_unchecked(((c2 - c1 - 1) << 1) | q3);
    // each date against the cache entry its day picks
    let kp2 = p.add(c1 + tj.koff as usize);
    let kp3 = p.add(c2 + q3);
    let e2 = k.days.add(_pext_u64(rd64(kp2.add(4)), tj.pm) as usize) as *const u8;
    let e3 = k.days.add(_pext_u64(rd64(kp3.add(4)), DATE_BITS) as usize) as *const u8;
    let bad_key = _mm256_and_si256(_mm256_xor_si256(two(kp2, kp3), two(e2, e3)), ld2(tj.kmask.as_ptr()));
    let days = two(e2.add(16), e3.add(16));
    // what follows the dates, or all of a number
    let x = two(p.add(c2).sub(16), rs4.sub(17));
    let d = _mm256_sub_epi8(_mm256_shuffle_epi8(x, ld2(tj.ctrl.as_ptr())), ld2(tj.base.as_ptr()));
    let m1 = _mm256_maddubs_epi16(d, ld2(tj.w1.as_ptr() as *const u8));
    let m2 = _mm256_madd_epi16(m1, ld2(tj.w2.as_ptr() as *const u8));
    let m3 = _mm256_madd_epi16(_mm256_packus_epi32(m2, m2), ld2(tj.w3.as_ptr() as *const u8));
    let bad_a = _mm256_subs_epu8(d, ld2(tj.lim.as_ptr()));
    let bad_b = _mm256_cmpgt_epi32(m2, ld2(tj.limv.as_ptr() as *const u8));
    let t = _mm256_mul_epu32(m3, ld2(tj.ka.as_ptr() as *const u8));
    let f = _mm256_mul_epi32(_mm256_srli_epi64::<32>(m3), ld2(tj.kb.as_ptr() as *const u8));
    let r = _mm256_add_epi64(add_or_sub(t, f, d, ld2(tj.ksel.as_ptr())), days);

    let bad = _mm256_or_si256(or3(bad_n, bad_cap, bad_key), or3(bad_a, bad_b, _mm256_zextsi128_si256(bad_kind)));
    if tail_bad | any(bad) {
        return None;
    }
    let (c, un) = words02(cu);
    let (ts, ing_sec, ing_ms) = words123(r);
    Some(Ev {
        c,
        un,
        ts,
        ing_sec,
        ing_ms,
        next: m + 33,
        tail: (z | (r5 << 8) | (r6 << 16) | (qi << 24) | (r4 << 32)) as u64,
    })
}

/// one to eight digits that end at `end`, which has eight readable bytes before it
#[inline(always)]
pub unsafe fn dec8(end: *const u8, n: usize) -> Option<u32> {
    if n.wrapping_sub(1) > 7 {
        return None;
    }
    const L: u64 = 0x0101_0101_0101_0101;
    // the first digit in the lowest byte kept
    let y = (rd64(end.sub(8)) ^ (L * 0x30)) & (!0u64 << (8 * (8 - n)));
    if (y | y.wrapping_add(L * 6)) & (L * 0xf0) != 0 {
        return None;
    }
    let y = (y.wrapping_mul(10) + (y >> 8)) & 0x00ff_00ff_00ff_00ff;
    let y = (y.wrapping_mul(100) + (y >> 16)) & 0x0000_ffff_0000_ffff;
    Some((y.wrapping_mul(10_000) + (y >> 32)) as u32)
}

// ------------------------------------------------------------------- checks

struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        ((self.0 >> 11) % n as u64) as usize
    }
    /// below `usual`, but one time in `odd` below `wide`
    fn mostly(&mut self, odd: usize, usual: usize, wide: usize) -> usize {
        let n = if self.below(odd) == 0 { wide } else { usual };
        self.below(n)
    }
    fn one(&mut self, of: &[&'static str]) -> &'static str {
        of[self.below(of.len())]
    }
}

/// a field as written: now and then in quotes, rarely with a byte of it changed
fn put(b: &mut Vec<u8>, r: &mut Rng, text: &[u8], last: bool) {
    const JUNK: &[u8] = b"\",\n 09azAZ:+-TZ\r\xff";
    let at = b.len();
    let quoted = r.below(4) == 0;
    if quoted {
        b.push(b'"');
    }
    b.extend_from_slice(text);
    if quoted && r.below(60) != 0 {
        b.push(b'"');
    }
    if b.len() > at && r.below(150) == 0 {
        let i = at + r.below(b.len() - at);
        b[i] = JUNK[r.below(JUNK.len())];
    }
    // a byte more or a byte less
    if b.len() > at && r.below(150) == 0 {
        let i = at + r.below(b.len() - at);
        if r.below(2) == 0 {
            b.insert(i, JUNK[r.below(JUNK.len())]);
        } else {
            b.remove(i);
        }
    }
    b.push(if last { b'\n' } else { b',' });
}

/// event rows as the generator writes them and in every way it damages them, and some it never would
fn sample_events(seed: u64, rows: usize) -> Vec<u8> {
    const DIG: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    const DATES: [&str; 6] = ["2026-04-18", "2026-04-30", "2028-02-29", "2026-05-01", "2026-02-30", "2026-04-00"];
    let mut r = Rng(seed | 1);
    let mut b: Vec<u8> = b"event_id,user_id,ts,ingest_ts,event_type,product_id,price_cents\n".to_vec();
    let mut f: Vec<u8> = Vec::new();
    for _ in 0..rows {
        for letter in [b'e', b'u'] {
            f.clear();
            if letter == b'e' || r.below(30) != 0 {
                f.push(if r.below(50) == 0 { b'E' } else { letter });
                let nd = match r.below(24) {
                    0 => r.below(10),
                    1 => 7,
                    _ => 8,
                };
                for i in 0..nd {
                    // the first digit kept low so that most values fit forty bits
                    let low = i == 0 && nd == 8 && r.below(30) != 0;
                    f.push(DIG[r.below(if low { 14 } else { 36 })]);
                }
            }
            put(&mut b, &mut r, &f, false);
        }
        for ingest in [false, true] {
            let clock = format!("{:02}:{:02}:{:02}", r.mostly(40, 24, 30), r.mostly(40, 60, 70), r.mostly(40, 60, 70));
            let date = DATES[r.mostly(12, 3, 6)];
            let form = if ingest { r.below(30) / 29 * (1 + r.below(4)) } else { r.below(10) };
            let text = match form {
                0 | 5 | 6 | 7 => format!("{}T{}Z", date, clock),
                1 => format!("{}T{}{}{:02}:{:02}", date, clock, r.one(&["+", "-", "-", "+", " "]), r.mostly(20, 24, 30), r.mostly(20, 60, 70)),
                2 | 8 | 9 => format!("17{:011}", r.below(100_000_000_000)),
                3 => format!("{:0w$}", r.below(1_000_000_000), w = 1 + r.below(18)),
                _ => r.one(&["", "2026-04-18 10:00:00Z", "2026-04-18T10:00:00z", "2026-04-18T10:00:00", "1.79e12", "-5", "2026-04-18T10:00:00.5Z", "2026-04-18T10:00:00+0200"]).to_string(),
            };
            put(&mut b, &mut r, text.as_bytes(), false);
        }
        let kind = if r.below(40) == 0 { r.one(&["Purchase", "cart ", "", "views", "purchase\r", "CART", "viex", "cars", "purchasf"]) } else { r.one(&["view", "view", "cart", "purchase"]) };
        put(&mut b, &mut r, kind.as_bytes(), false);
        let prod = match r.below(50) {
            0 => String::new(),
            1 => "x".repeat(1 + r.below(40)),
            _ => format!("p{}", r.below(50_000)),
        };
        put(&mut b, &mut r, prod.as_bytes(), false);
        let price = match r.below(8) {
            0 | 1 | 2 => String::new(),
            3 => r.one(&["0", "-5", "12.5", "10000001", "0250", "1e3"]).to_string(),
            _ => format!("{}", 1 + r.below(50_000)),
        };
        // a field too few or too many, an empty line
        match r.below(60) {
            0 => {
                put(&mut b, &mut r, price.as_bytes(), false);
                put(&mut b, &mut r, b"x", true);
            }
            1 => {
                b.pop();
                b.push(b'\n');
            }
            2 => {
                put(&mut b, &mut r, price.as_bytes(), true);
                b.push(b'\n');
            }
            _ => put(&mut b, &mut r, price.as_bytes(), true),
        }
    }
    b.resize(b.len() + 160, b'\n');
    b
}

/// `ev` over sample rows: whatever it accepts must be what the reference parsers make of the row.
/// Some: how many rows it accepted.
fn check_events(seed: u64, rows: usize) -> Option<usize> {
    use crate::tbl::parse_ts;
    // caps that decide for half the ids, or for none
    let tight = seed & 2 != 0;
    let k = Keys { ek: 0x12_3456_789a, uk: 0xab_cdef_0123, ncap: if tight { 1 << 39 } else { 1 << 40 }, ucap: if tight { 1 << 30 } else { 1 << 31 }, shift: 12 };
    let d = sample_events(seed, rows);
    let mut days = Box::new(Days::new());
    let mut hits = 0;
    let mut p = crate::first_line_start(&d, 0);
    while p + crate::split::REACH <= d.len() {
        let sc = crate::scan_line(&d, p, false);
        let line = &d[p..sc.nl];
        let got = unsafe { ev(d.as_ptr().add(p), &Kern::new(&k, days.as_ptr())) };
        if let Some(e) = got {
            let Some(f) = crate::fields::<7>(line, &sc) else { return None };
            let at = |i: usize| &line[f[i].0 as usize..f[i].1 as usize];
            let t = unsafe { Tail::of(d.as_ptr().add(p), e.tail) };
            let ing = parse_ts(at(3));
            let same = k.counter(at(0)) == e.c
                && e.c != super::NONE
                && k.user(at(1)) == Some(e.un)
                && parse_ts(at(2)) == Some(e.ts)
                && ing == Some(e.ing_ms)
                && e.ing_ms == e.ing_sec * 1000
                && e.ing_sec > 0
                && e.ing_sec <= u32::MAX as i64
                && (at(4) == b"view" || at(4) == b"cart" || at(4) == b"purchase")
                && t.pur == (at(4) == b"purchase")
                && !at(5).is_empty()
                && (t.prod as usize, t.nprod) == (at(5).as_ptr() as usize, at(5).len())
                && (t.price as usize, t.nprice) == (at(6).as_ptr() as usize, at(6).len())
                && e.next == sc.nl + 1 - p
                && dec8_agrees(at(6))
                && dec8_agrees(&at(5)[1..]);
            if !same {
                return None;
            }
            hits += 1;
        } else if let Some(f) = crate::fields::<7>(line, &sc) {
            days.learn(&line[f[2].0 as usize..f[2].1 as usize]);
            days.learn(&line[f[3].0 as usize..f[3].1 as usize]);
        }
        p = sc.nl + 1;
    }
    // slot 0 stands for no date
    if days.e[0].key != [0; 16] || days.e[0].ms != 0 {
        return None;
    }
    Some(hits)
}

/// `dec8` against the digit loop, for a field well inside its buffer
fn dec8_agrees(f: &[u8]) -> bool {
    let want = if f.len() <= 8 { crate::digits_u32(f) } else { None };
    unsafe { dec8(f.as_ptr().add(f.len()), f.len()) == want }
}

/// the tables against the reference parsers, at startup
pub fn agrees() -> bool {
    check_events(0x51_7cc1_b727_220c, 3000).is_some_and(|hits| hits > 400) && check_events(0x51_7cc1_b727_220e, 1000).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_rows_match_the_reference_parsers() {
        let mut hits = 0;
        for seed in 1..=300u64 {
            hits += check_events(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15), 4000).expect("a row the tables accept and the reference reads otherwise");
        }
        assert!(hits > 250_000, "too few rows accepted: {}", hits);
    }

    /// every shape the generator writes must be taken, or the tables are only a detour
    #[test]
    fn clean_event_rows_are_taken() {
        let k = Keys { ek: 0x12_3456_789a, uk: 0xab_cdef_0123, ncap: 1 << 40, ucap: 1 << 31, shift: 12 };
        let mut days = Box::new(Days::new());
        days.learn(b"2026-04-18T");
        days.learn(b"2026-04-17T");
        let q = |on: bool, s: &str| if on { format!("\"{}\"", s) } else { s.to_string() };
        let mut n = 0;
        for bits in 0..128u32 {
            for (eid, uid) in [("e1234567", "u7654321"), ("e123456", "u1"), ("e9", "u765432")] {
                for ts in ["2026-04-18T10:20:30Z", "2026-04-18T23:59:59+12:00", "2026-04-17T00:00:00-10:00", "1776500000123"] {
                    for (kind, prod, price) in [("view", "p1", ""), ("cart", "p49999", "7535"), ("purchase", "p123", "50000")] {
                        // short ids are read only when plain
                        if (bits & 1 != 0 && eid.len() < 8) || (bits & 2 != 0 && uid.len() < 8) {
                            continue;
                        }
                        let f = [eid, uid, ts, "2026-04-18T10:21:00Z", kind, prod, price];
                        let row: Vec<String> = (0..7).map(|i| q(bits >> i & 1 != 0, f[i])).collect();
                        // a newline past byte 95 is out of reach
                        if row.join(",").len() > 95 {
                            continue;
                        }
                        let mut d = vec![b'\n'; 16];
                        d.extend_from_slice(row.join(",").as_bytes());
                        d.resize(d.len() + 160, b'\n');
                        let e = unsafe { ev(d.as_ptr().add(16), &Kern::new(&k, days.as_ptr())) };
                        assert!(e.is_some(), "{}", row.join(","));
                        n += 1;
                    }
                }
            }
        }
        assert!(n > 2000);
    }
}
