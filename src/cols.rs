// one counter range as columns: kept events, their sessions, their rows
use crate::GAP_MS;

/// entries a vector step may read or write past the end of a column
pub(crate) const PAD: usize = 16;
/// user << 9 | alias of no user: before the first event, and after the last
pub(crate) const BEFORE: u32 = 0xffff_fdff;
pub(crate) const AFTER: u32 = 0xffff_ffff;

/// the vector kernels are in the build
pub(crate) const VEC: bool = cfg!(all(
    target_arch = "x86_64",
    target_feature = "avx512f",
    target_feature = "avx512vl",
    target_feature = "avx2",
    target_feature = "popcnt",
    target_feature = "lzcnt",
    target_feature = "bmi2"
));

/// floor(x / 84375) for x < 2^22, as a multiply and a shift by 40
const DAY_MUL: u64 = 13_031_250;

/// days from the day `base` is in to the day of `base + ts`; `rem` is `base` modulo a day
#[inline(always)]
pub(crate) fn day_of(ts: u32, rem: u32) -> u32 {
    ((((ts + rem) >> 10) as u64 * DAY_MUL) >> 40) as u32
}

/// a column with one entry before index 0 and `PAD` after the last
pub(crate) struct Col<T: Copy> {
    /// its own memory, unless it is a piece of a block
    v: Vec<T>,
    at: *mut T,
}

impl<T: Copy> Col<T> {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn new(cap: usize, zero: T) -> Col<T> {
        let mut v = vec![zero; cap + 1 + PAD];
        let at = unsafe { v.as_mut_ptr().add(1) };
        Col { v, at }
    }
    /// the next piece of `block`, from word `*used` on, a multiple of 64 bytes
    fn carve(block: &mut [u64], used: &mut usize, cap: usize) -> Col<T> {
        let words = ((cap + 1 + PAD) * std::mem::size_of::<T>() + 63) / 64 * 8;
        let at = unsafe { (block[*used..*used + words].as_mut_ptr() as *mut T).add(1) };
        *used += words;
        Col { v: Vec::new(), at }
    }
    fn words(cap: usize) -> usize {
        ((cap + 1 + PAD) * std::mem::size_of::<T>() + 63) / 64 * 8
    }
    #[inline(always)]
    pub(crate) fn p(&mut self) -> *mut T {
        debug_assert!(self.v.is_empty() || self.at == unsafe { self.v.as_mut_ptr().add(1) });
        self.at
    }
}

pub(crate) struct Cols {
    /// One block for the slots and every column: at 2 MB or more it is on
    /// huge pages, where 4K pages would miss the TLB on every slot.
    _block: Vec<u64>,
    /// `cap` slots of two words, zeroed
    pub(crate) slots: *mut u64,
    /// user and time of each kept event, in counter order
    pub(crate) cu: Col<u32>,
    pub(crate) ct: Col<u32>,
    /// purchases: event index << 32 | (category << 24 | price)
    pub(crate) pl: Vec<u64>,
    /// events earlier than the one before them in their run
    pub(crate) dis: Vec<u32>,
    /// first event, start and user of each session
    pub(crate) si: Col<u32>,
    pub(crate) st: Col<u32>,
    pub(crate) su: Col<u32>,
    /// day and (revenue << 1 | purchased) of each session
    pub(crate) sd: Col<u8>,
    pub(crate) sv: Col<u64>,
    /// first session, revenue and top category of each row
    pub(crate) rs: Col<u32>,
    pub(crate) rrev: Col<u64>,
    pub(crate) rcat: Col<u8>,
    /// first row of each run of one user's rows
    pub(crate) ps: Col<u32>,
}

impl Cols {
    pub(crate) fn new(cap: usize) -> Cols {
        let words = 2 * cap + 8 + 7 * Col::<u32>::words(cap) + 2 * Col::<u8>::words(cap) + 2 * Col::<u64>::words(cap);
        const HUGE: usize = (2 << 20) / 8;
        let mut block = vec![0u64; (words + HUGE - 1) / HUGE * HUGE];
        let slots = block.as_mut_ptr();
        let mut used = 2 * cap + 8;
        let b = &mut block[..];
        let u = &mut used;
        Cols {
            slots,
            cu: Col::carve(b, u, cap),
            ct: Col::carve(b, u, cap),
            pl: Vec::new(),
            dis: Vec::new(),
            si: Col::carve(b, u, cap),
            st: Col::carve(b, u, cap),
            su: Col::carve(b, u, cap),
            sd: Col::carve(b, u, cap),
            sv: Col::carve(b, u, cap),
            rs: Col::carve(b, u, cap),
            rrev: Col::carve(b, u, cap),
            rcat: Col::carve(b, u, cap),
            ps: Col::carve(b, u, cap),
            _block: block,
        }
    }
}

/// Cut events `0..m` into sessions: a new user (`cu >> 9`), or more than 30 minutes
/// after the event before. `si/st/su[k]` get the first event, start and `cu` of
/// session k, and entry `ns` is the end: event m, user `AFTER`. Events
/// earlier than the one before them in their run go to `dis`.
/// Needs `cu[-1] == BEFORE`, and `cu[m..m + 8] == AFTER`, `ct[m..m + 8] == 0`.
pub(crate) unsafe fn cut_sessions_plain(cu: *const u32, ct: *const u32, m: usize, si: *mut u32, st: *mut u32, su: *mut u32, dis: &mut Vec<u32>) -> usize {
    let mut ns = 0usize;
    for i in 0..=m {
        let (u1, u0) = (*cu.add(i), *cu.offset(i as isize - 1));
        let (t1, t0) = (*ct.add(i), *ct.offset(i as isize - 1));
        if (u1 ^ u0) > 511 || t1.wrapping_sub(t0) > GAP_MS {
            *si.add(ns) = i as u32;
            *st.add(ns) = t1;
            *su.add(ns) = u1;
            ns += 1;
        }
        if (u1 ^ u0) <= 511 && t1 < t0 {
            dis.push(i as u32);
        }
    }
    ns - 1
}

/// Cut sessions `0..ns` into rows: a new user or a new day. `sd[k]` gets the
/// day of session k, `rs[r]` the first session of row r, and entry `nr` is
/// the end: session ns. Needs `su[-1] == BEFORE`, and `su[ns..ns + 9] == AFTER`,
/// `st[ns..ns + 9] == 0`.
pub(crate) unsafe fn cut_rows_plain(st: *const u32, su: *const u32, ns: usize, rem: u32, off: u32, sd: *mut u8, rs: *mut u32) -> usize {
    let mut nr = 0usize;
    let mut prev = 0u32;
    for k in 0..=ns {
        let day = day_of(*st.add(k), rem).wrapping_add(off);
        *sd.add(k) = day as u8;
        if (*su.add(k) ^ *su.offset(k as isize - 1)) > 511 || (k > 0 && day != prev) {
            *rs.add(nr) = k as u32;
            nr += 1;
        }
        prev = day;
    }
    nr - 1
}

#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx512f",
    target_feature = "avx512vl",
    target_feature = "avx2",
    target_feature = "popcnt",
    target_feature = "bmi2"
))]
pub(crate) mod v {
    use super::*;
    use core::arch::x86_64::*;

    const fn pack_tbl() -> [[u32; 8]; 16] {
        let mut t = [[0u32; 8]; 16];
        let mut m = 0;
        while m < 16 {
            let (mut q, mut n) = (0, 0);
            while q < 4 {
                if m >> q & 1 != 0 {
                    t[m][n] = 2 * q as u32;
                    t[m][4 + n] = 2 * q as u32 + 1;
                    n += 1;
                }
                q += 1;
            }
            m += 1;
        }
        t
    }

    /// for each set of kept slots, where their (user, time) pairs go
    #[repr(C, align(64))]
    struct Pack([[u32; 8]; 16]);
    static PACK: Pack = Pack(pack_tbl());

    /// Four slots of (a, b) words at `s`: the plain events are packed into
    /// `cu` (user and alias) and `ct`. Returns their bits, whether any slot
    /// holds a price, and the bits of the escaped slots.
    #[inline(always)]
    pub(crate) unsafe fn slots4(s: *const u64, cu: *mut u32, ct: *mut u32) -> (u32, bool, u32) {
        // read apart: two loads side by side are merged into one of 512 bits
        let y0 = std::ptr::read_volatile(s as *const __m256i);
        let y1 = std::ptr::read_volatile(s.add(4) as *const __m256i);
        let a = _mm256_permutex2var_epi64(y0, _mm256_setr_epi64x(0, 2, 4, 6), y1);
        // tag 2 is a plain event, 3 an escaped one: bits 1 and 0 as signs
        let b1 = _mm256_movemask_pd(_mm256_castsi256_pd(_mm256_slli_epi64::<62>(a))) as u32;
        let b0 = _mm256_movemask_pd(_mm256_castsi256_pd(_mm256_slli_epi64::<63>(a))) as u32;
        let live = b1 & !b0;
        // user and alias in the low half of each word, the time in the high half
        let un = _mm256_and_si256(_mm256_srli_epi64::<2>(a), _mm256_set1_epi64x(0x7fff_ffff));
        let x = _mm256_blend_epi32::<0xaa>(un, _mm256_srli_epi64::<1>(a));
        let idx = _mm256_load_si256(PACK.0.as_ptr().add(live as usize) as *const __m256i);
        let packed = _mm256_permutevar8x32_epi32(x, idx);
        _mm_storeu_si128(cu as *mut __m128i, _mm256_castsi256_si128(packed));
        store_high(ct, packed);
        // a price is the high half of a b word
        let zero = _mm256_cmpeq_epi32(_mm256_or_si256(y0, y1), _mm256_setzero_si256());
        let priced = _mm256_movemask_ps(_mm256_castsi256_ps(zero)) & 0x88 != 0x88;
        (live, priced, b1 & b0)
    }

    #[inline(always)]
    unsafe fn store_high(p: *mut u32, v: __m256i) {
        _mm_storeu_si128(p as *mut __m128i, _mm256_extracti128_si256::<1>(v));
    }

    #[inline(always)]
    pub(crate) unsafe fn zero4(s: *mut u64) {
        _mm256_storeu_si256(s as *mut __m256i, _mm256_setzero_si256());
        _mm256_storeu_si256(s.add(4) as *mut __m256i, _mm256_setzero_si256());
    }

    /// whether any of the `n` events at `cu` has an alias above `top`
    #[inline(always)]
    pub(crate) unsafe fn alias_over(cu: *const u32, n: usize, top: u32) -> bool {
        let (low, topv) = (_mm256_set1_epi32(511), _mm256_set1_epi32(top as i32));
        let mut over = 0u32;
        let mut i = 0usize;
        while i < n {
            let part = _bzhi_u32(0xff, (n - i).min(8) as u32);
            over |= part & _mm256_cmpgt_epu32_mask(_mm256_and_si256(_mm256_loadu_si256(cu.add(i) as *const __m256i), low), topv) as u32;
            i += 8;
        }
        over != 0
    }

    /// `cut_sessions_plain`, eight events a step
    pub(crate) unsafe fn cut_sessions(cu: *const u32, ct: *const u32, m: usize, si: *mut u32, st: *mut u32, su: *mut u32, dis: &mut Vec<u32>) -> usize {
        let gap = _mm256_set1_epi32(GAP_MS as i32);
        let alias = _mm256_set1_epi32(511);
        let mut at = _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7);
        let eight = _mm256_set1_epi32(8);
        let mut ns = 0usize;
        let mut i = 0usize;
        while i <= m {
            let u1 = _mm256_loadu_si256(cu.add(i) as *const __m256i);
            let u0 = _mm256_loadu_si256(cu.offset(i as isize - 1) as *const __m256i);
            let t1 = _mm256_loadu_si256(ct.add(i) as *const __m256i);
            let t0 = _mm256_loadu_si256(ct.offset(i as isize - 1) as *const __m256i);
            let r = _mm256_cmpgt_epu32_mask(_mm256_xor_si256(u1, u0), alias);
            let s = r | _mm256_cmpgt_epu32_mask(_mm256_sub_epi32(t1, t0), gap);
            let d = !r & _mm256_cmplt_epu32_mask(t1, t0);
            _mm256_storeu_si256(si.add(ns) as *mut __m256i, _mm256_maskz_compress_epi32(s, at));
            _mm256_storeu_si256(st.add(ns) as *mut __m256i, _mm256_maskz_compress_epi32(s, t1));
            _mm256_storeu_si256(su.add(ns) as *mut __m256i, _mm256_maskz_compress_epi32(s, u1));
            ns += (s as u32).count_ones() as usize;
            if d != 0 {
                let mut d = d as u32;
                while d != 0 {
                    dis.push((i + d.trailing_zeros() as usize) as u32);
                    d &= d - 1;
                }
            }
            at = _mm256_add_epi32(at, eight);
            i += 8;
        }
        ns - 1
    }

    #[inline(always)]
    unsafe fn day8(t: __m256i, rem: __m256i, off: __m256i) -> __m256i {
        let mul = _mm256_set1_epi64x(DAY_MUL as i64);
        let y = _mm256_srli_epi32::<10>(_mm256_add_epi32(t, rem));
        let even = _mm256_srli_epi64::<40>(_mm256_mul_epu32(y, mul));
        // the quotient of an odd lane lands in its own upper half
        let odd = _mm256_srli_epi64::<8>(_mm256_mul_epu32(_mm256_srli_epi64::<32>(y), mul));
        _mm256_add_epi32(_mm256_blend_epi32::<0xaa>(even, odd), off)
    }

    /// `cut_rows_plain`, eight sessions a step
    pub(crate) unsafe fn cut_rows(st: *const u32, su: *const u32, ns: usize, rem: u32, off: u32, sd: *mut u8, rs: *mut u32) -> usize {
        let (remv, offv) = (_mm256_set1_epi32(rem as i32), _mm256_set1_epi32(off as i32));
        let alias = _mm256_set1_epi32(511);
        let mut at = _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7);
        let eight = _mm256_set1_epi32(8);
        let mut nr = 0usize;
        let mut k = 0usize;
        // session 0 starts a row whatever is read as the day before it
        while k <= ns {
            let u1 = _mm256_loadu_si256(su.add(k) as *const __m256i);
            let u0 = _mm256_loadu_si256(su.offset(k as isize - 1) as *const __m256i);
            let d1 = day8(_mm256_loadu_si256(st.add(k) as *const __m256i), remv, offv);
            let d0 = day8(_mm256_loadu_si256(st.offset(k as isize - 1) as *const __m256i), remv, offv);
            let w = _mm256_cmpgt_epu32_mask(_mm256_xor_si256(u1, u0), alias) | _mm256_cmpneq_epi32_mask(d1, d0);
            _mm_storel_epi64(sd.add(k) as *mut __m128i, _mm256_cvtepi32_epi8(d1));
            _mm256_storeu_si256(rs.add(nr) as *mut __m256i, _mm256_maskz_compress_epi32(w, at));
            nr += (w as u32).count_ones() as usize;
            at = _mm256_add_epi32(at, eight);
            k += 8;
        }
        nr - 1
    }
}

/// (campaign, day) cells held before they are counted
const CELLS: usize = 16_384;
/// the most clicks a person may have for the vector attribution
pub(crate) const MID: usize = 256;

/// what the vector attribution keeps between persons
#[repr(C, align(64))]
pub(crate) struct Light {
    ts: [u32; 32],
    camp: [u32; 32],
    /// the clicks in time order: time, campaign, campaign * stride, and what
    /// says which click of the same campaign came before
    sts: Vec<u32>,
    scamp: Vec<u32>,
    scell: Vec<u32>,
    conf: Vec<u32>,
    /// the place in the person's list of each click in time order
    sidx: Vec<u32>,
    keys: Vec<u64>,
    /// per campaign, its latest click so far; zero between persons
    last: Vec<u32>,
    /// (campaign, day) cells with one more assisted session each
    cells: Vec<u32>,
    nl: usize,
    /// (campaign, day) cells with one more credited session each
    creds: Vec<u32>,
    nc: usize,
}

impl Light {
    pub(crate) fn new(ncamp: usize) -> Light {
        Light {
            ts: [0; 32],
            camp: [0; 32],
            sts: vec![0; MID + 16],
            scamp: vec![0; MID + 16],
            scell: vec![0; MID + 16],
            conf: vec![0; MID + 16],
            sidx: vec![0; MID + 16],
            keys: Vec::with_capacity(MID),
            last: vec![0; ncamp + 1],
            cells: vec![0; CELLS],
            nl: 0,
            creds: vec![0; CELLS],
            nc: 0,
        }
    }
    /// count the assists and the credits noted so far: far apart in memory,
    /// they are quicker one after the other than each amid its person
    #[inline]
    pub(crate) fn flush(&mut self, asst: &mut [u32], cs: &mut [u32]) {
        for &c in &self.cells[..self.nl] {
            asst[c as usize] += 1;
        }
        self.nl = 0;
        for &c in &self.creds[..self.nc] {
            cs[c as usize] += 1;
        }
        self.nc = 0;
    }
}

#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx512f",
    target_feature = "avx512vl",
    target_feature = "avx2",
    target_feature = "popcnt",
    target_feature = "lzcnt",
    target_feature = "bmi2"
))]
pub(crate) mod va {
    use super::*;
    use crate::{Click, WEEK};
    use core::arch::x86_64::*;

    /// -1 in the first 32 places: read from 32 - i, the lanes before lane i
    #[repr(C, align(64))]
    struct Step([i32; 72]);
    static STEP: Step = Step({
        let mut t = [0i32; 72];
        let mut i = 0;
        while i < 32 {
            t[i] = -1;
            i += 1;
        }
        t
    });

    /// The lanes of `a` that are `P` to those of `b`, unsigned (0 equal, 1
    /// below, 2 at most). Spelled out: given the compare itself, the compiler
    /// joins two of them into one of 512 bits, which this machine pays for
    /// with its clock.
    #[inline(always)]
    unsafe fn cmp8<const P: i32>(a: __m256i, b: __m256i) -> u32 {
        let r: u32;
        std::arch::asm!(
            "vpcmpud {k}, {a}, {b}, {p}",
            "kmovb {r:e}, {k}",
            k = out(kreg) _,
            a = in(ymm_reg) a,
            b = in(ymm_reg) b,
            p = const P,
            r = lateout(reg) r,
            options(pure, nomem, nostack, preserves_flags)
        );
        r
    }

    /// sessions, those with purchases, and revenue per (campaign, day)
    pub(crate) type Cells = (*mut u32, *mut u32, *mut u64);

    /// the session itself goes on the list; a purchase is rare and counted here
    #[inline(always)]
    unsafe fn credit(cd: Cells, creds: *mut u32, nc: &mut usize, cell: usize, v: u64) {
        *creds.add(*nc) = cell as u32;
        *nc += 1;
        if v != 0 {
            *cd.1.add(cell) += 1;
            *cd.2.add(cell) += v >> 1;
        }
    }

    #[inline(always)]
    unsafe fn flush_all(lt: &mut Light, cd: Cells, asst: &mut [u32]) {
        let cs = std::slice::from_raw_parts_mut(cd.0, asst.len());
        lt.flush(asst, cs);
    }

    /// Credit and assists for a person of 1 to `MID` clicks, in any order,
    /// and `ns` sessions in time order: starts `ss`, days `sd`, (revenue << 1
    /// | purchased) `sv`. `cd` and `asst` are indexed campaign * stride + day;
    /// assists may stay in `lt` until its next flush. Of two clicks at one
    /// time, `before(j, i)` says whether j is the earlier: the later is credited.
    /// That question reads the ids, far away and cold. With `hold`, a person
    /// who needs it asked is left alone: `hold` is told the clicks concerned,
    /// to ask for their ids, and false comes back.
    #[inline]
    pub(crate) unsafe fn attribute<C: Click>(
        lt: &mut Light,
        before: &dyn Fn(usize, usize) -> bool,
        hold: Option<&dyn Fn(usize)>,
        cl: &[C],
        ss: *const u32,
        sd: *const u8,
        sv: *const u64,
        ns: usize,
        stride: usize,
        organic: usize,
        cd: Cells,
        asst: &mut [u32],
    ) -> bool {
        match (cl.len() + 7) / 8 {
            1 => light::<C, 1>(lt, before, hold, cl, ss, sd, sv, ns, stride, organic, cd, asst),
            2 => light::<C, 2>(lt, before, hold, cl, ss, sd, sv, ns, stride, organic, cd, asst),
            3 => light::<C, 3>(lt, before, hold, cl, ss, sd, sv, ns, stride, organic, cd, asst),
            4 => light::<C, 4>(lt, before, hold, cl, ss, sd, sv, ns, stride, organic, cd, asst),
            _ => mid(lt, before, hold, cl, ss, sd, sv, ns, stride, organic, cd, asst),
        }
    }

    /// at most 8 * NV clicks: each session meets all of them in NV compares
    #[inline(always)]
    unsafe fn light<C: Click, const NV: usize>(
        lt: &mut Light,
        before: &dyn Fn(usize, usize) -> bool,
        hold: Option<&dyn Fn(usize)>,
        cl: &[C],
        ss: *const u32,
        sd: *const u8,
        sv: *const u64,
        ns: usize,
        stride: usize,
        organic: usize,
        cd: Cells,
        asst: &mut [u32],
    ) -> bool {
        let n = cl.len();
        debug_assert!(n >= 1 && n <= 8 * NV && NV <= 4);
        let tp = lt.ts.as_mut_ptr();
        // no click is at a time with the top bit
        let ones = _mm256_set1_epi32(-1);
        for v in 0..NV {
            _mm256_store_si256(tp.add(8 * v) as *mut __m256i, ones);
        }
        // one at a time: as a loop over vectors it would take 512-bit ones
        for (i, c) in cl.iter().enumerate() {
            std::ptr::write_volatile(tp.add(i), c.ts());
            *lt.camp.get_unchecked_mut(i) = c.camp() as u32;
        }
        let mut t = [ones; NV];
        for v in 0..NV {
            t[v] = _mm256_load_si256(tp.add(8 * v) as *const __m256i);
        }
        let (sts, scamp, conf, sidx) = (lt.sts.as_mut_ptr(), lt.scamp.as_mut_ptr(), lt.conf.as_mut_ptr(), lt.sidx.as_mut_ptr());
        // A click's place in time order is the number of clicks before it:
        // those earlier, and of those at its time the ones listed before it,
        // which is "below its time plus one" for the lanes before its own.
        for i in 0..n {
            let b = _mm256_set1_epi32(*tp.add(i) as i32);
            let mut r = 0u32;
            for v in 0..NV {
                let step = _mm256_loadu_si256(STEP.0.as_ptr().add(32 - i + 8 * v) as *const __m256i);
                r += cmp8::<1>(t[v], _mm256_sub_epi32(b, step)).count_ones();
            }
            *sts.add(r as usize) = *tp.add(i);
            *scamp.add(r as usize) = *lt.camp.get_unchecked(i);
            *sidx.add(r as usize) = i as u32;
        }
        let mut tied = false;
        for r in 1..n {
            tied |= *sts.add(r) == *sts.add(r - 1) && *scamp.add(r) != *scamp.add(r - 1);
        }
        if tied {
            if let Some(hold) = hold {
                for r in 0..n {
                    if (r > 0 && *sts.add(r) == *sts.add(r - 1)) || (r + 1 < n && *sts.add(r) == *sts.add(r + 1)) {
                        hold(*sidx.add(r) as usize);
                    }
                }
                return false;
            }
            order_ties(std::slice::from_raw_parts(sts, n), std::slice::from_raw_parts_mut(scamp, n), std::slice::from_raw_parts_mut(sidx, n), before);
        }
        // the bit of the click before of the same campaign, or none
        let last = lt.last.as_mut_ptr();
        for i in 0..n {
            let c = *scamp.add(i) as usize;
            *conf.add(i) = *last.add(c);
            *last.add(c) = 1 << i;
        }
        for i in 0..n {
            *last.add(*scamp.add(i) as usize) = 0;
        }
        let valid = !0u32 >> (32 - n);
        let week = _mm256_set1_epi32(WEEK as i32);
        let stv = _mm256_set1_epi32(stride as i32);
        let (mut s, mut f, mut c) = ([ones; NV], [ones; NV], [ones; NV]);
        for v in 0..NV {
            s[v] = _mm256_loadu_si256(sts.add(8 * v) as *const __m256i);
            f[v] = _mm256_loadu_si256(conf.add(8 * v) as *const __m256i);
            c[v] = _mm256_mullo_epi32(_mm256_loadu_si256(scamp.add(8 * v) as *const __m256i), stv);
        }
        let org = organic * stride;
        if lt.nl + ns * 32 + 32 > CELLS || lt.nc + ns > CELLS {
            flush_all(lt, cd, asst);
        }
        let (mut nl, mut nc) = (lt.nl, lt.nc);
        let (list, creds) = (lt.cells.as_mut_ptr(), lt.creds.as_mut_ptr());
        for k in 0..ns {
            if ns > 256 && (nl + 64 > CELLS || nc == CELLS) {
                (lt.nl, lt.nc) = (nl, nc);
                flush_all(lt, cd, asst);
                (nl, nc) = (0, 0);
            }
            let start = _mm256_set1_epi32(*ss.add(k) as i32);
            // a click after the start is a huge time before it
            let mut win = 0u32;
            for v in 0..NV {
                win |= cmp8::<2>(_mm256_sub_epi32(start, s[v]), week) << (8 * v);
            }
            win &= valid;
            let day = *sd.add(k) as usize;
            // the latest click in the window has its top bit
            let top = 31 - (win | 1).leading_zeros() as usize;
            let by = *scamp.add(top) as usize * stride;
            let cell = if win != 0 { by } else { org };
            credit(cd, creds, &mut nc, cell + day, *sv.add(k));
            // a campaign assists once: by its first click in the window
            let low = _mm256_set1_epi32((win & win.wrapping_neg()) as i32);
            let dv = _mm256_set1_epi32(day as i32);
            for v in 0..NV {
                let a = (win >> (8 * v)) & cmp8::<1>(f[v], low);
                _mm256_storeu_si256(list.add(nl) as *mut __m256i, _mm256_maskz_compress_epi32(a as u8, _mm256_add_epi32(c[v], dv)));
                nl += a.count_ones() as usize;
            }
        }
        (lt.nl, lt.nc) = (nl, nc);
        true
    }

    /// 33 to `MID` clicks: sorted, and a window that slides along them
    #[inline(never)]
    unsafe fn mid<C: Click>(
        lt: &mut Light,
        before: &dyn Fn(usize, usize) -> bool,
        hold: Option<&dyn Fn(usize)>,
        cl: &[C],
        ss: *const u32,
        sd: *const u8,
        sv: *const u64,
        ns: usize,
        stride: usize,
        organic: usize,
        cd: Cells,
        asst: &mut [u32],
    ) -> bool {
        let n = cl.len();
        debug_assert!(n <= MID);
        let sidx = lt.sidx.as_mut_ptr();
        let (sts, scamp, scell, conf) = (lt.sts.as_mut_ptr(), lt.scamp.as_mut_ptr(), lt.scell.as_mut_ptr(), lt.conf.as_mut_ptr());
        // by time, and at one time as listed; too many to rank each against all
        lt.keys.clear();
        for (i, c) in cl.iter().enumerate() {
            lt.keys.push(((c.ts() as u64) << 32) | i as u64);
        }
        lt.keys.sort_unstable();
        for (r, &key) in lt.keys.iter().enumerate() {
            let i = key as u32;
            *sts.add(r) = (key >> 32) as u32;
            *scamp.add(r) = cl.get_unchecked(i as usize).camp() as u32;
            *sidx.add(r) = i;
        }
        // no click is at a time with the top bit: it ends the list
        _mm256_storeu_si256(sts.add(n) as *mut __m256i, _mm256_set1_epi32(-1));
        let mut tied = false;
        for r in 1..n {
            tied |= *sts.add(r) == *sts.add(r - 1) && *scamp.add(r) != *scamp.add(r - 1);
        }
        if tied {
            if let Some(hold) = hold {
                for r in 0..n {
                    if (r > 0 && *sts.add(r) == *sts.add(r - 1)) || (r + 1 < n && *sts.add(r) == *sts.add(r + 1)) {
                        hold(*sidx.add(r) as usize);
                    }
                }
                return false;
            }
            order_ties(std::slice::from_raw_parts(sts, n), std::slice::from_raw_parts_mut(scamp, n), std::slice::from_raw_parts_mut(sidx, n), before);
        }
        let last = lt.last.as_mut_ptr();
        // one more than the place of the click before of the same campaign, or 0
        for i in 0..n {
            let c = *scamp.add(i) as usize;
            *scell.add(i) = (c * stride) as u32;
            *conf.add(i) = *last.add(c);
            *last.add(c) = i as u32 + 1;
        }
        for i in 0..n {
            *last.add(*scamp.add(i) as usize) = 0;
        }
        let org = organic * stride;
        let (mut nl, mut nc) = (lt.nl, lt.nc);
        let (list, creds) = (lt.cells.as_mut_ptr(), lt.creds.as_mut_ptr());
        let (mut lo, mut hi) = (0usize, 0usize);
        let week = _mm256_set1_epi32(WEEK as i32);
        for k in 0..ns {
            if nl + n + 16 > CELLS || nc == CELLS {
                (lt.nl, lt.nc) = (nl, nc);
                flush_all(lt, cd, asst);
                (nl, nc) = (0, 0);
            }
            let s = *ss.add(k);
            let sv8 = _mm256_set1_epi32(s as i32);
            // both ends only move forward, and seldom by 8 clicks at once
            loop {
                let c = cmp8::<2>(_mm256_loadu_si256(sts.add(hi) as *const __m256i), sv8).count_ones() as usize;
                hi += c;
                if c != 8 {
                    break;
                }
            }
            loop {
                let old = cmp8::<6>(_mm256_sub_epi32(sv8, _mm256_loadu_si256(sts.add(lo) as *const __m256i)), week);
                let c = (old & _bzhi_u32(0xff, (hi - lo).min(8) as u32)).count_ones() as usize;
                lo += c;
                if c != 8 {
                    break;
                }
            }
            let day = *sd.add(k) as usize;
            let cell = if lo < hi { *scell.add(hi - 1) as usize } else { org };
            credit(cd, creds, &mut nc, cell + day, *sv.add(k));
            // a campaign assists once: by its first click in the window
            let low = _mm256_set1_epi32(lo as i32);
            let dv = _mm256_set1_epi32(day as i32);
            let mut x = lo;
            while x < hi {
                let part = _bzhi_u32(0xff, (hi - x).min(8) as u32);
                let a = part & _mm256_cmple_epu32_mask(_mm256_loadu_si256(conf.add(x) as *const __m256i), low) as u32;
                let cells = _mm256_add_epi32(_mm256_loadu_si256(scell.add(x) as *const __m256i), dv);
                _mm256_storeu_si256(list.add(nl) as *mut __m256i, _mm256_maskz_compress_epi32(a as u8, cells));
                nl += a.count_ones() as usize;
                x += 8;
            }
        }
        (lt.nl, lt.nc) = (nl, nc);
        true
    }

    /// Clicks of one time and several campaigns in the order `before` gives;
    /// `idx` holds each click's place in the person's list.
    #[cold]
    #[inline(never)]
    fn order_ties(ts: &[u32], camp: &mut [u32], idx: &mut [u32], before: &dyn Fn(usize, usize) -> bool) {
        let mut i = 0;
        while i < ts.len() {
            let mut j = i + 1;
            while j < ts.len() && ts[j] == ts[i] {
                j += 1;
            }
            // of one campaign, as copies of a click are, their order changes nothing
            if camp[i..j].iter().any(|&c| c != camp[i]) {
                // a handful: by insertion, one click at a time
                for a in i + 1..j {
                    let (x, c) = (idx[a], camp[a]);
                    let mut b = a;
                    while b > i && before(x as usize, idx[b - 1] as usize) {
                        idx[b] = idx[b - 1];
                        camp[b] = camp[b - 1];
                        b -= 1;
                    }
                    idx[b] = x;
                    camp[b] = c;
                }
            }
            i = j;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::{Click, DAY_MS, WEEK};

    #[test]
    fn day_by_multiply() {
        // exact at both sides of every day the 32 bits hold
        for rem in [0u32, 1, 1023, 1024, 86_399_999, 43_200_000] {
            let mut d = 0u64;
            while d * DAY_MS as u64 <= u32::MAX as u64 + DAY_MS as u64 {
                for x in [d * DAY_MS as u64 - (d > 0) as u64, d * DAY_MS as u64, d * DAY_MS as u64 + 1] {
                    if x >= rem as u64 && x - (rem as u64) < (1 << 31) {
                        assert_eq!(day_of((x - rem as u64) as u32, rem) as u64, x / DAY_MS as u64, "{} {}", x, rem);
                    }
                }
                d += 1;
            }
        }
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..2_000_000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let (ts, rem) = ((x >> 33) as u32, ((x & 0xffff_ffff) % DAY_MS as u64) as u32);
            assert_eq!(day_of(ts, rem) as u64, (ts as u64 + rem as u64) / DAY_MS as u64);
        }
    }

    /// events of a few users with every kind of gap, some out of order
    #[cfg_attr(not(all(target_arch = "x86_64", target_feature = "avx512f", target_feature = "avx512vl", target_feature = "avx2", target_feature = "popcnt")), allow(dead_code))]
    fn events(seed: u64, m: usize) -> (Col<u32>, Col<u32>) {
        let (mut cu, mut ct) = (Col::new(m, 0u32), Col::new(m, 0u32));
        let mut x = seed | 1;
        let (mut user, mut t) = (5u32, 1000u32);
        unsafe {
            *cu.p().offset(-1) = BEFORE;
            for i in 0..m {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                match x % 23 {
                    0 | 1 => {
                        user += 1 + (x >> 20) as u32 % 3;
                        t = (x >> 30) as u32 % (1 << 30);
                    }
                    2 => t += GAP_MS,
                    3 => t += GAP_MS + 1,
                    4 => t += GAP_MS - 1,
                    5 => t += 86_400_000 - (x >> 40) as u32 % 3,
                    6 => t = t.saturating_sub((x >> 40) as u32 % 5000),
                    7 => {}
                    _ => t += (x >> 40) as u32 % 600_000,
                }
                t &= 0x7fff_ffff;
                *cu.p().add(i) = (user << 9) | ((x >> 50) as u32 % 4);
                *ct.p().add(i) = t;
            }
            for i in m..m + 8 {
                *cu.p().add(i) = AFTER;
                *ct.p().add(i) = 0;
            }
        }
        (cu, ct)
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f", target_feature = "avx512vl", target_feature = "avx2", target_feature = "popcnt"))]
    #[test]
    fn vector_cuts_match_plain() {
        for round in 0..400u64 {
            let m = [0usize, 1, 2, 7, 8, 9, 15, 16, 17, 100, 1000, 4097][(round % 12) as usize];
            let (mut cu, mut ct) = events(round * 7919 + 1, m);
            let mk = || (Col::new(m + 1, 7u32), Col::new(m + 1, 7u32), Col::new(m + 1, 7u32));
            let (mut si, mut st, mut su) = mk();
            let (mut si2, mut st2, mut su2) = mk();
            let (mut dis, mut dis2) = (Vec::new(), Vec::new());
            unsafe {
                *su.p().offset(-1) = BEFORE;
                *su2.p().offset(-1) = BEFORE;
                let ns = cut_sessions_plain(cu.p(), ct.p(), m, si.p(), st.p(), su.p(), &mut dis);
                let ns2 = v::cut_sessions(cu.p(), ct.p(), m, si2.p(), st2.p(), su2.p(), &mut dis2);
                assert_eq!(ns, ns2, "round {}", round);
                assert_eq!(dis, dis2, "round {}", round);
                for k in 0..=ns {
                    assert_eq!((*si.p().add(k), *st.p().add(k), *su.p().add(k)), (*si2.p().add(k), *st2.p().add(k), *su2.p().add(k)), "round {} session {}", round, k);
                }
                assert_eq!((*si.p().add(ns), *su.p().add(ns)), (m as u32, AFTER));
                for c in [&mut st, &mut su, &mut st2, &mut su2] {
                    let fill = if *c.p().add(ns) == AFTER { AFTER } else { 0 };
                    for k in ns..ns + 9 {
                        *c.p().add(k) = fill;
                    }
                }
                let (rem, off) = ((round as u32 * 7_654_321) % DAY_MS as u32, round as u32 % 3);
                let (mut sd, mut rs) = (Col::new(m + 1, 9u8), Col::new(m + 1, 9u32));
                let (mut sd2, mut rs2) = (Col::new(m + 1, 9u8), Col::new(m + 1, 9u32));
                let nr = cut_rows_plain(st.p(), su.p(), ns, rem, off, sd.p(), rs.p());
                let nr2 = v::cut_rows(st2.p(), su2.p(), ns, rem, off, sd2.p(), rs2.p());
                assert_eq!(nr, nr2, "round {}", round);
                for k in 0..=ns {
                    assert_eq!(*sd.p().add(k), *sd2.p().add(k), "round {} day {}", round, k);
                }
                for r in 0..=nr {
                    assert_eq!(*rs.p().add(r), *rs2.p().add(r), "round {} row {}", round, r);
                }
                assert_eq!(*rs.p().add(nr), ns as u32);
            }
        }
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f", target_feature = "avx512vl", target_feature = "avx2", target_feature = "popcnt"))]
    #[test]
    fn slots_pack_like_one_at_a_time() {
        let mut x = 0x1234_5678_9abc_def1u64;
        for _ in 0..200_000 {
            let mut s = [0u64; 8];
            for q in 0..4 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let tag = [0u64, 1, 2, 2, 2, 2, 2, 3][(x % 8) as usize];
                let (un, ts) = ((x >> 8) & 0x7fff_ffff, (x >> 24) & 0x7fff_ffff);
                s[2 * q] = if tag == 0 { 0 } else { (ts << 33) | (un << 2) | tag };
                s[2 * q + 1] = if x >> 60 < 4 { ((x >> 40) & 0xffff) << 32 } else { 0 } | (x & 0xffff_ffff);
            }
            let (mut cu, mut ct) = ([0u32; 4], [0u32; 4]);
            let (live, priced, esc) = unsafe { v::slots4(s.as_ptr(), cu.as_mut_ptr(), ct.as_mut_ptr()) };
            assert_eq!(priced, (0..4).any(|q| s[2 * q + 1] >> 32 != 0));
            let mut n = 0;
            for q in 0..4 {
                let a = s[2 * q];
                assert_eq!(live >> q & 1 != 0, a & 3 == 2);
                assert_eq!(esc >> q & 1 != 0, a & 3 == 3);
                if a & 3 == 2 {
                    assert_eq!((cu[n], ct[n]), (((a >> 2) & 0x7fff_ffff) as u32, (a >> 33) as u32));
                    n += 1;
                }
            }
        }
    }

    /// a click with its time, campaign and one of a few ids
    #[derive(Copy, Clone)]
    #[allow(dead_code)]
    struct TC(u32, u32, u32);
    #[allow(dead_code)]
    static IDS: [&[u8]; 4] = [b"k1", b"k10", b"k2", b"k2"];
    impl Click for TC {
        fn ts(&self) -> u32 {
            self.0
        }
        fn camp(&self) -> usize {
            self.1 as usize
        }
        fn id<'a>(&self, _ctx: &'a crate::Ctx, _at: usize) -> &'a [u8] {
            IDS[self.2 as usize]
        }
    }

    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f", target_feature = "avx512vl", target_feature = "avx2", target_feature = "popcnt", target_feature = "lzcnt", target_feature = "bmi2"))]
    #[test]
    fn vector_attribution_matches_the_rules() {
        let (ncamp, stride) = (6usize, 9usize);
        let mut lt = Light::new(ncamp);
        let mut x = 0x0bad_5eed_1234_5678u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut tied = 0;
        let mut asst = vec![0u32; (ncamp + 1) * stride];
        let mut asst2 = vec![0u32; (ncamp + 1) * stride];
        for round in 0..60_000 {
            let nc = 1 + (next() % [8, 16, 32, 80, 256][round % 5]) as usize;
            let ns = 1 + (next() % if round % 97 == 0 { 3000 } else { 40 }) as usize;
            let span = [WEEK / 2, WEEK * 2, 5000, 1 << 30][(round / 4) % 4];
            let mut ss: Vec<u32> = (0..ns).map(|_| 1_000_000 + (next() % span as u64) as u32).collect();
            ss.sort_unstable();
            let sd: Vec<u8> = (0..ns).map(|_| (next() % 7) as u8).collect();
            let sv: Vec<u64> = (0..ns).map(|_| if next() % 3 == 0 { (next() % 100_000) << 1 | 1 } else { 0 }).collect();
            let cl: Vec<TC> = (0..nc)
                .map(|_| {
                    let r = next();
                    // at a start, a week before it to the millisecond, or anywhere
                    let at = ss[(r >> 8) as usize % ns];
                    let ts = match r % 6 {
                        0 => at,
                        1 => at.saturating_sub(WEEK),
                        2 => at.saturating_sub(WEEK + 1),
                        3 => at + 1,
                        _ => (1_000_000 + (r >> 20) % (span as u64 + WEEK as u64)) as u32 - (WEEK / 2).min(900_000),
                    } & 0x7fff_ffff;
                    // copies of a click agree on everything
                    let id = (r >> 50) as u32 % 4;
                    TC(ts, (ts ^ IDS[id as usize].len() as u32 ^ IDS[id as usize][1] as u32) % ncamp as u32, id)
                })
                .collect();
            tied += (0..nc).any(|i| (0..i).any(|j| cl[i].0 == cl[j].0)) as usize;
            let (mut cs, mut cp, mut cr) = (vec![0u32; (ncamp + 1) * stride], vec![0u32; (ncamp + 1) * stride], vec![0u64; (ncamp + 1) * stride]);
            let mut ssp = ss.clone();
            ssp.extend([0; 8]);
            let before = |j: usize, i: usize| {
                let (a, b) = (IDS[cl[j].2 as usize], IDS[cl[i].2 as usize]);
                a > b || (a == b && j < i)
            };
            let held = std::cell::Cell::new(0usize);
            let hold = |_i: usize| held.set(held.get() + 1);
            let done = unsafe { va::attribute(&mut lt, &before, if round % 2 == 1 { Some(&hold) } else { None }, &cl, ssp.as_ptr(), sd.as_ptr(), sv.as_ptr(), ns, stride, ncamp, (cs.as_mut_ptr(), cp.as_mut_ptr(), cr.as_mut_ptr()), &mut asst) };
            assert_eq!(done, held.get() == 0);
            if !done {
                assert!(held.get() >= 2 && cs.iter().all(|&x| x == 0));
                lt.flush(&mut asst, &mut cs);
                assert!(cs.iter().all(|&x| x == 0));
            }
            if !done { unsafe { va::attribute(&mut lt, &before, None, &cl, ssp.as_ptr(), sd.as_ptr(), sv.as_ptr(), ns, stride, ncamp, (cs.as_mut_ptr(), cp.as_mut_ptr(), cr.as_mut_ptr()), &mut asst) }; }
            // credits wait for a flush too
            lt.flush(&mut asst, &mut cs);
            let mut cd2 = vec![(0u32, 0u32, 0u64); (ncamp + 1) * stride];
            for k in 0..ns {
                let near: Vec<&TC> = cl.iter().filter(|c| c.0 <= ss[k] && ss[k] - c.0 <= WEEK).collect();
                // the latest, and of several at its time the smallest id
                let by = near.iter().max_by(|a, b| a.0.cmp(&b.0).then(IDS[b.2 as usize].cmp(IDS[a.2 as usize])));
                let camp = by.map_or(ncamp, |c| c.1 as usize);
                let e = &mut cd2[camp * stride + sd[k] as usize];
                e.0 += 1;
                e.1 += (sv[k] & 1) as u32;
                e.2 += sv[k] >> 1;
                for c in 0..ncamp {
                    if near.iter().any(|x| x.1 as usize == c) {
                        asst2[c * stride + sd[k] as usize] += 1;
                    }
                }
            }
            for (i, b) in cd2.iter().enumerate() {
                assert_eq!((cs[i], cp[i], cr[i]), *b, "round {}", round);
            }
            assert_eq!(asst, asst2, "round {}", round);
        }
        assert_eq!(asst, asst2);
        assert!(tied > 5_000, "{}", tied);
    }
}
