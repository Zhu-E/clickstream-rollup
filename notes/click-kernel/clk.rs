// ------------------------------------------------------------------- clicks

/// a user id in the low half, a campaign id in the high half; row `user raw` and row `campaign raw * 2 + plain`
#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct HalfRow {
    ctrl: [u8; 16],
    subv: [u8; 16],
    lz: [u8; 16],
    pad: [u8; 16],
}

const fn uid_rows() -> [HalfRow; 64] {
    let mut t = [HalfRow { ctrl: [0; 16], subv: [0; 16], lz: [0; 16], pad: [0; 16] }; 64];
    let mut raw = 0;
    while raw < 64 {
        let x = id_half(b'u', raw);
        t[raw] = HalfRow { ctrl: x.0, subv: x.1, lz: x.2, pad: [0; 16] };
        raw += 1;
    }
    t
}

/// `c_` and one to eight digits to bytes 0..8, the letters and quotes after; `plain` is the low bit of the first byte
const fn camp_rows() -> [HalfRow; 128] {
    let mut t = [HalfRow { ctrl: [0x80; 16], subv: [0; 16], lz: [0; 16], pad: [0; 16] }; 128];
    let mut j = 0;
    while j < 128 {
        let (raw, q) = (j / 2, 1 - j % 2);
        let r = &mut t[j];
        if raw >= 3 + 2 * q && raw <= 10 + 2 * q {
            let nd = raw - 2 - 2 * q;
            let mut i = 0;
            while i < nd {
                r.ctrl[8 - nd + i] = (2 + q + i) as u8;
                r.subv[8 - nd + i] = b'0';
                i += 1;
            }
            r.ctrl[8] = q as u8;
            r.subv[8] = b'c';
            r.ctrl[9] = 1 + q as u8;
            r.subv[9] = b'_';
            if q == 1 {
                r.ctrl[10] = 0;
                r.subv[10] = b'"';
                r.ctrl[11] = (raw - 1) as u8;
                r.subv[11] = b'"';
            }
            if nd > 1 {
                r.lz[8 - nd] = 1;
            }
        } else {
            // never zero: no such id
            r.subv[8] = 1;
        }
        j += 1;
    }
    t
}

/// the quotes a click id of `raw` bytes may have in its first sixteen: none, or one at each end
const fn cid_rows() -> [[u32; 2]; 64] {
    let mut t = [[NO_PAT; 2]; 64];
    let mut raw = 1;
    while raw <= 16 {
        // at most fifteen bytes of id, and not an empty one
        if raw <= 15 {
            t[raw][0] = 0;
        }
        if raw >= 3 {
            t[raw][1] = 1 | 1 << (raw - 1);
        }
        raw += 1;
    }
    t
}

#[repr(C, align(64))]
struct ClTables {
    uid: [HalfRow; 64],
    camp: [HalfRow; 128],
    cid: [[u32; 2]; 64],
}

static TC: ClTables = ClTables { uid: uid_rows(), camp: camp_rows(), cid: cid_rows() };

/// a click row the tables vouch for: an id of 1 to 15 bytes, a valid user under the cap,
/// a campaign that is `c_` and the number `camp` with no leading zero, a valid time
#[derive(Clone, Copy)]
pub struct Cl {
    pub un: u64,
    pub camp: u64,
    pub ts: i64,
    /// the click id, from the row start
    pub id: usize,
    pub nid: usize,
    /// bytes to the next row
    pub next: usize,
}

/// The click row at `p`, on the terms of `ev`.
#[inline(always)]
pub unsafe fn cl(p: *const u8, k: &Kern) -> Option<Cl> {
    let (a, b) = (ld2(p), ld2(p.add(32)));
    let c = crate::split::join(eq(a, k.comma), eq(b, k.comma));
    let n = crate::split::join(eq(a, k.nl), eq(b, k.nl));
    let c0 = c.trailing_zeros() as usize;
    let t = c & c.wrapping_sub(1);
    let c1 = t.trailing_zeros() as usize;
    let t = t & t.wrapping_sub(1);
    let c2 = t.trailing_zeros() as usize;
    let t = t & t.wrapping_sub(1);
    let m = n.trailing_zeros() as usize;
    // three commas before the first newline and no fourth
    if (m > 63) | (c2 >= m) | (_bzhi_u64(t, m as u32) != 0) {
        return None;
    }
    // the id may hold anything but a quote inside
    let q = _bzhi_u32(_mm_movemask_epi8(_mm_cmpeq_epi8(ld(p), _mm256_castsi256_si128(k.quote))) as u32, c0 as u32);
    let pat = TC.cid.get_unchecked(c0);
    let id_bad = (q != pat[0]) & (q != pat[1]);

    let ur = TC.uid.get_unchecked(c1 - c0 - 1);
    let cp = p.add(c1 + 1);
    let cr = TC.camp.get_unchecked(((c2 - c1 - 1) << 1) | (*cp & 1) as usize);
    let x = two(p.add(c0 + 1), cp);
    let v = _mm256_sub_epi8(_mm256_shuffle_epi8(x, two(ur.ctrl.as_ptr(), cr.ctrl.as_ptr())), two(ur.subv.as_ptr(), cr.subv.as_ptr()));
    let notdig = _mm256_subs_epu8(v, _mm256_set1_epi8(9));
    // letters count as digits in the user id only
    let notlet = _mm256_max_epu8(_mm256_subs_epu8(_mm256_sub_epi8(v, _mm256_set1_epi8(49)), _mm256_set1_epi8(25)), _mm256_set_epi64x(-1, -1, 0, 0));
    let val = _mm256_min_epu8(v, _mm256_sub_epi8(v, _mm256_set1_epi8(39)));
    let lz = _mm256_subs_epu8(two(ur.lz.as_ptr(), cr.lz.as_ptr()), val);
    let cls = or_and(_mm256_min_epu8(notdig, notlet), v, _mm256_set_epi64x(-1, 0, -1, 0));
    // base 36 below, base 10 above
    let m1 = _mm256_maddubs_epi16(val, _mm256_set_epi64x(0x010a_010a_010a_010a, 0x010a_010a_010a_010a, 0x0124_0124_0124_0124, 0x0124_0124_0124_0124));
    let m2 = _mm256_madd_epi16(m1, _mm256_set_epi64x(0x0001_0064_0001_0064, 0x0001_0064_0001_0064, 0x0001_0510_0001_0510, 0x0001_0510_0001_0510));
    let nn = _mm256_add_epi64(_mm256_mul_epu32(m2, _mm256_set_epi64x(10_000, 10_000, 1_679_616, 1_679_616)), _mm256_srli_epi64::<32>(m2));
    let (cu, bad_cap) = unscr(nn, k);

    let raw = m - c2 - 1;
    let tj = T.ts1.get_unchecked(raw);
    let kp = p.add(c2 + tj.koff as usize);
    let e = k.days.add(_pext_u64(rd64(kp.add(4)), tj.pm) as usize) as *const u8;
    let bad_key = _mm_and_si128(_mm_xor_si128(ld(kp), ld(e)), ld(tj.kmask.as_ptr()));
    let x = _mm256_zextsi128_si256(ld(p.add(m).sub(16)));
    let d = _mm256_sub_epi8(_mm256_shuffle_epi8(x, ld2(tj.ctrl.as_ptr())), ld2(tj.base.as_ptr()));
    let m1 = _mm256_maddubs_epi16(d, ld2(tj.w1.as_ptr() as *const u8));
    let m2 = _mm256_madd_epi16(m1, ld2(tj.w2.as_ptr() as *const u8));
    let m3 = _mm256_madd_epi16(_mm256_packus_epi32(m2, m2), ld2(tj.w3.as_ptr() as *const u8));
    let bad_a = _mm256_subs_epu8(d, ld2(tj.lim.as_ptr()));
    let bad_b = _mm256_cmpgt_epi32(m2, ld2(tj.limv.as_ptr() as *const u8));
    let t = _mm256_mul_epu32(m3, ld2(tj.ka.as_ptr() as *const u8));
    let f = _mm256_mul_epi32(_mm256_srli_epi64::<32>(m3), ld2(tj.kb.as_ptr() as *const u8));
    let r = _mm256_add_epi64(add_or_sub(t, f, d, ld2(tj.ksel.as_ptr())), _mm256_zextsi128_si256(ld(e.add(16))));

    let bad = _mm256_or_si256(or3(cls, lz, _mm256_srli_epi64::<40>(nn)), or3(or3(bad_a, bad_b, bad_cap), _mm256_zextsi128_si256(bad_key), _mm256_setzero_si256()));
    if id_bad | any(bad) {
        return None;
    }
    let (un, _) = words02(cu);
    let (_, camp) = words02(nn);
    let (ts, _, _) = words123(r);
    let quoted = (q & 1) as usize;
    Some(Cl { un, camp, ts, id: quoted, nid: c0 - 2 * quoted, next: m + 1 })
}

