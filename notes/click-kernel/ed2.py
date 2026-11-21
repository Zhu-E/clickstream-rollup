# ed2.py : the click kernel
p = 'src/rowk.rs'
s = open(p, encoding='utf-8').read()

def rep(a, b, cnt=1):
    global s
    assert s.count(a) == cnt, (s.count(a), a)
    s = s.replace(a, b)

# unscramble under either pair of keys
rep('unsafe fn unscr(v: __m256i, k: &Kern) -> (__m256i, __m256i) {', 'unsafe fn unscr(v: __m256i, keys: __m256i, caps: __m256i) -> (__m256i, __m256i) {', 2)
rep('_mm256_xor_si256(h, k.keys)', '_mm256_xor_si256(h, keys)')
rep('(r, _mm256_cmpgt_epi64(r, k.caps))', '(r, _mm256_cmpgt_epi64(r, caps))', 2)
rep('''        0 => _mm256_extract_epi64::<0>(k.keys) as u64,
        _ => _mm256_extract_epi64::<2>(k.keys) as u64,''', '''        0 => _mm256_extract_epi64::<0>(keys) as u64,
        _ => _mm256_extract_epi64::<2>(keys) as u64,''')
rep('let (cu, bad_cap) = unscr(n, k);', 'let (cu, bad_cap) = unscr(n, k.keys, k.caps);')
rep('''    caps: __m256i,
    days: *const Day,
}''', '''    caps: __m256i,
    /// the same for a click row: the user in word 0, nothing in word 2
    ckeys: __m256i,
    ccaps: __m256i,
    days: *const Day,
}''')
rep('''                caps: _mm256_set_epi64x(i64::MAX, (k.ucap << 9) as i64 - 1, i64::MAX, k.ncap as i64 - 1),''', '''                caps: _mm256_set_epi64x(i64::MAX, (k.ucap << 9) as i64 - 1, i64::MAX, k.ncap as i64 - 1),
                ckeys: _mm256_set_epi64x(0, 0, 0, k.uk as i64),
                ccaps: _mm256_set_epi64x(i64::MAX, i64::MAX, i64::MAX, (k.ucap << 9) as i64 - 1),''')
rep('''/// words 1, 2 and 3
''', '''/// word 0, word 2, word 1
#[inline(always)]
unsafe fn word0(v: __m256i) -> u64 {
    words02(v).0
}

#[inline(always)]
unsafe fn word2(v: __m256i) -> u64 {
    #[cfg(all(target_feature = "avx512f", target_feature = "avx512vl"))]
    {
        let a: u64;
        core::arch::asm!("vextracti128 {t}, {v}, 1", "vmovq {a}, {t}", v = in(ymm_reg) v, t = out(xmm_reg) _, a = lateout(reg) a, options(pure, nomem, nostack, preserves_flags));
        return a;
    }
    #[cfg(not(all(target_feature = "avx512f", target_feature = "avx512vl")))]
    return _mm256_extract_epi64::<2>(v) as u64;
}

#[inline(always)]
unsafe fn word1(v: __m256i) -> i64 {
    #[cfg(all(target_feature = "avx512f", target_feature = "avx512vl"))]
    {
        let a: i64;
        core::arch::asm!("vpextrq {a}, {v:x}, 1", v = in(ymm_reg) v, a = lateout(reg) a, options(pure, nomem, nostack, preserves_flags));
        return a;
    }
    #[cfg(not(all(target_feature = "avx512f", target_feature = "avx512vl")))]
    return _mm256_extract_epi64::<1>(v);
}

/// words 1, 2 and 3
''')
clk = open('.scratch/clk.rs', encoding='utf-8').read()
clk = clk.replace('let (cu, bad_cap) = unscr(nn, k);', 'let (cu, bad_cap) = unscr(nn, k.ckeys, k.ccaps);')
clk = clk.replace('''    let (un, _) = words02(cu);
    let (_, camp) = words02(nn);
    let (ts, _, _) = words123(r);
''', '''    let (un, camp, ts) = (word0(cu), word2(nn), word1(r));
''')
clk = clk.replace('''    // three commas before the first newline and no fourth
    if (m > 63) | (c2 >= m) | (_bzhi_u64(t, m as u32) != 0) {''', '''    // three commas before the first newline; a fourth would be in the time, which is read whole
    if (m > 63) | (c2 >= m) {''')
clk = clk.replace('''    let t = t & t.wrapping_sub(1);
    let m = n.trailing_zeros() as usize;''', '''    let m = n.trailing_zeros() as usize;''')
rep('// ------------------------------------------------------------------- checks', clk + '// ------------------------------------------------------------------- checks')
rep('''/// `dec8` against the digit loop''', open('.scratch/clchk.rs', encoding='utf-8').read().lstrip('\n') + '''
/// `dec8` against the digit loop''')
rep('''check_events(0x51_7cc1_b727_220e, 1000).is_some()''', '''check_events(0x51_7cc1_b727_220e, 1000).is_some()
        && check_clicks(0x2b_9921_6f1d_0c4c, 3000).is_some_and(|hits| hits > 400)
        && check_clicks(0x2b_9921_6f1d_0c4e, 1000).is_some()''')
rep('''    /// every shape the generator writes must be taken''', '''    #[test]
    fn click_rows_match_the_reference_parsers() {
        let mut hits = 0;
        for seed in 1..=300u64 {
            hits += check_clicks(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15), 4000).expect("a row the tables accept and the reference reads otherwise");
        }
        assert!(hits > 250_000, "too few rows accepted: {}", hits);
    }

    #[test]
    fn clean_click_rows_are_taken() {
        let k = Keys { ek: 0x12_3456_789a, uk: 0xab_cdef_0123, ncap: 1 << 40, ucap: 1 << 31, shift: 12 };
        let mut days = Box::new(Days::new());
        days.learn(b"2026-04-18T");
        days.learn(b"2026-04-17T");
        let q = |on: bool, s: &str| if on { format!("\\"{}\\"", s) } else { s.to_string() };
        let mut n = 0;
        for bits in 0..16u32 {
            for (id, uid) in [("k1234567", "u7654321"), ("k123456", "u1"), ("k", "u765432"), ("click-number-15", "u1234567")] {
                for ts in ["2026-04-18T10:20:30Z", "2026-04-18T23:59:59+12:00", "2026-04-17T00:00:00-10:00", "1776500000123"] {
                    for camp in ["c_0", "c_7", "c_12", "c_823", "c_1975", "c_12345678"] {
                        if (bits & 2 != 0 && uid.len() < 8) || (bits & 1 != 0 && id.len() > 14) {
                            continue;
                        }
                        let f = [id, uid, camp, ts];
                        let row: Vec<String> = (0..4).map(|i| q(bits >> i & 1 != 0, f[i])).collect();
                        if row.join(",").len() > 63 {
                            continue;
                        }
                        let mut d = vec![b'\\n'; 16];
                        d.extend_from_slice(row.join(",").as_bytes());
                        d.resize(d.len() + 160, b'\\n');
                        let e = unsafe { cl(d.as_ptr().add(16), &Kern::new(&k, days.as_ptr())) };
                        assert!(e.is_some(), "{}", row.join(","));
                        n += 1;
                    }
                }
            }
        }
        assert!(n > 800, "{}", n);
    }

    /// every shape the generator writes must be taken''')
open(p, 'w', encoding='utf-8', newline='\n').write(s)

p = 'src/fast.rs'
s = open(p, encoding='utf-8').read()
a = s.index('#[cfg_attr(not(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "bmi1", target_feature = "bmi2")), allow(dead_code))]\n#[cold]\n#[inline(never)]\nfn cl_rare(')
b = s.index('// ---------------------------------------------------------------- user table')
s = s[:a] + '''/// a row the tables left: its date noted, then the window, then the reference
#[cfg(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "bmi1", target_feature = "bmi2"))]
#[cold]
#[inline(never)]
unsafe fn cl_second(x: Env, fr: u64, p: usize, cs: &mut ClBins, oddc: &mut Vec<OddCl>, dc: &mut DateCache, days: &mut rowk::Days) -> usize {
    let p0 = x.d.as_ptr().add(p);
    let cut = split::Cut::new();
    let tab = cs.cur.as_mut_ptr();
    let m = split::masks(p0, &cut);
    if let Some((mut a, nl)) = split::tail::<3>(m.0, m.1, m.2) {
        let mut w = a;
        let (s3, e3) = (w.next(), w.next(), w.next(), w.next()).3;
        days.learn(std::slice::from_raw_parts(p0.add(s3), e3 - s3));
        if cl_row::<true>(x, fr, p0, || a.next(), tab, cs, oddc, dc) {
            return p + nl + 1;
        }
    }
    cl_line(x, fr, p, cs, oddc, dc)
}

fn parse_cl(ctx: &Ctx, k: &Keys, cl0: usize, fi: usize, from: usize, to: usize, st: &mut PSt) {
    let simd = SIMD_OK.load(Ordering::Relaxed);
    let x = Env::new(ctx, k, fi, simd, ctx.cl_lo, ctx.cl_hi);
    let d = x.d;
    let mut p = first_line_start(d, from);
    let fr = (fi - cl0) as u64;
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "bmi1", target_feature = "bmi2"))]
    if simd {
        let PSt { cs, oddc, dc, days, .. } = &mut *st;
        // rows that start before `to` and have a whole window to read
        let stop = to.min((d.len() + 1).saturating_sub(split::REACH));
        // the tables read a little before a row
        while p < stop.min(16) {
            p = cl_line(x, fr, p, cs, oddc, dc);
        }
        let kern = rowk::Kern::new(k, days.as_ptr());
        let tab = cs.cur.as_mut_ptr();
        // what a record has room for: a file number, an offset, a campaign
        let fits = fr < 256 && d.len() < (1 << 36) && ctx.camp.len() <= (1 << 16) && ctx.ncamp <= (1 << 16);
        let camps = if fits { ctx.camp.len() as u64 } else { 0 };
        while p < stop {
            unsafe {
                let p0 = d.as_ptr().add(p);
                if let Some(e) = rowk::cl(p0, &kern) {
                    // index + 1, or 0 for a number that is no campaign here
                    let c = if e.camp < camps { *ctx.camp.get_unchecked(e.camp as usize) } else { 0 };
                    if c != 0 {
                        if (e.ts.wrapping_sub(x.lo) as u64) < x.span {
                            let ts = (e.ts - ctx.base) as u32;
                            let ui = e.un >> 9;
                            let off = (p + e.id) as u64;
                            cs.put(tab, (ui >> CSHIFT) as usize, FC { a: (ui << 40) | ((ts as u64) << 9) | (e.un & ALIAS), b: (((c - 1) as u64) << 48) | (fr << 40) | (off << 4) | e.nid as u64 });
                        }
                        p += e.next;
                        continue;
                    }
                }
            }
            p = unsafe { cl_second(x, fr, p, cs, oddc, dc, days) };
        }
    }
    let PSt { cs, oddc, dc, .. } = st;
    while p < to {
        p = cl_line(x, fr, p, cs, oddc, dc);
    }
}

''' + s[b:]
open(p, 'w', encoding='utf-8', newline='\n').write(s)
