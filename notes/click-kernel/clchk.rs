
/// click rows as the generator writes them, damaged the same ways
fn sample_clicks(seed: u64, rows: usize) -> Vec<u8> {
    const DIG: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    const DATES: [&str; 6] = ["2026-04-18", "2026-04-30", "2028-02-29", "2026-05-01", "2026-02-30", "2026-04-00"];
    let mut r = Rng(seed | 1);
    let mut b: Vec<u8> = b"click_id,user_id,campaign_id,ts\n".to_vec();
    let mut f: Vec<u8> = Vec::new();
    for _ in 0..rows {
        for letter in [b'k', b'u'] {
            f.clear();
            if r.below(30) != 0 {
                f.push(if r.below(50) == 0 { b'U' } else { letter });
                let nd = match r.below(24) {
                    0 => r.below(20),
                    1 => 7,
                    _ => 8,
                };
                for i in 0..nd {
                    let low = i == 0 && nd == 8 && r.below(30) != 0;
                    f.push(DIG[r.below(if low { 14 } else { 36 })]);
                }
            }
            put(&mut b, &mut r, &f, false);
        }
        let camp = match r.below(30) {
            0 => r.one(&["", "c_", "c_007", "C_12", "c-12", "c_1x", "c12", "c_123456789", "c_0", "x_12"]).to_string(),
            1 => format!("c_{}", r.below(100_000_000)),
            _ => format!("c_{}", r.below(2500)),
        };
        put(&mut b, &mut r, camp.as_bytes(), false);
        let clock = format!("{:02}:{:02}:{:02}", r.mostly(40, 24, 30), r.mostly(40, 60, 70), r.mostly(40, 60, 70));
        let date = DATES[r.mostly(12, 3, 6)];
        let text = match r.below(10) {
            0 | 5 | 6 | 7 => format!("{}T{}Z", date, clock),
            1 => format!("{}T{}{}{:02}:{:02}", date, clock, r.one(&["+", "-", "-", "+", " "]), r.mostly(20, 24, 30), r.mostly(20, 60, 70)),
            2 | 8 | 9 => format!("17{:011}", r.below(100_000_000_000)),
            3 => format!("{:0w$}", r.below(1_000_000_000), w = 1 + r.below(18)),
            _ => r.one(&["", "2026-04-18 10:00:00Z", "2026-04-18T10:00:00z", "2026-04-18T10:00:00", "1.79e12", "-5", "2026-04-18T10:00:00.5Z", "2026-04-18T10:00:00+0200"]).to_string(),
        };
        match r.below(60) {
            0 => {
                put(&mut b, &mut r, text.as_bytes(), false);
                put(&mut b, &mut r, b"x", true);
            }
            1 => {
                b.pop();
                b.push(b'\n');
            }
            2 => {
                put(&mut b, &mut r, text.as_bytes(), true);
                b.push(b'\n');
            }
            _ => put(&mut b, &mut r, text.as_bytes(), true),
        }
    }
    b.resize(b.len() + 160, b'\n');
    b
}

/// `cl` over sample rows, as `check_events`
fn check_clicks(seed: u64, rows: usize) -> Option<usize> {
    use crate::tbl::parse_ts;
    let tight = seed & 2 != 0;
    let k = Keys { ek: 0x12_3456_789a, uk: 0xab_cdef_0123, ncap: 1 << 40, ucap: if tight { 1 << 30 } else { 1 << 31 }, shift: 12 };
    let d = sample_clicks(seed, rows);
    let mut days = Box::new(Days::new());
    let mut hits = 0;
    let mut p = crate::first_line_start(&d, 0);
    while p + crate::split::REACH <= d.len() {
        let sc = crate::scan_line(&d, p, false);
        let line = &d[p..sc.nl];
        let fs = crate::fields::<4>(line, &sc);
        if p >= 16 {
            if let Some(e) = unsafe { cl(d.as_ptr().add(p), &Kern::new(&k, days.as_ptr())) } {
                let Some(f) = fs else { return None };
                let at = |i: usize| &line[f[i].0 as usize..f[i].1 as usize];
                let same = (e.id, e.nid) == (f[0].0 as usize, at(0).len())
                    && e.nid >= 1
                    && e.nid <= 15
                    && k.user(at(1)) == Some(e.un)
                    && at(2) == format!("c_{}", e.camp).as_bytes()
                    && parse_ts(at(3)) == Some(e.ts)
                    && e.next == sc.nl + 1 - p;
                if !same {
                    return None;
                }
                hits += 1;
            } else if let Some(f) = fs {
                days.learn(&line[f[3].0 as usize..f[3].1 as usize]);
            }
        }
        p = sc.nl + 1;
    }
    if days.e[0].key != [0; 16] || days.e[0].ms != 0 {
        return None;
    }
    Some(hits)
}
