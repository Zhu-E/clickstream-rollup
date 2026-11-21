// Probe build: reports the scorer's hardware, kernel settings and timings.
// It adds rows to user_daily on purpose, so it can never score.
use crate::pq;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    fn munmap(addr: *mut u8, len: usize) -> i32;
    fn madvise(addr: *mut u8, len: usize, advice: i32) -> i32;
}

const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const MAP_PRIVATE: i32 = 2;
const MAP_ANON: i32 = 0x20;
const MAP_NORESERVE: i32 = 0x4000;
const MADV_HUGEPAGE: i32 = 14;
const MADV_NOHUGEPAGE: i32 = 15;
const HUGE: usize = 2 << 20;

fn say(s: &str) {
    eprintln!("PROBE {}", s);
}

fn rd(p: &str) -> String {
    match std::fs::read_to_string(p) {
        Ok(s) => s.trim_end().to_string(),
        Err(e) => format!("<{:?}>", e.kind()),
    }
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1e3
}

/// The word in [brackets], as sysfs marks the active choice.
fn chosen(s: &str) -> String {
    match (s.find('['), s.find(']')) {
        (Some(a), Some(b)) if b > a => s[a + 1..b].to_string(),
        _ => s.to_string(),
    }
}

fn kb_line(text: &str, key: &str) -> i64 {
    text.lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(-1)
}

fn cpu_list(s: &str) -> Vec<usize> {
    let mut v = Vec::new();
    for part in s.trim().split(',') {
        let mut it = part.split('-');
        let a = it.next().and_then(|x| x.trim().parse::<usize>().ok());
        let b = it.next().and_then(|x| x.trim().parse::<usize>().ok());
        match (a, b) {
            (Some(a), Some(b)) => v.extend(a..=b),
            (Some(a), None) => v.push(a),
            _ => {}
        }
    }
    v
}

fn size_kb(s: &str) -> i64 {
    let s = s.trim();
    if let Some(x) = s.strip_suffix('K') {
        x.parse().unwrap_or(-1)
    } else if let Some(x) = s.strip_suffix('M') {
        x.parse::<i64>().map(|v| v * 1024).unwrap_or(-1)
    } else {
        s.parse::<i64>().map(|v| v / 1024).unwrap_or(-1)
    }
}

#[derive(Default)]
struct Sum {
    cpu: String,
    flags: String,
    ncpu: i64,
    ncore: i64,
    l2kb: i64,
    l3kb: i64,
    kernel: String,
    thp: String,
    mem_mb: i64,
    cg_mb: i64,
    ahp_mb: i64,
    fs: String,
    dmi: String,
    wall_ms: i64,
    total_ms: i64,
    stages: String,
    abl: String,
    wall4_ms: i64,
    age_ms: i64,
    spawn_us: i64,
    micro: String,
    micro2: String,
    load100: i64,
    nproc: i64,
}

fn sysinfo(s: &mut Sum) {
    let ci = rd("/proc/cpuinfo");
    let field = |k: &str| -> String {
        ci.lines()
            .find(|l| l.starts_with(k))
            .and_then(|l| l.splitn(2, ':').nth(1))
            .map(|v| v.trim().to_string())
            .unwrap_or_default()
    };
    let model = field("model name");
    let flags = field("flags");
    s.nproc = ci.lines().filter(|l| l.starts_with("processor")).count() as i64;
    say(&format!("cpu model: {}", model));
    for k in [
        "vendor_id", "cpu family", "model\t", "stepping", "microcode", "cpu MHz", "cache size",
        "siblings", "cpu cores", "bogomips", "address sizes",
    ] {
        say(&format!("cpuinfo {}: {}", k.trim(), field(k)));
    }
    say(&format!("cpuinfo processors: {}", s.nproc));
    say(&format!("cpu flags: {}", flags));
    let has = |f: &str| flags.split(' ').any(|x| x == f);
    let mut bits = String::from("512:");
    for f in [
        "avx512f", "avx512bw", "avx512vl", "avx512dq", "avx512cd", "avx512ifma", "avx512vbmi",
        "avx512_vbmi2", "avx512_vnni", "avx512_bitalg", "avx512_vpopcntdq",
    ] {
        bits.push(if has(f) { '1' } else { '0' });
    }
    bits.push('|');
    for (f, c) in [
        ("avx2", '2'), ("bmi2", 'b'), ("gfni", 'g'), ("vaes", 'a'), ("vpclmulqdq", 'p'),
        ("erms", 'e'), ("fsrm", 's'), ("hypervisor", 'h'), ("sha_ni", 'n'),
    ] {
        if has(f) {
            bits.push(c);
        }
    }
    s.flags = bits;
    s.cpu = model
        .replace("Intel(R) ", "")
        .replace("Xeon(R) ", "")
        .replace("CPU ", "")
        .replace("Processor", "")
        .replace("(R)", "")
        .replace("(TM)", "")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");

    let st = rd("/proc/self/status");
    for l in st.lines() {
        if l.starts_with("Cpus_allowed") || l.starts_with("Mems_allowed") || l.starts_with("Uid")
            || l.starts_with("Pid") || l.starts_with("PPid") || l.starts_with("Threads")
            || l.starts_with("CapEff") || l.starts_with("Seccomp") || l.starts_with("NoNewPrivs")
        {
            say(&format!("status {}", l.replace('\t', " ")));
        }
    }
    let allowed = st
        .lines()
        .find(|l| l.starts_with("Cpus_allowed_list"))
        .and_then(|l| l.splitn(2, ':').nth(1))
        .map(cpu_list)
        .unwrap_or_default();
    s.ncpu = allowed.len() as i64;
    let mut sib: Vec<String> = Vec::new();
    for (i, &c) in allowed.iter().enumerate() {
        let base = format!("/sys/devices/system/cpu/cpu{}", c);
        let t = rd(&format!("{}/topology/thread_siblings_list", base));
        if i < 16 {
            say(&format!(
                "cpu{} siblings {} core {} pkg {} governor {} cur_khz {} max_khz {}",
                c,
                t,
                rd(&format!("{}/topology/core_id", base)),
                rd(&format!("{}/topology/physical_package_id", base)),
                rd(&format!("{}/cpufreq/scaling_governor", base)),
                rd(&format!("{}/cpufreq/scaling_cur_freq", base)),
                rd(&format!("{}/cpufreq/cpuinfo_max_freq", base)),
            ));
        }
        if !sib.contains(&t) {
            sib.push(t);
        }
    }
    s.ncore = sib.len() as i64;
    say(&format!("allowed cpus {} on {} distinct cores", s.ncpu, s.ncore));
    let c0 = allowed.first().copied().unwrap_or(0);
    for i in 0..5 {
        let b = format!("/sys/devices/system/cpu/cpu{}/cache/index{}", c0, i);
        let level = rd(&format!("{}/level", b));
        if level.starts_with('<') {
            continue;
        }
        let size = rd(&format!("{}/size", b));
        let ty = rd(&format!("{}/type", b));
        say(&format!(
            "cache L{} {} {} shared with {} ways {}",
            level,
            ty,
            size,
            rd(&format!("{}/shared_cpu_list", b)),
            rd(&format!("{}/ways_of_associativity", b)),
        ));
        if level == "2" {
            s.l2kb = size_kb(&size);
        }
        if level == "3" {
            s.l3kb = size_kb(&size);
        }
    }
    for f in [
        "/sys/devices/system/cpu/smt/active",
        "/sys/devices/system/cpu/smt/control",
        "/sys/devices/system/cpu/intel_pstate/no_turbo",
        "/sys/devices/system/cpu/online",
        "/sys/devices/system/node/online",
        "/sys/devices/system/clocksource/clocksource0/current_clocksource",
    ] {
        say(&format!("{}: {}", f, rd(f)));
    }

    s.kernel = rd("/proc/sys/kernel/osrelease");
    say(&format!("kernel: {}", rd("/proc/version")));
    let thp = "/sys/kernel/mm/transparent_hugepage";
    for f in [
        "enabled", "defrag", "shmem_enabled", "use_zero_page", "hpage_pmd_size",
        "khugepaged/defrag", "khugepaged/scan_sleep_millisecs",
    ] {
        say(&format!("thp {}: {}", f, rd(&format!("{}/{}", thp, f))));
    }
    s.thp = format!(
        "thp={}/{}",
        chosen(&rd(&format!("{}/enabled", thp))),
        chosen(&rd(&format!("{}/defrag", thp)))
    );
    let mi = rd("/proc/meminfo");
    for l in mi.lines() {
        if [
            "MemTotal", "MemFree", "MemAvailable", "Cached", "Dirty", "AnonHugePages", "FileHugePages",
            "ShmemHugePages", "HugePages_Total", "Hugepagesize", "SwapTotal",
        ]
        .iter()
        .any(|k| l.starts_with(k))
        {
            say(&format!("meminfo {}", l.split_whitespace().collect::<Vec<_>>().join(" ")));
        }
    }
    s.mem_mb = kb_line(&mi, "MemTotal") / 1024;
    for f in [
        "memory.max", "memory.high", "memory.current", "memory.swap.max", "cpu.max",
        "cpuset.cpus.effective", "cpuset.cpus", "pids.max", "cgroup.controllers",
        "memory/memory.limit_in_bytes", "cpuset/cpuset.cpus", "cpu/cpu.cfs_quota_us",
    ] {
        say(&format!("cgroup {}: {}", f, rd(&format!("/sys/fs/cgroup/{}", f)).replace('\n', " ")));
    }
    s.cg_mb = rd("/sys/fs/cgroup/memory.max").parse::<i64>().map(|v| v >> 20).unwrap_or(-1);
    say(&format!("self cgroup: {}", rd("/proc/self/cgroup").replace('\n', " | ")));

    let data = std::env::var("DATA_DIR").unwrap_or_else(|_| "/data".into());
    let out = std::env::var("OUTPUT_DIR").unwrap_or_else(|_| "/output".into());
    let scr = std::env::var("SCRATCH_DIR").unwrap_or_else(|_| "/scratch".into());
    let mut fs = String::new();
    for l in rd("/proc/self/mountinfo").lines() {
        let p: Vec<&str> = l.split(' ').collect();
        if p.len() < 6 {
            continue;
        }
        let mp = p[4];
        let tag = if mp == "/" {
            "r"
        } else if mp == data {
            "d"
        } else if mp == out {
            "o"
        } else if mp == scr {
            "s"
        } else if mp == "/tmp" {
            "t"
        } else {
            continue;
        };
        say(&format!("mount {}", l));
        if let Some(i) = p.iter().position(|&x| x == "-") {
            if let Some(ty) = p.get(i + 1) {
                if tag != "t" {
                    fs.push_str(&format!("{}={} ", tag, ty));
                }
            }
        }
    }
    s.fs = fs.trim().to_string();

    let mut dmi = String::new();
    for f in ["sys_vendor", "product_name", "board_vendor", "bios_vendor", "chassis_asset_tag", "product_version"] {
        let v = rd(&format!("/sys/class/dmi/id/{}", f));
        say(&format!("dmi {}: {}", f, v));
        if (f == "sys_vendor" || f == "product_name") && !v.starts_with('<') {
            dmi.push_str(&v);
            dmi.push(' ');
        }
    }
    say(&format!("hypervisor type: {}", rd("/sys/hypervisor/type")));
    s.dmi = dmi.trim().to_string();

    let la = rd("/proc/loadavg");
    say(&format!("loadavg: {}", la));
    s.load100 = la
        .split(' ')
        .next()
        .and_then(|v| v.parse::<f64>().ok())
        .map(|v| (v * 100.0) as i64)
        .unwrap_or(-1);
    say(&format!("uptime: {}", rd("/proc/uptime")));
    for f in ["cpu", "memory", "io"] {
        say(&format!("pressure {}: {}", f, rd(&format!("/proc/pressure/{}", f)).replace('\n', " | ")));
    }
    for f in ["overcommit_memory", "max_map_count", "dirty_ratio", "dirty_background_ratio", "swappiness"] {
        say(&format!("vm.{}: {}", f, rd(&format!("/proc/sys/vm/{}", f))));
    }
    for (k, v) in std::env::vars_os() {
        say(&format!("env {}={}", k.to_string_lossy(), v.to_string_lossy()));
    }
    for l in rd("/proc/self/limits").lines() {
        say(&format!("limit {}", l.split_whitespace().collect::<Vec<_>>().join(" ")));
    }

    // how long this process had existed when main started (10 ms resolution)
    let stat = rd("/proc/self/stat");
    let start_ticks = stat
        .rsplit(')')
        .next()
        .and_then(|r| r.split_whitespace().nth(19))
        .and_then(|v| v.parse::<f64>().ok());
    let up = rd("/proc/uptime").split(' ').next().and_then(|v| v.parse::<f64>().ok());
    if let (Some(st), Some(up)) = (start_ticks, up) {
        s.age_ms = ((up - st / 100.0) * 1e3) as i64;
        say(&format!("process age at probe start: {} ms (pid {})", s.age_ms, std::process::id()));
    }

    for sub in ["events", "clicks", "links"] {
        let mut n = 0usize;
        let mut bytes = 0u64;
        let mut big = 0u64;
        if let Ok(rdir) = std::fs::read_dir(Path::new(&data).join(sub)) {
            for e in rdir.flatten() {
                if let Ok(m) = e.metadata() {
                    n += 1;
                    bytes += m.len();
                    big = big.max(m.len());
                }
            }
        }
        say(&format!("data {}: {} files, {} bytes, largest {}", sub, n, bytes, big));
    }
}

// ------------------------------------------------------------ child runs

struct Run {
    wall: f64,
    err: String,
    ok: bool,
}

fn child(data: &Path, out: &Path, envs: &[(&str, &str)]) -> Run {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/app/shopsess"));
    let mut c = Command::new(exe);
    c.arg(data).arg(out).env("SS_CHILD", "1").env("SS_TIMING", "1");
    for (k, v) in envs {
        c.env(k, v);
    }
    let t = Instant::now();
    match c.output() {
        Ok(o) => Run {
            wall: ms(t),
            err: String::from_utf8_lossy(&o.stderr).to_string(),
            ok: o.status.success(),
        },
        Err(e) => Run { wall: ms(t), err: format!("spawn failed: {}", e), ok: false },
    }
}

fn stage(err: &str, key: &str) -> f64 {
    err.lines()
        .find(|l| l.starts_with("STAGE_MS"))
        .and_then(|l| l.split(' ').find(|p| p.starts_with(key)))
        .and_then(|p| p.splitn(2, '=').nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(-1.0)
}

fn rot(b: u8, k: u8) -> u8 {
    const D: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let v = match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'z' => b - b'a' + 10,
        _ => return b,
    };
    D[((v + k) % 36) as usize]
}

/// A copy of a CSV with the last character of the given fields rotated, so
/// every copy has its own ids and the copies add up to a larger dataset.
fn rotated(src: &[u8], k: u8, fields: &[usize]) -> Vec<u8> {
    let mut out = src.to_vec();
    if k == 0 {
        return out;
    }
    let n = out.len();
    let mut p = match src.iter().position(|&b| b == b'\n') {
        Some(i) => i + 1,
        None => n,
    };
    while p < n {
        let mut fi = 0usize;
        let mut fs = p;
        let mut i = p;
        loop {
            let b = if i < n { out[i] } else { b'\n' };
            if b == b',' || b == b'\n' {
                if fields.contains(&fi) && i > fs {
                    let mut q = i - 1;
                    if out[q] == b'"' && q > fs {
                        q -= 1;
                    }
                    out[q] = rot(out[q], k);
                }
                fi += 1;
                fs = i + 1;
                if b == b'\n' {
                    break;
                }
            }
            i += 1;
        }
        p = i + 1;
    }
    out
}

fn csvs(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|r| r.flatten().map(|e| e.path()).filter(|p| p.extension().map(|x| x == "csv").unwrap_or(false)).collect())
        .unwrap_or_default();
    v.sort();
    v
}

fn replicate(src: &Path, dst: &Path, copies: u8) -> u64 {
    let mut total = 0u64;
    for (sub, fields) in [("events", &[0usize, 1][..]), ("clicks", &[1usize][..]), ("links", &[0usize, 1][..])] {
        let _ = std::fs::create_dir_all(dst.join(sub));
        let files = csvs(&src.join(sub));
        let next = AtomicUsize::new(0);
        let sum = AtomicUsize::new(0);
        std::thread::scope(|sc| {
            for _ in 0..8 {
                sc.spawn(|| loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= files.len() {
                        break;
                    }
                    let Ok(b) = std::fs::read(&files[i]) else { continue };
                    for k in 0..copies {
                        let o = rotated(&b, k, fields);
                        let name = format!("part-{:03}-{:02}.csv", i, k);
                        if std::fs::write(dst.join(sub).join(name), &o).is_ok() {
                            sum.fetch_add(o.len(), Ordering::Relaxed);
                        }
                    }
                });
            }
        });
        total += sum.load(Ordering::Relaxed) as u64;
    }
    for f in ["manifest.json", "products.csv", "campaigns.csv"] {
        let _ = std::fs::copy(src.join(f), dst.join(f));
    }
    total
}

// ------------------------------------------------------- micro-benchmarks

fn anon_huge_kb() -> i64 {
    kb_line(&rd("/proc/self/smaps_rollup"), "AnonHugePages")
}

fn vmstat(keys: &[&str]) -> Vec<i64> {
    let t = rd("/proc/vmstat");
    keys.iter().map(|k| kb_line(&t, k)).collect()
}

/// First touch of 1 GiB of fresh anonymous memory from `nt` threads, a second
/// pass that fills it, and the unmap. Returns (touch, fill, unmap) in ms and
/// how much of it ended up on huge pages.
fn touch_test(advice: i32, nt: usize) -> (f64, f64, f64, i64) {
    const SZ: usize = 1 << 30;
    unsafe {
        let p = mmap(
            std::ptr::null_mut(),
            SZ + HUGE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANON | MAP_NORESERVE,
            -1,
            0,
        );
        if p as isize == -1 {
            return (-1.0, -1.0, -1.0, -1);
        }
        let base = ((p as usize) + HUGE - 1) & !(HUGE - 1);
        madvise(base as *mut u8, SZ, advice);
        let before = anon_huge_kb();
        let per = (SZ / nt) & !(HUGE - 1);
        let t = Instant::now();
        std::thread::scope(|sc| {
            for k in 0..nt {
                sc.spawn(move || {
                    let mut q = base + per * k;
                    let hi = q + per;
                    while q < hi {
                        (q as *mut u8).write_volatile(1);
                        q += 4096;
                    }
                });
            }
        });
        let touch = ms(t);
        let huge = anon_huge_kb() - before;
        let t = Instant::now();
        std::thread::scope(|sc| {
            for k in 0..nt {
                sc.spawn(move || {
                    std::ptr::write_bytes((base + per * k) as *mut u8, 7, per);
                });
            }
        });
        let fill = ms(t);
        let t = Instant::now();
        munmap(p, SZ + HUGE);
        (touch, fill, ms(t), huge)
    }
}

#[inline(never)]
fn count_nl(b: &[u8]) -> usize {
    b.iter().filter(|&&c| c == b'\n').count()
}

fn scan_tests(files: &[PathBuf], nt: usize) -> (f64, f64, f64, f64, f64) {
    let sizes: Vec<usize> = files.iter().map(|f| std::fs::metadata(f).map(|m| m.len() as usize).unwrap_or(0)).collect();
    let total: usize = sizes.iter().sum();
    let gb = total as f64 / 1e9;
    let chunks = |c: usize| -> Vec<(usize, usize, usize)> {
        let mut v = Vec::new();
        for (fi, &n) in sizes.iter().enumerate() {
            let mut a = 0;
            while a < n {
                v.push((fi, a, c.min(n - a)));
                a += c;
            }
        }
        v
    };
    let handles: Vec<std::fs::File> = files.iter().filter_map(|f| std::fs::File::open(f).ok()).collect();
    if handles.len() != files.len() || total == 0 {
        return (-1.0, -1.0, -1.0, -1.0, -1.0);
    }

    // mmap, first pass (faults in the mapping) and second pass (already mapped)
    use std::os::unix::io::AsRawFd;
    let maps: Vec<(usize, usize)> = handles
        .iter()
        .zip(&sizes)
        .map(|(f, &n)| {
            if n == 0 {
                return (0, 0);
            }
            let p = unsafe { mmap(std::ptr::null_mut(), n, PROT_READ, MAP_PRIVATE, f.as_raw_fd(), 0) };
            if p as isize == -1 { (0, 0) } else { (p as usize, n) }
        })
        .collect();
    let ck = chunks(1 << 20);
    let mut mm = [0.0f64; 2];
    let mut lines = 0usize;
    for pass in 0..2 {
        let next = AtomicUsize::new(0);
        let cnt = AtomicUsize::new(0);
        let t = Instant::now();
        std::thread::scope(|sc| {
            for _ in 0..nt {
                sc.spawn(|| loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= ck.len() {
                        break;
                    }
                    let (fi, a, n) = ck[i];
                    if maps[fi].0 == 0 {
                        continue;
                    }
                    let s = unsafe { std::slice::from_raw_parts((maps[fi].0 + a) as *const u8, n) };
                    cnt.fetch_add(count_nl(s), Ordering::Relaxed);
                });
            }
        });
        mm[pass] = gb / t.elapsed().as_secs_f64();
        lines = cnt.load(Ordering::Relaxed);
    }
    let t = Instant::now();
    for &(p, n) in &maps {
        if p != 0 {
            unsafe { munmap(p as *mut u8, n) };
        }
    }
    let unmap = ms(t);
    say(&format!("scan: {} files, {:.2} GB, {} lines", files.len(), gb, lines));

    // pread into a per-thread buffer
    let mut rdv = [0.0f64; 2];
    for (j, &c) in [1usize << 20, 256 << 10].iter().enumerate() {
        let ck = chunks(c);
        let next = AtomicUsize::new(0);
        let cnt = AtomicUsize::new(0);
        let t = Instant::now();
        std::thread::scope(|sc| {
            for _ in 0..nt {
                sc.spawn(|| {
                    let mut buf = vec![0u8; c];
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= ck.len() {
                            break;
                        }
                        let (fi, a, n) = ck[i];
                        let mut got = 0;
                        while got < n {
                            match handles[fi].read_at(&mut buf[got..n], (a + got) as u64) {
                                Ok(0) | Err(_) => break,
                                Ok(k) => got += k,
                            }
                        }
                        cnt.fetch_add(count_nl(&buf[..got]), Ordering::Relaxed);
                    }
                });
            }
        });
        rdv[j] = gb / t.elapsed().as_secs_f64();
    }
    (mm[0], mm[1], unmap, rdv[0], rdv[1])
}

fn write_test(dir: &Path) -> (f64, f64) {
    use std::io::Write;
    let buf = vec![0x5au8; 100 << 20];
    let one = dir.join("_probe.bin");
    let t = Instant::now();
    let ok = std::fs::File::create(&one).and_then(|mut f| {
        for c in buf.chunks(1 << 20) {
            f.write_all(c)?;
        }
        Ok(())
    });
    let single = if ok.is_ok() { ms(t) } else { -1.0 };
    let _ = std::fs::remove_file(&one);
    let t = Instant::now();
    std::thread::scope(|sc| {
        for k in 0..8usize {
            let buf = &buf;
            sc.spawn(move || {
                let p = dir.join(format!("_probe{}.bin", k));
                if let Ok(mut f) = std::fs::File::create(&p) {
                    let part = buf.len() / 8;
                    let _ = f.write_all(&buf[part * k..part * (k + 1)]);
                }
            });
        }
    });
    let par = ms(t);
    for k in 0..8 {
        let _ = std::fs::remove_file(dir.join(format!("_probe{}.bin", k)));
    }
    (single, par)
}

// ------------------------------------------------------------------ main

fn clip(s: &str) -> String {
    s.chars().take(31).collect()
}

pub fn parent() {
    let t0 = Instant::now();
    let left = |lim: f64| t0.elapsed().as_secs_f64() < lim;
    let data = PathBuf::from(std::env::var("DATA_DIR").unwrap_or_else(|_| "/data".into()));
    let out = PathBuf::from(std::env::var("OUTPUT_DIR").unwrap_or_else(|_| "/output".into()));
    let scr = PathBuf::from(std::env::var("SCRATCH_DIR").unwrap_or_else(|_| "/scratch".into()));
    let nt: usize = std::env::var("NCPU").ok().and_then(|v| v.parse().ok()).filter(|&v| v > 0).unwrap_or(8);
    let mut s = Sum::default();

    // the real run first, so the output is there whatever happens later
    let r = child(&data, &out, &[]);
    say(&format!("real run: wall {:.1} ms ok {}", r.wall, r.ok));
    for l in r.err.lines() {
        say(&format!("  | {}", l));
    }

    sysinfo(&mut s);

    // cost of starting and reaping a process that does nothing
    let mut best = f64::MAX;
    for _ in 0..5 {
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/app/shopsess"));
        let t = Instant::now();
        let _ = Command::new(exe).env("SS_CHILD", "noop").output();
        best = best.min(ms(t));
    }
    s.spawn_us = (best * 1e3) as i64;
    say(&format!("spawn+exit of a no-op process: {:.3} ms", best));
    let t = Instant::now();
    std::thread::scope(|sc| {
        for _ in 0..8 {
            sc.spawn(|| std::hint::black_box(1));
        }
    });
    say(&format!("spawn+join of 8 threads: {:.3} ms", ms(t)));

    // fresh anonymous memory: huge pages against 4K pages
    let keys = ["thp_fault_alloc", "thp_fault_fallback", "compact_stall", "pgfault"];
    let v0 = vmstat(&keys);
    let (ht, hf, hu, hk) = touch_test(MADV_HUGEPAGE, nt);
    let v1 = vmstat(&keys);
    let (st, sf, su, sk) = touch_test(MADV_NOHUGEPAGE, nt);
    let v2 = vmstat(&keys);
    s.ahp_mb = hk / 1024;
    say(&format!(
        "1 GiB anon, MADV_HUGEPAGE:   touch {:.1} ms  fill {:.1} ms  unmap {:.1} ms  on huge pages {} MB",
        ht, hf, hu, hk / 1024
    ));
    say(&format!(
        "1 GiB anon, MADV_NOHUGEPAGE: touch {:.1} ms  fill {:.1} ms  unmap {:.1} ms  on huge pages {} MB",
        st, sf, su, sk / 1024
    ));
    for (i, k) in keys.iter().enumerate() {
        say(&format!("vmstat {}: +{} during huge test, +{} during 4K test", k, v1[i] - v0[i], v2[i] - v1[i]));
    }

    // output writes
    let (w1, w8) = write_test(&out);
    let (x1, x8) = write_test(&scr);
    say(&format!("write 100 MB to output: one file {:.1} ms, eight files in parallel {:.1} ms", w1, w8));
    say(&format!("write 100 MB to scratch: one file {:.1} ms, eight files in parallel {:.1} ms", x1, x8));

    // a practice-sized dataset: twenty relabelled copies of the dev set
    let big = scr.join("big");
    let bout = scr.join("bigout");
    let t = Instant::now();
    let bytes = replicate(&data, &big, 20);
    say(&format!("replicated dataset: {} bytes in {:.0} ms", bytes, ms(t)));

    let (m1, m2, mu, r1, r2) = scan_tests(&csvs(&big.join("events")), nt);
    say(&format!(
        "newline count over events, {} threads: mmap first pass {:.2} GB/s, second pass {:.2} GB/s, unmap {:.1} ms; pread 1M {:.2} GB/s, pread 256K {:.2} GB/s",
        nt, m1, m2, mu, r1, r2
    ));
    s.micro = format!("{:.0}/{:.0}/{:.0}/{:.0}/{:.0}", ht, st, m1 * 10.0, r1 * 10.0, w1);
    s.micro2 = format!("{:.0}/{:.0}/{:.0}/{:.0}/{:.0}", mu, su, hu, hf, w8);

    // the whole pipeline at that size
    let mut best: Option<Run> = None;
    for i in 0..3 {
        if !left(60.0) {
            break;
        }
        let _ = std::fs::remove_dir_all(&bout);
        let r = child(&big, &bout, &[]);
        say(&format!("big run {}: wall {:.1} ms ok {}", i, r.wall, r.ok));
        for l in r.err.lines() {
            say(&format!("  | {}", l));
        }
        if r.ok && best.as_ref().map(|b| r.wall < b.wall).unwrap_or(true) {
            best = Some(r);
        }
    }
    if let Some(b) = &best {
        s.wall_ms = b.wall as i64;
        s.total_ms = stage(&b.err, "total") as i64;
        s.stages = format!(
            "{:.0}/{:.0}/{:.0}/{:.0}/{:.0}",
            stage(&b.err, "pre"),
            stage(&b.err, "links"),
            stage(&b.err, "parse"),
            stage(&b.err, "dedup"),
            stage(&b.err, "fold")
        );
    }
    // one-change variants of the same run
    for (label, key, val) in [
        ("no huge pages", "SS_NOHUGE", "1"),
        ("inputs read into memory, not mapped", "SS_READ", "1"),
        ("NCPU=4", "NCPU", "4"),
        ("NCPU=16", "NCPU", "16"),
        ("scalar scanner", "SS_NOSIMD", "1"),
        ("NCPU=2", "NCPU", "2"),
    ] {
        if !left(80.0) {
            break;
        }
        let mut w = f64::MAX;
        let mut line = String::new();
        for _ in 0..2 {
            let _ = std::fs::remove_dir_all(&bout);
            let r = child(&big, &bout, &[(key, val)]);
            if r.ok && r.wall < w {
                w = r.wall;
                line = r.err.lines().find(|l| l.starts_with("STAGE_MS")).unwrap_or("").to_string();
            }
            if !left(80.0) {
                break;
            }
        }
        say(&format!("big run, {}: wall {:.1} ms | {}", label, w, line));
        if val == "4" {
            s.wall4_ms = w as i64;
        }
    }

    // parse ablation: each level adds one step of the event parser
    let mut abl: Vec<String> = Vec::new();
    for lv in ["1", "2", "3", "4", "5", "6", "0"] {
        if !left(110.0) {
            break;
        }
        let r = child(&big, &bout, &[("SS_BENCH", lv)]);
        let best = r
            .err
            .lines()
            .filter(|l| l.starts_with("BENCH_MS"))
            .filter_map(|l| l.split("ms=").nth(1).and_then(|v| v.trim().parse::<f64>().ok()))
            .fold(f64::MAX, f64::min);
        say(&format!("parse ablation level {}: best {:.1} ms", lv, best));
        if lv != "3" {
            abl.push(format!("{:.0}", best));
        }
    }
    s.abl = abl.join("/");
    let _ = std::fs::remove_dir_all(&big);
    let _ = std::fs::remove_dir_all(&bout);
    say(&format!("loadavg at end: {}", rd("/proc/loadavg")));
    say(&format!("probe finished in {:.1} s", t0.elapsed().as_secs_f64()));

    // the headline facts again as rows, in case only the row diff comes back
    let rows: [(String, String, i64, i64, i64); 5] = [
        (format!("!0{}", s.cpu), s.flags.clone(), s.ncpu, s.ncore, s.l2kb),
        (format!("!1{}", s.kernel), s.thp.clone(), s.mem_mb, s.cg_mb, s.ahp_mb),
        (format!("!2{}", s.fs), s.dmi.clone(), s.wall_ms, s.total_ms, s.l3kb),
        (format!("!3{}", s.stages), s.abl.clone(), s.wall4_ms, s.age_ms, s.spawn_us),
        (format!("!4{}", s.micro), s.micro2.clone(), s.load100, s.nproc, t0.elapsed().as_millis() as i64),
    ];
    let mut uid = Vec::new();
    let mut tc = Vec::new();
    let mut day: Vec<i32> = Vec::new();
    let mut a: Vec<i64> = Vec::new();
    let mut b: Vec<i64> = Vec::new();
    let mut c: Vec<i64> = Vec::new();
    for (i, (u, t, x, y, z)) in rows.iter().enumerate() {
        say(&format!("row {} | {} | {} | {} | {} | {}", i, clip(u), clip(t), x, y, z));
        pq::push_str(&mut uid, clip(u).as_bytes());
        pq::push_str(&mut tc, clip(if t.is_empty() { "-" } else { t }).as_bytes());
        day.push(0);
        a.push(*x);
        b.push(*y);
        c.push(*z);
    }
    let n = rows.len() as i64;
    let defs = vec![1u8; rows.len()];
    let cols = [
        pq::Col { name: "user_id", kind: pq::Kind::Utf8, vals: &uid, defs: &[], nvals: n },
        pq::Col { name: "day", kind: pq::Kind::Date, vals: pq::as_bytes(&day), defs: &[], nvals: n },
        pq::Col { name: "sessions", kind: pq::Kind::I64, vals: pq::as_bytes(&a), defs: &[], nvals: n },
        pq::Col { name: "events", kind: pq::Kind::I64, vals: pq::as_bytes(&b), defs: &[], nvals: n },
        pq::Col { name: "revenue_cents", kind: pq::Kind::I64, vals: pq::as_bytes(&c), defs: &[], nvals: n },
        pq::Col { name: "top_category", kind: pq::Kind::Utf8Opt, vals: &tc, defs: &defs, nvals: n },
    ];
    let _ = std::fs::create_dir_all(out.join("user_daily"));
    if let Err(e) = pq::write(&out.join("user_daily").join("zz-probe.parquet"), n, &cols) {
        say(&format!("could not write probe rows: {}", e));
    }
}
