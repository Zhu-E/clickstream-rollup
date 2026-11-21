// Low-level OS bits: mmap'd input files, a huge-page bump arena, bucketed sinks.
#![allow(dead_code)]
use std::sync::atomic::{AtomicUsize, Ordering};

extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    fn munmap(addr: *mut u8, len: usize) -> i32;
    fn madvise(addr: *mut u8, len: usize, advice: i32) -> i32;
}

const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const MAP_PRIVATE: i32 = 2;
#[cfg(target_os = "linux")]
const MAP_ANON: i32 = 0x20;
#[cfg(not(target_os = "linux"))]
const MAP_ANON: i32 = 0x1000;
#[cfg(target_os = "linux")]
const MAP_NORESERVE: i32 = 0x4000;
#[cfg(not(target_os = "linux"))]
const MAP_NORESERVE: i32 = 0x40;
const MADV_WILLNEED: i32 = 3;
#[cfg(target_os = "linux")]
const MADV_HUGEPAGE: i32 = 14;

/// Zeroed anonymous memory for the big hash tables. The pages arrive zeroed
/// without a memset, and on Linux they can be huge pages, which matters
/// because a 64 MB table otherwise takes a TLB miss on most probes. All-zero
/// bytes must be a valid `T`.
pub struct Blob<T: Copy> {
    ptr: *mut T,
    len: usize,
    base: *mut u8,
    bytes: usize,
}
unsafe impl<T: Copy> Send for Blob<T> {}
unsafe impl<T: Copy> Sync for Blob<T> {}

const HUGE: usize = 1 << 21;

impl<T: Copy> Blob<T> {
    pub fn zeroed(len: usize) -> Blob<T> {
        let want = len * std::mem::size_of::<T>();
        // Over-allocate large tables so the start can be moved to a 2 MB
        // boundary; without that the kernel has nowhere to put a huge page.
        let pad = if want >= HUGE { HUGE } else { 0 };
        let bytes = want + pad;
        let base = unsafe {
            mmap(std::ptr::null_mut(), bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0)
        };
        assert!(base as isize != -1, "blob mmap failed");
        let ptr = if pad == 0 {
            base
        } else {
            let a = ((base as usize) + HUGE - 1) & !(HUGE - 1);
            #[cfg(target_os = "linux")]
            unsafe {
                if std::env::var_os("SS_NOHUGE").is_none() {
                    madvise(a as *mut u8, want, MADV_HUGEPAGE);
                }
            }
            a as *mut u8
        };
        Blob { ptr: ptr as *mut T, len, base, bytes }
    }
}

impl<T: Copy> Drop for Blob<T> {
    fn drop(&mut self) {
        unsafe { munmap(self.base, self.bytes) };
    }
}

impl<T: Copy> std::ops::Deref for Blob<T> {
    type Target = [T];
    #[inline(always)]
    fn deref(&self) -> &[T] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl<T: Copy> std::ops::DerefMut for Blob<T> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut [T] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

/// Pull a line into L1 well before it is needed. A real prefetch rather than a
/// discarded load, because a load has to land in a register and the extra
/// pressure across the parse loop cost more than the miss it hid: swapping the
/// two took 32 instructions per row back off.
///
/// `_mm_prefetch` has been stable since 1.27 and takes its hint positionally
/// under `rustc_legacy_const_generics`; `prfm` is plain aarch64. Anything else
/// gets the load, which is correct everywhere and merely slower.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn prefetch(p: *const u8) {
    unsafe { core::arch::x86_64::_mm_prefetch(p as *const i8, core::arch::x86_64::_MM_HINT_T0) }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub fn prefetch(p: *const u8) {
    unsafe {
        core::arch::asm!(
            "prfm pldl1keep, [{x}]",
            x = in(reg) p,
            options(nostack, readonly, preserves_flags),
        )
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline(always)]
pub fn prefetch(p: *const u8) {
    unsafe {
        std::ptr::read_volatile(p);
    }
}

/// A read-only mapping of a whole file.
pub struct Map {
    pub ptr: *const u8,
    pub len: usize,
}
unsafe impl Send for Map {}
unsafe impl Sync for Map {}

impl Map {
    pub fn open(path: &std::path::Path) -> std::io::Result<Map> {
        use std::os::unix::io::AsRawFd;
        let f = std::fs::File::open(path)?;
        let len = f.metadata()?.len() as usize;
        if len == 0 {
            return Ok(Map { ptr: std::ptr::NonNull::<u8>::dangling().as_ptr(), len: 0 });
        }
        // probe A/B: copy the file into anonymous memory instead of mapping it
        if std::env::var_os("SS_READ").is_some() {
            use std::os::unix::fs::FileExt;
            let p = unsafe {
                mmap(std::ptr::null_mut(), len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0)
            };
            if p as isize == -1 {
                return Err(std::io::Error::last_os_error());
            }
            let buf = unsafe { std::slice::from_raw_parts_mut(p, len) };
            let mut got = 0usize;
            while got < len {
                match f.read_at(&mut buf[got..], got as u64)? {
                    0 => break,
                    k => got += k,
                }
            }
            return Ok(Map { ptr: p, len });
        }
        let p = unsafe { mmap(std::ptr::null_mut(), len, PROT_READ, MAP_PRIVATE, f.as_raw_fd(), 0) };
        if p as isize == -1 {
            return Err(std::io::Error::last_os_error());
        }
        unsafe { madvise(p, len, MADV_WILLNEED) };
        Ok(Map { ptr: p, len })
    }
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

/// One big anonymous mapping handed out with a bump pointer. Transparent huge
/// pages keep the page-fault count (and TLB misses) down on the shuffle arrays.
pub struct Arena {
    base: *mut u8,
    cap: usize,
    next: AtomicUsize,
}
unsafe impl Send for Arena {}
unsafe impl Sync for Arena {}

impl Drop for Arena {
    fn drop(&mut self) {
        unsafe { munmap(self.base, self.cap) };
    }
}

impl Arena {
    pub fn new(cap: usize) -> Arena {
        let cap = (cap + (1 << 21) - 1) & !((1 << 21) - 1);
        let p = unsafe {
            mmap(
                std::ptr::null_mut(),
                cap,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANON | MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert!(p as isize != -1, "arena mmap failed");
        #[cfg(target_os = "linux")]
        unsafe {
            if std::env::var_os("SS_NOHUGE").is_none() {
                madvise(p, cap, MADV_HUGEPAGE);
            }
        }
        Arena { base: p, cap, next: AtomicUsize::new(0) }
    }
    /// Grab a slab of raw bytes (2 MiB aligned chunks keep huge pages intact).
    pub fn slab(&self, bytes: usize) -> *mut u8 {
        let bytes = (bytes + 63) & !63;
        let off = self.next.fetch_add(bytes, Ordering::Relaxed);
        assert!(off + bytes <= self.cap, "arena exhausted");
        unsafe { self.base.add(off) }
    }
    pub fn used(&self) -> usize {
        self.next.load(Ordering::Relaxed)
    }
}

pub const SLAB: usize = 4 << 20;

/// Per-thread bump allocator pulling slabs from the shared arena.
pub struct Bump<'a> {
    arena: &'a Arena,
    cur: *mut u8,
    rem: usize,
}
impl<'a> Bump<'a> {
    pub fn new(arena: &'a Arena) -> Bump<'a> {
        Bump { arena, cur: std::ptr::null_mut(), rem: 0 }
    }
    #[inline]
    pub fn alloc(&mut self, bytes: usize) -> *mut u8 {
        let bytes = (bytes + 63) & !63;
        if bytes > self.rem {
            let want = if bytes > SLAB { bytes } else { SLAB };
            self.cur = self.arena.slab(want);
            self.rem = want;
        }
        let p = self.cur;
        unsafe {
            self.cur = self.cur.add(bytes);
        }
        self.rem -= bytes;
        p
    }
}

/// A block of records belonging to one bucket.
#[derive(Copy, Clone)]
pub struct Blk<T> {
    pub ptr: *const T,
    pub len: u32,
}
unsafe impl<T> Send for Blk<T> {}
unsafe impl<T> Sync for Blk<T> {}
impl<T> Blk<T> {
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len as usize) }
    }
}

/// Scatters records into `nb` buckets as linked lists of fixed-size blocks.
/// Write a full cache line, bypassing the cache where the target has an
/// instruction for it. A line written whole needs no read-for-ownership, so
/// the shuffle stops reading the memory it is about to overwrite, and the
/// record stream stops evicting the link map and the Bloom filter.
///
/// `dst` must be 64-byte aligned and `bytes` a multiple of 64.
#[cfg(all(target_arch = "x86_64", target_feature = "avx"))]
#[inline(always)]
unsafe fn stream(dst: *mut u8, src: *const u8, bytes: usize) {
    use core::arch::x86_64::*;
    let mut i = 0;
    while i < bytes {
        let v = _mm256_loadu_si256(src.add(i) as *const __m256i);
        _mm256_stream_si256(dst.add(i) as *mut __m256i, v);
        i += 32;
    }
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn stream(dst: *mut u8, src: *const u8, bytes: usize) {
    use core::arch::aarch64::*;
    if !NT {
        std::ptr::copy_nonoverlapping(src, dst, bytes);
        return;
    }
    let mut i = 0;
    while i < bytes {
        let a = vld1q_u8(src.add(i));
        let b = vld1q_u8(src.add(i + 16));
        core::arch::asm!(
            "stnp {a:q}, {b:q}, [{p}]",
            a = in(vreg) a,
            b = in(vreg) b,
            p = in(reg) dst.add(i),
            options(nostack, preserves_flags),
        );
        i += 32;
    }
}

#[cfg(not(any(all(target_arch = "x86_64", target_feature = "avx"), target_arch = "aarch64")))]
#[inline(always)]
unsafe fn stream(dst: *mut u8, src: *const u8, bytes: usize) {
    std::ptr::copy_nonoverlapping(src, dst, bytes);
}

/// Order the non-temporal stores before whatever the reader synchronises on.
#[inline(always)]
pub fn stream_fence() {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_mm_sfence()
    }
}

/// Hold records back per bucket and write whole cache lines non-temporally.
/// Off, because it measured slower: see README. `SS_WC=1` at build time turns
/// it on, `SS_WC=1 SS_NONT=1` keeps the staging but stores the line normally,
/// which is how the staging cost and the instruction's effect were separated.
const WC: bool = option_env!("SS_WC").is_some();
const NT: bool = option_env!("SS_NONT").is_none();

pub struct Sink<'a, T: Copy> {
    bump: Bump<'a>,
    nb: usize,
    blk_items: usize,
    cur: Vec<*mut T>,
    rem: Vec<u32>,
    /// One cache line's worth of records per bucket, held back so each bucket
    /// is written a whole line at a time instead of a record at a time.
    stg: Blob<u8>,
    sn: Vec<u8>,
    pub blocks: Vec<Vec<Blk<T>>>,
}

impl<'a, T: Copy> Sink<'a, T> {
    const SZ: usize = std::mem::size_of::<T>();
    /// The smallest run of records that is a whole number of cache lines.
    const LINE: usize = {
        let mut l = 64;
        while l % Self::SZ != 0 {
            l += 64;
        }
        l
    };
    const SREC: usize = Self::LINE / Self::SZ;

    pub fn new(arena: &'a Arena, nb: usize, blk_items: usize) -> Sink<'a, T> {
        // A staged line must never straddle two blocks.
        assert!(blk_items % Self::SREC == 0, "block size must hold whole lines");
        Sink {
            bump: Bump::new(arena),
            nb,
            blk_items,
            cur: vec![std::ptr::null_mut(); nb],
            rem: vec![0u32; nb],
            stg: Blob::zeroed(if WC { nb * Self::LINE } else { 1 }),
            sn: vec![0u8; nb],
            blocks: (0..nb).map(|_| Vec::new()).collect(),
        }
    }
    #[inline(always)]
    pub fn push(&mut self, b: usize, v: T) {
        unsafe {
            if !WC {
                let r = *self.rem.get_unchecked(b);
                if r == 0 {
                    self.grow(b);
                }
                let c = self.cur.get_unchecked_mut(b);
                **c = v;
                *c = c.add(1);
                *self.rem.get_unchecked_mut(b) -= 1;
                return;
            }
            let n = *self.sn.get_unchecked(b) as usize;
            let s = self.stg.as_mut_ptr().add(b * Self::LINE + n * Self::SZ);
            std::ptr::write_unaligned(s as *mut T, v);
            if n + 1 < Self::SREC {
                *self.sn.get_unchecked_mut(b) = (n + 1) as u8;
                return;
            }
            *self.sn.get_unchecked_mut(b) = 0;
            if *self.rem.get_unchecked(b) == 0 {
                self.grow(b);
            }
            let dst = *self.cur.get_unchecked(b);
            stream(dst as *mut u8, s.sub(n * Self::SZ), Self::LINE);
            *self.cur.get_unchecked_mut(b) = dst.add(Self::SREC);
            *self.rem.get_unchecked_mut(b) -= Self::SREC as u32;
        }
    }
    #[cold]
    fn grow(&mut self, b: usize) {
        let p = self.bump.alloc(self.blk_items * std::mem::size_of::<T>()) as *mut T;
        if !self.cur[b].is_null() {
            let start = unsafe { self.cur[b].sub(self.blk_items) };
            self.blocks[b].push(Blk { ptr: start, len: self.blk_items as u32 });
        }
        self.cur[b] = p;
        self.rem[b] = self.blk_items as u32;
    }
    /// Close out the partially filled blocks.
    pub fn finish(mut self) -> Vec<Vec<Blk<T>>> {
        // Records still staged go out with ordinary stores: a part of a line
        // is exactly what a non-temporal store is bad at.
        if WC {
            for b in 0..self.nb {
                let n = self.sn[b] as usize;
                if n == 0 {
                    continue;
                }
                unsafe {
                    if *self.rem.get_unchecked(b) == 0 {
                        self.grow(b);
                    }
                    let dst = *self.cur.get_unchecked(b);
                    let src = self.stg.as_ptr().add(b * Self::LINE) as *const T;
                    std::ptr::copy_nonoverlapping(src, dst, n);
                    *self.cur.get_unchecked_mut(b) = dst.add(n);
                    *self.rem.get_unchecked_mut(b) -= n as u32;
                }
                self.sn[b] = 0;
            }
            stream_fence();
        }
        for b in 0..self.nb {
            if !self.cur[b].is_null() {
                let used = self.blk_items - self.rem[b] as usize;
                if used > 0 {
                    let start = unsafe { self.cur[b].sub(used) };
                    self.blocks[b].push(Blk { ptr: start, len: used as u32 });
                }
            }
        }
        std::mem::take(&mut self.blocks)
    }
}

/// Merge per-thread bucket lists into one list per bucket.
pub fn merge_blocks<T: Copy>(parts: Vec<Vec<Vec<Blk<T>>>>, nb: usize) -> Vec<Vec<Blk<T>>> {
    let mut out: Vec<Vec<Blk<T>>> = (0..nb).map(|_| Vec::new()).collect();
    for p in parts {
        for (b, list) in p.into_iter().enumerate() {
            if !list.is_empty() {
                out[b].extend_from_slice(&list);
            }
        }
    }
    out
}

/// Shared read-only wrapper so raw pointers can cross thread boundaries.
pub struct Shared<T>(pub T);
unsafe impl<T> Send for Shared<T> {}
unsafe impl<T> Sync for Shared<T> {}
