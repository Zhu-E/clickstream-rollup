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
            madvise(p, cap, MADV_HUGEPAGE);
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
pub struct Sink<'a, T: Copy> {
    bump: Bump<'a>,
    nb: usize,
    blk_items: usize,
    cur: Vec<*mut T>,
    rem: Vec<u32>,
    pub blocks: Vec<Vec<Blk<T>>>,
}

impl<'a, T: Copy> Sink<'a, T> {
    pub fn new(arena: &'a Arena, nb: usize, blk_items: usize) -> Sink<'a, T> {
        Sink {
            bump: Bump::new(arena),
            nb,
            blk_items,
            cur: vec![std::ptr::null_mut(); nb],
            rem: vec![0u32; nb],
            blocks: (0..nb).map(|_| Vec::new()).collect(),
        }
    }
    #[inline(always)]
    pub fn push(&mut self, b: usize, v: T) {
        unsafe {
            let r = *self.rem.get_unchecked(b);
            if r == 0 {
                self.grow(b);
            }
            let c = self.cur.get_unchecked_mut(b);
            **c = v;
            *c = c.add(1);
            *self.rem.get_unchecked_mut(b) -= 1;
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
