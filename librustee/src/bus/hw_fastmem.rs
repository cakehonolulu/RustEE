use super::{map, Bus};
use region::{Allocation, Protection};
use std::io::{self, ErrorKind};
use super::HW_BASE;
use std::sync::atomic::Ordering;
use tracing::debug;

pub unsafe fn init_hardware_fastmem(bus: &mut Bus) {
    debug!("Initializing Hardware Fast Memory...");
    debug!("Installing handler...");
    unsafe { super::install_handler().expect("Failed to install handler") };
    debug!("Handler installed");

    debug!("Initializing hardware arena...");
    let (arena, base, size) = unsafe { init_hardware_arena(bus).expect("Failed to init arena") };
    debug!("Hardware arena initialized");

    bus.hw_base = base;
    bus.hw_size = size;
    bus.arena = Some(arena);
    HW_BASE.store(base as usize, Ordering::SeqCst);

    debug!(
        "Initialized Hardware Fast Memory: base=0x{:08X}, size={}",
        bus.hw_base as usize, bus.hw_size
    );
}

pub unsafe fn init_hardware_arena(bus: &Bus) -> io::Result<(Allocation, *mut u8, usize)> {
    let hw_size = (map::BIOS.0 as usize) + (map::BIOS.1 as usize);

    let mut alloc = region::alloc(hw_size, Protection::NONE)
        .map_err(|e| io::Error::new(ErrorKind::Other, e))?;

    let base = alloc.as_mut_ptr::<u8>();

    let ram_addr = unsafe { base.add(map::RAM.0 as usize) };
    unsafe { region::protect(ram_addr, map::RAM.1 as usize, Protection::READ_WRITE)
        .map_err(|e| io::Error::new(ErrorKind::Other, e)) }?;

    let bios_addr = unsafe { base.add(map::BIOS.0 as usize) };
    unsafe { region::protect(bios_addr, map::BIOS.1 as usize, Protection::READ_WRITE)
        .map_err(|e| io::Error::new(ErrorKind::Other, e)) }?;

    let bios_len = map::BIOS.1 as usize;
    let dst: &mut [u8] = unsafe { std::slice::from_raw_parts_mut(bios_addr, bios_len) };
    dst.copy_from_slice(&bus.bios.bytes);

    unsafe { region::protect(bios_addr, map::BIOS.1 as usize, Protection::READ_EXECUTE)
        .map_err(|e| io::Error::new(ErrorKind::Other, e)) }?;

    Ok((alloc, base, hw_size))
}

impl Bus {
    #[inline]
    pub fn hw_read32(&self, addr: u32) -> u32 {
        assert!((addr as usize) + 4 <= self.hw_size);
        unsafe { (self.hw_base.add(addr as usize) as *const u32).read_unaligned() }
    }

    #[inline]
    pub fn hw_write32(&mut self, addr: u32, val: u32) {
        assert!((addr as usize) + 4 <= self.hw_size);
        unsafe { (self.hw_base.add(addr as usize) as *mut u32).write_unaligned(val) }
    }
}