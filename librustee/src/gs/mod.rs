use tracing::{error, trace};
use crate::Bus;

/// Base address for privileged GS registers
pub const GS_BASE: u32 = 0x1200_0000;

const VRAM_SIZE: usize = 4 * 1024 * 1024;

/// GS register offsets (size = 8 bytes each)
const PMODE_OFFSET: u32 = GS_BASE + 0x000; // PMODE
const SMODE1_OFFSET: u32 = GS_BASE + 0x010; // SMODE1
const SMODE2_OFFSET: u32 = GS_BASE + 0x020; // SMODE2
const SRFSH_OFFSET: u32 = GS_BASE + 0x030; // SRFSH
const SYNCH1_OFFSET: u32 = GS_BASE + 0x040; // SYNCH1
const SYNCH2_OFFSET: u32 = GS_BASE + 0x050; // SYNCH2
const SYNCV_OFFSET: u32 = GS_BASE + 0x060; // SYNCV
const DISPFB1_OFFSET: u32 = GS_BASE + 0x070; // DISPFB1
const DISPLAY1_OFFSET: u32 = GS_BASE + 0x080; // DISPLAY1
const DISPFB2_OFFSET: u32 = GS_BASE + 0x090; // DISPFB2
const DISPLAY2_OFFSET: u32 = GS_BASE + 0x0A0; // DISPLAY2
const EXTBUF_OFFSET: u32 = GS_BASE + 0x0B0; // EXTBUF
const EXTDATA_OFFSET: u32 = GS_BASE + 0x0C0; // EXTDATA
const EXTWRITE_OFFSET: u32 = GS_BASE + 0x0D0; // EXTWRITE
const BGCOLOR_OFFSET: u32 = GS_BASE + 0x0E0; // BGCOLOR

const GS_CSR_OFFSET: u32 = GS_BASE + 0x1000; // GS_CSR
const GS_IMR_OFFSET: u32 = GS_BASE + 0x1010; // GS_IMR
const BUSDIR_OFFSET: u32 = GS_BASE + 0x1040; // BUSDIR
const SIGLBLID_OFFSET: u32 = GS_BASE + 0x1080; // SIGLBLID

#[derive(Debug, Clone, Copy)]
struct Vertex {
    x: f32,
    y: f32,
    z: u32,
    r: u8,
    g: u8,
    b: u8,
    a: u8,
}

impl Default for Vertex {
    fn default() -> Self {
        Vertex {
            x: 0.0,
            y: 0.0,
            z: 0,
            r: 0,
            g: 0,
            b: 0,
            a: 0,
        }
    }
}


#[derive(Debug)]
pub enum GsEvent {
    None,
    GsCsrVblankOut { delay: u64 },
}

/// Privileged GS register block
#[derive(Debug)]
pub struct GS {
    pub pmode: u64,
    pub smode1: u64,
    pub smode2: u64,
    pub srfsh: u64,
    pub synch1: u64,
    pub synch2: u64,
    pub syncv: u64,
    pub dispfb1: u64,
    pub display1: u64,
    pub dispfb2: u64,
    pub display2: u64,
    pub extbuf: u64,
    pub extdata: u64,
    pub extwrite: u64,
    pub bgcolor: u64,
    pub gs_csr: u64,
    pub gs_imr: u64,
    pub busdir: u64,
    pub siglblid: u64,
    pub registers: [u64; 0x63],
    pub hwreg: u64,
    pub vram: Vec<u8>,

    // Transfer registers state
    bitbltbuf: u64,
    trxpos: u64,
    trxreg: u64,
    trxdir: u64,

    source_base_pointer: u64,
    source_buffer_width: u64,
    source_format: u64,
    destination_base_pointer: u64,
    destination_buffer_width: u64,
    destination_format: u64,

    source_rectangle_x: u64,
    source_rectangle_y: u64,
    destination_rectangle_x: u64,
    destination_rectangle_y: u64,
    transmission_order: u64,

    transmission_area_pixel_width: u64,
    transmission_area_pixel_height: u64,

    transmission_direction: u64,

    // Transfer progress counters
    source_x: u64,
    source_y: u64,
    destination_x: u64,
    destination_y: u64,

    // Framebuffer info
    framebuffer_fbp: u32,
    framebuffer_fbw: u32,
    framebuffer_psm: u32,

    // Primitive handling
    current_prim: u64,
    vertex_queue: Vec<Vertex>,
}

impl Default for GS {
    fn default() -> Self {
        GS {
            pmode: 0,
            smode1: 0,
            smode2: 0,
            srfsh: 0,
            synch1: 0,
            synch2: 0,
            syncv: 0,
            dispfb1: 0,
            display1: 0,
            dispfb2: 0,
            display2: 0,
            extbuf: 0,
            extdata: 0,
            extwrite: 0,
            bgcolor: 0,
            gs_csr: 0,
            gs_imr: 0,
            busdir: 0,
            siglblid: 0,
            registers: [0; 0x63],
            hwreg: 0,
            vram: vec![0; 4 * 1024 * 1024],
            bitbltbuf: 0,
            trxpos: 0,
            trxreg: 0,
            trxdir: 0,
            source_base_pointer: 0,
            source_buffer_width: 0,
            source_format: 0,
            destination_base_pointer: 0,
            destination_buffer_width: 0,
            destination_format: 0,
            source_rectangle_x: 0,
            source_rectangle_y: 0,
            destination_rectangle_x: 0,
            destination_rectangle_y: 0,
            transmission_order: 0,
            transmission_area_pixel_width: 0,
            transmission_area_pixel_height: 0,
            transmission_direction: 0,
            source_x: 0,
            source_y: 0,
            destination_x: 0,
            destination_y: 0,
            framebuffer_fbp: 0,
            framebuffer_fbw: 0,
            framebuffer_psm: 0,
            current_prim: 0,
            vertex_queue: Vec::with_capacity(3),
        }
    }
}

impl GS {
    /// Create a new privileged GS register block
    pub fn new() -> Self {
        GS {
            registers: [0u64; 0x63],
            hwreg: 0,
            vram: vec![0; 4 * 1024 * 1024], // 4MB VRAM
            ..Default::default()
        }
    }

    pub fn get_framebuffer_data(&self) -> (Option<Vec<u8>>, u32, u32) {
        let fbp = self.framebuffer_fbp;
        let fbw = self.framebuffer_fbw;
        let psm = self.framebuffer_psm;

        let width = 640;
        let height = 480;

        if psm != 0 {
            return (None, width, height);
        }

        let base_addr_bytes = (fbp * 2048 * 4) as usize;
        let buffer_width_pixels = fbw * 64;

        let mut frame = vec![0u8; (width * height * 4) as usize];

        for y in 0..height {
            for x in 0..width {
                let src_addr = base_addr_bytes + ((y as usize * buffer_width_pixels as usize) + x as usize) * 4;
                let dst_addr = (y as usize * width as usize + x as usize) * 4;

                if src_addr + 4 <= self.vram.len() && dst_addr + 4 <= frame.len() {
                    frame[dst_addr..dst_addr + 4].copy_from_slice(&self.vram[src_addr..src_addr + 4]);
                }
            }
        }

        (Some(frame), width, height)
    }


    /// Write a 64-bit value to a GS register
    pub fn write64(&mut self, offset: u32, value: u64) -> GsEvent {
        let mut event: GsEvent = GsEvent::None;
        match offset {
            PMODE_OFFSET => self.pmode = value,
            SMODE1_OFFSET => self.smode1 = value,
            SMODE2_OFFSET => self.smode2 = value,
            SRFSH_OFFSET => self.srfsh = value,
            SYNCH1_OFFSET => self.synch1 = value,
            SYNCH2_OFFSET => self.synch2 = value,
            SYNCV_OFFSET => self.syncv = value,
            DISPFB1_OFFSET => self.dispfb1 = value,
            DISPLAY1_OFFSET => self.display1 = value,
            DISPFB2_OFFSET => self.dispfb2 = value,
            DISPLAY2_OFFSET => self.display2 = value,
            EXTBUF_OFFSET => self.extbuf = value,
            EXTDATA_OFFSET => self.extdata = value,
            EXTWRITE_OFFSET => self.extwrite = value,
            BGCOLOR_OFFSET => self.bgcolor = value,
            GS_CSR_OFFSET => {
                self.gs_csr = value;
                event = GsEvent::GsCsrVblankOut { delay: 64000 };
            }
            GS_IMR_OFFSET => self.gs_imr = value,
            BUSDIR_OFFSET => self.busdir = value,
            SIGLBLID_OFFSET => self.siglblid = value,
            _ => {
                panic!("Invalid GS write offset: {:#X}", offset);
            }
        }
        event
    }

    /// Read a 64-bit value from a GS register
    pub fn read64(&self, offset: u32) -> u64 {
        match offset {
            PMODE_OFFSET => self.pmode,
            SMODE1_OFFSET => self.smode1,
            SMODE2_OFFSET => self.smode2,
            SRFSH_OFFSET => self.srfsh,
            SYNCH1_OFFSET => self.synch1,
            SYNCH2_OFFSET => self.synch2,
            SYNCV_OFFSET => self.syncv,
            DISPFB1_OFFSET => self.dispfb1,
            DISPLAY1_OFFSET => self.display1,
            DISPFB2_OFFSET => self.dispfb2,
            DISPLAY2_OFFSET => self.display2,
            EXTBUF_OFFSET => self.extbuf,
            EXTDATA_OFFSET => self.extdata,
            EXTWRITE_OFFSET => self.extwrite,
            BGCOLOR_OFFSET => self.bgcolor,
            GS_CSR_OFFSET => self.gs_csr,
            GS_IMR_OFFSET => self.gs_imr,
            BUSDIR_OFFSET => self.busdir,
            SIGLBLID_OFFSET => self.siglblid,
            _ => {
                error!("Invalid GS read offset: {:#X}", offset);
                0
            }
        }
    }

    pub fn write_internal_reg(&mut self, reg: u64, data: u64) {
        match reg {
            0x00 => { // PRIM
                self.registers[0x00] = data;
                self.handle_prim_selection(data);
            }
            0x01 => { // RGBAQ
                let r = data & 0xFF;
                let g = (data >> 8) & 0xFF;
                let b = (data >> 16) & 0xFF;
                let a = (data >> 24) & 0xFF;
                let q = data >> 32;
                let v = b | (g << 8) | (r << 16) | (a << 24) | (q << 32);
                self.registers[0x01] = v;
            }
            0x02 => { // ST
                self.registers[0x02] = data;
            }
            0x03 => { // UV
                self.registers[0x03] = data;
            }
            0x04 => { // XYZF2
                let x = data & 0xFFFF;
                let y = (data >> 16) & 0xffff;
                let z = data >> 32;
                let v = x | (y << 16) | (z << 32);
                self.registers[0x04] = v;
                self.add_vertex(v, true);
            }
            0x05 => { // XYZ2
                let x = data & 0xFFFF;
                let y = (data >> 16) & 0xffff;
                let z = data >> 32;
                let v = x | (y << 16) | (z << 32);
                self.registers[0x05] = data;
                self.add_vertex(v, true);
            }
            0x06 => { // TEX0_1
                self.registers[0x06] = data;
            }
            0x07 => { // TEX0_2
                self.registers[0x07] = data;
            }
            0x08 => { // CLAMP_1
                self.registers[0x08] = data;
            }
            0x09 => { // CLAMP_2
                self.registers[0x09] = data;
            }
            0x0A => { // FOG
                self.registers[0x0A] = data;
            }
            0x0C => { // XYZF3
                let x = data & 0xffff;
                let y = (data >> 16) & 0xffff;
                let z = data >> 32;
                let v = x | (y << 16) | (z << 32);
                self.registers[0x0C] = v;
                self.add_vertex(v, false);
            }
            0x0D => { // XYZ3
                let x = data & 0xffff;
                let y = (data >> 16) & 0xffff;
                let z = data >> 32;
                let v = x | (y << 16) | (z << 32);
                self.registers[0x0D] = v;
                self.add_vertex(v, false);
            }
            0x14 => { // TEX1_1
                self.registers[0x14] = data;
            }
            0x15 => { // TEX1_2
                self.registers[0x15] = data;
            }
            0x16 => { // TEX2_1
                self.registers[0x16] = data;
            }
            0x17 => { // TEX2_2
                self.registers[0x17] = data;
            }
            0x18 => { // XYOFFSET_1
                self.registers[0x18] = data;
            }
            0x19 => { // XYOFFSET_2
                self.registers[0x19] = data;
            }
            0x1A => { // PRMODECONT
                self.registers[0x1A] = data;
            }
            0x1B => { // PRMODE
                self.registers[0x1B] = data;
            }
            0x1C => { // TEXCLUT
                self.registers[0x1C] = data;
            }
            0x22 => { // SCANMSK
                self.registers[0x22] = data;
            }
            0x34 => { // MIPTBP1_1
                self.registers[0x34] = data;
            }
            0x35 => { // MIPTBP1_2
                self.registers[0x35] = data;
            }
            0x36 => { // MIPTBP2_1
                self.registers[0x36] = data;
            }
            0x37 => { // MIPTBP2_2
                self.registers[0x37] = data;
            }
            0x3B => { // TEXA
                self.registers[0x3B] = data;
            }
            0x3D => { // FOGCOL
                self.registers[0x3D] = data;
            }
            0x3F => { // TEXFLUSH
                self.registers[0x3F] = data;
            }
            0x40 => { // SCISSOR_1
                self.registers[0x40] = data;
            }
            0x41 => { // SCISSOR_2
                self.registers[0x41] = data;
            }
            0x42 => { // ALPHA_1
                self.registers[0x42] = data;
            }
            0x43 => { // ALPHA_2
                self.registers[0x43] = data;
            }
            0x44 => { // DIMX
                self.registers[0x44] = data;
            }
            0x45 => { // DTHE
                self.registers[0x45] = data;
            }
            0x46 => { // COLCLAMP
                self.registers[0x46] = data;
            }
            0x47 => { // TEST_1
                self.registers[0x47] = data;
            }
            0x48 => { // TEST_2
                self.registers[0x48] = data;
            }
            0x49 => { // PABE
                self.registers[0x49] = data;
            }
            0x4A => { // FBA_1
                self.registers[0x4A] = data;
            }
            0x4B => { // FBA_2
                self.registers[0x4B] = data;
            }
            0x4C => { // FRAME_1
                self.registers[0x4C] = data;
                self.update_framebuffer_info(data);
            }
            0x4D => { // FRAME_2
                self.registers[0x4D] = data;
                self.update_framebuffer_info(data);
            }
            0x4E => { // ZBUF_1
                self.registers[0x4E] = data;
            }
            0x4F => { // ZBUF_2
                self.registers[0x4F] = data;
            }
            0x50 => { // BITBLTBUF
                self.set_bitbltbuf(data);
            }
            0x51 => { // TRXPOS
                self.set_trxpos(data);
            }
            0x52 => { // TRXREG
                self.set_trxreg(data);
            }
            0x53 => { // TRXDIR
                self.set_trxdir(data);
            }
            0x54 => { // HWREG
                self.write_hwreg(data);
            }
            0x60 => { // SIGNAL
                self.registers[0x60] = data;
            }
            0x61 => { // FINISH
                self.registers[0x61] = data;
            }
            0x62 => { // LABEL
                self.registers[0x62] = data;
            }
            _ => {
                panic!("GS: write_internal_reg invalid reg 0x{:02X} = 0x{:016X}", reg, data);
            }
        }
    }

    /// Handle a 128-bit PACKED GIF quadword delivered by DMA.
    pub fn write_packed_gif_data(&mut self, reg: u8, data: u128, mut q: u32) {
        let low = data as u64;
        let high = (data >> 64) as u64;

        match reg {
            0x00 => { // PRIM
                let prim_value = low & 0x3FF;
                self.registers[0x00] = prim_value;
                self.handle_prim_selection(prim_value);
            }
            0x01 => { // RGBAQ
                let r = low & 0xFF;
                let g = (low >> 32) & 0xFF;
                let b = high & 0xFF;
                let a = (high >> 32) & 0xFF;
                let v = (a << 24) | (r << 16) | (g << 8) | b;
                self.registers[0x01] = v;
            }
            0x02 => { // ST
                q = high as u32;
                self.registers[0x02] = low;
            }
            0x03 => { // UV
                self.registers[0x03] = (low & 0x3fff) | (low >> 16);
            }
            0x04 => { // XYZ2F/XYZ3F
                let x = low & 0xffff;
                let y = (low >> 32) & 0xffff;
                let z = high >> 32;
                let v = x | (y << 16) | (z << 32);
                let disable_drawing = (high & 0x800000000000) != 0;
                let idx;
                if disable_drawing {
                    idx = 0x0C;
                } else {
                    idx = 0x04;
                }
                self.add_vertex(v, !disable_drawing);
                self.registers[idx as usize] = v;
            }
            0x05 => { // XYZ2/XYZ3
                let x = low & 0xffff;
                let y = (low >> 32) & 0xffff;
                let z = high >> 32;
                let v = x | (y << 16) | (z << 32);
                let disable_drawing = (high & 0x800000000000) != 0;
                let idx;
                if disable_drawing {
                    idx = 0x0D;
                } else {
                    idx = 0x05;
                }
                self.add_vertex(v, !disable_drawing);
                self.registers[idx as usize] = v;
            }
            0x08 => {}
            0x09 => {}
            0x0A => { // FOG
                self.registers[0xA] = high << 20;
            }
            0x0C => { // FOG
                self.registers[0xC] = low;
            }
            0x0E => { // A+D
                let dst_reg = high;
                self.write_internal_reg(dst_reg, low);
            }
            0x0D => {}
            0x0F => {}
            _ => {
                panic!("GS: write_packed_gif_data invalid reg 0x{:02X}", reg);
            }
        }
    }

    pub fn write_hwreg(&mut self, data: u64) {
        self.hwreg = data;
        self.transfer_vram();
    }

    fn transfer_vram(&mut self) {
        if self.transmission_direction == 0 { // Host to Local
            let base_addr_words = self.destination_base_pointer;
            let rect_x = self.destination_rectangle_x;
            let rect_y = self.destination_rectangle_y;
            let buffer_width_pixels = self.destination_buffer_width;

            let pixel_offset = (rect_y + self.destination_y) * buffer_width_pixels + (rect_x + self.destination_x);
            let byte_addr = (base_addr_words * 4 + pixel_offset * 4) as usize;

            let data_bytes = self.hwreg.to_le_bytes();

            if byte_addr + 8 <= self.vram.len() {
                self.vram[byte_addr..byte_addr + 8].copy_from_slice(&data_bytes);
            }

            self.destination_x += 2;

            if self.destination_x >= self.transmission_area_pixel_width {
                self.destination_x = 0;
                self.destination_y += 1;
            }
        }
    }

    fn handle_prim_selection(&mut self, data: u64) {
        self.current_prim = data & 0x7;
        self.vertex_queue.clear();
    }

    fn add_vertex(&mut self, data: u64, kick: bool) {
        let x_fixed = ((data >> 0) & 0xFFFF) as i16;
        let y_fixed = ((data >> 16) & 0xFFFF) as i16;

        let xoffset_1 = (self.registers[0x18] & 0xFFFF) as i16;
        let yoffset_1 = ((self.registers[0x18] >> 32) & 0xFFFF) as i16;

        let x_fixed = x_fixed - xoffset_1;
        let y_fixed = y_fixed - yoffset_1;

        let z = ((data >> 48) & 0xFFFFFF) as i32;

        let x = x_fixed as f32 / 16.0;
        let y = y_fixed as f32 / 16.0;

        let rgbaq = self.registers[0x01];
        let b = ((rgbaq >> 0) & 0xFF) as u8;
        let g = ((rgbaq >> 8) & 0xFF) as u8;
        let r = ((rgbaq >> 16) & 0xFF) as u8;
        let a = ((rgbaq >> 24) & 0xFF) as u8;

        let vertex = Vertex { x: x as f32, y: y as f32, z: 0, r, g, b, a };
        self.vertex_queue.push(vertex);

        if kick {
            match self.current_prim {
                0 => { // Point
                    if self.vertex_queue.len() >= 1 {
                        self.draw_point();
                        self.vertex_queue.clear();
                    }
                }
                3 => { // Triangle
                    if self.vertex_queue.len() >= 3 {
                        self.draw_triangle();
                        self.vertex_queue.clear();
                    }
                }
                6 => { // Sprite
                    if self.vertex_queue.len() >= 2 {
                        self.draw_sprite();
                        self.vertex_queue.clear();
                    }
                }
                _ => {}
            }
        }
    }

    fn update_framebuffer_info(&mut self, data: u64) {
        self.framebuffer_fbp = (data & 0x1FF) as u32;
        self.framebuffer_fbw = ((data >> 16) & 0x3F) as u32;
        self.framebuffer_psm = ((data >> 24) & 0x3F) as u32;
    }

    fn set_bitbltbuf(&mut self, data: u64) {
        self.bitbltbuf = data;

        self.source_base_pointer = (data >> 0) & 0x3fff;
        self.source_buffer_width = (data >> 16) & 0x3f;
        self.source_format = (data >> 24) & 0x3f;

        self.destination_base_pointer = (data >> 32) & 0x3fff;
        self.destination_buffer_width = (data >> 48) & 0x3f;
        self.destination_format = (data >> 56) & 0x3f;

        self.destination_base_pointer <<= 6;
        self.destination_buffer_width <<= 6;
    }

    fn set_trxpos(&mut self, data: u64) {
        self.trxpos = data;

        self.source_rectangle_x = (data >> 0) & 0x7ff;
        self.source_rectangle_y = (data >> 16) & 0x7ff;
        self.destination_rectangle_x = (data >> 32) & 0x7ff;
        self.destination_rectangle_y = (data >> 48) & 0x7ff;
        self.transmission_order = (data >> 59) & 3;
    }

    fn set_trxreg(&mut self, data: u64) {
        self.trxreg = data;

        self.transmission_area_pixel_width = data & 0xfff;
        self.transmission_area_pixel_height = (data >> 32) & 0xfff;
    }

    fn set_trxdir(&mut self, value: u64) {
        self.trxdir = value;

        self.transmission_direction = (self.trxdir & 3) as u32 as u64;
        self.source_x = 0;
        self.source_y = 0;
        self.destination_x = 0;
        self.destination_y = 0;

        if self.transmission_direction == 2 {
            //self.blit_vram();
        }
    }

    fn blit_vram(&mut self) {
        for y in 0..self.transmission_area_pixel_height {
            let src = (self.source_base_pointer + self.source_rectangle_x
                + (self.source_rectangle_y * self.source_buffer_width)
                + (y * self.source_buffer_width)) as usize;

            let dst = (self.destination_base_pointer + self.destination_rectangle_x
                + (self.destination_rectangle_y * self.destination_buffer_width)
                + (y * self.destination_buffer_width)) as usize;

            let copy_size = self.transmission_area_pixel_width as usize;

            if src + copy_size <= VRAM_SIZE && dst + copy_size <= VRAM_SIZE {
                if src < dst && src + copy_size > dst {
                    for i in (0..copy_size).rev() {
                        self.vram[dst + i] = self.vram[src + i];
                    }
                } else if dst < src && dst + copy_size > src {
                    for i in 0..copy_size {
                        self.vram[dst + i] = self.vram[src + i];
                    }
                } else {
                    if src < dst {
                        let (left, right) = self.vram.split_at_mut(dst);
                        right[..copy_size].copy_from_slice(&left[src..src + copy_size]);
                    } else {
                        let (left, right) = self.vram.split_at_mut(src);
                        left[dst..dst + copy_size].copy_from_slice(&right[..copy_size]);
                    }
                }
            } else {
                eprintln!("VRAM blit out of bounds");
                panic!("VRAM blit out of bounds - src: {}, dst: {}, copy_size: {}, VRAM_SIZE: {}",
                       src, dst, copy_size, VRAM_SIZE);
            }
        }
    }

    fn draw_point(&mut self) {
        let v = self.vertex_queue[0];
        let scissor = self.registers[0x40];
        let scax0 = (scissor & 0x7FF) as i32;
        let scax1 = ((scissor >> 16) & 0x7FF) as i32;
        let scay0 = ((scissor >> 32) & 0x7FF) as i32;
        let scay1 = ((scissor >> 48) & 0x7FF) as i32;

        let x = (v.x.floor() as i32).clamp(scax0, scax1);
        let y = (v.y.floor() as i32).clamp(scay0, scay1);

        let zbuf = self.registers[0x4E];
        let zbp = (zbuf & 0x1FF) as usize;
        let z_base = zbp * 2048 * 4;
        let z_format = ((zbuf >> 24) & 0xF) as u32;
        let z_mask = ((zbuf >> 32) & 0x1) != 0;

        let z_value = v.z;

        let frame_base = (self.framebuffer_fbp as usize * 2048 * 4);
        let width = self.framebuffer_fbw as usize * 64;

        let pixel_addr = frame_base + (y as usize * width + x as usize) * 4;
        if pixel_addr + 4 > self.vram.len() {
            return;
        }

        let mut write_pixel = !z_mask;

        let mut old_z: u32 = 0;
        let z_addr: usize;

        if !z_mask {
            match z_format {
                0 | 1 => { // PSMZ32 or PSMZ24
                    z_addr = z_base + (y as usize * width + x as usize) * 4;
                    if z_addr + 4 > self.vram.len() {
                        return;
                    }
                    old_z = u32::from_le_bytes(self.vram[z_addr..z_addr + 4].try_into().unwrap());
                    if z_format == 1 {
                        old_z &= 0x00FFFFFF;
                    }
                    write_pixel = z_value >= old_z;
                }
                2 | 0xA => { // PSMZ16 or PSMZ16S
                    z_addr = z_base + (y as usize * width + x as usize) * 2;
                    if z_addr + 2 > self.vram.len() {
                        return;
                    }
                    old_z = u16::from_le_bytes(self.vram[z_addr..z_addr + 2].try_into().unwrap()) as u32;
                    write_pixel = z_value >= old_z;
                }
                _ => return,
            }
        } else {
            write_pixel = true;
            z_addr = 0;
        }

        if write_pixel {
            if !z_mask {
                match z_format {
                    0 | 1 => {
                        let mut z_to_write = z_value;
                        if z_format == 1 {
                            z_to_write &= 0x00FFFFFF;
                        }
                        self.vram[z_addr..z_addr + 4].copy_from_slice(&z_to_write.to_le_bytes());
                    }
                    2 | 0xA => {
                        self.vram[z_addr..z_addr + 2].copy_from_slice(&(z_value as u16).to_le_bytes());
                    }
                    _ => {},
                }
            }

            self.vram[pixel_addr] = v.a;
            self.vram[pixel_addr + 1] = v.r;
            self.vram[pixel_addr + 2] = v.g;
            self.vram[pixel_addr + 3] = v.b;
        }
    }

    fn draw_triangle(&mut self) {
        let v0 = self.vertex_queue[0];
        let v1 = self.vertex_queue[1];
        let v2 = self.vertex_queue[2];

        let scissor = self.registers[0x40];
        let scax0 = (scissor & 0x7FF) as i32;
        let scax1 = ((scissor >> 16) & 0x7FF) as i32;
        let scay0 = ((scissor >> 32) & 0x7FF) as i32;
        let scay1 = ((scissor >> 48) & 0x7FF) as i32;

        let min_x = [v0.x, v1.x, v2.x].iter().fold(f32::INFINITY, |m, &v| m.min(v)).floor() as i32;
        let max_x = [v0.x, v1.x, v2.x].iter().fold(f32::NEG_INFINITY, |m, &v| m.max(v)).ceil() as i32;
        let min_y = [v0.y, v1.y, v2.y].iter().fold(f32::INFINITY, |m, &v| m.min(v)).floor() as i32;
        let max_y = [v0.y, v1.y, v2.y].iter().fold(f32::NEG_INFINITY, |m, &v| m.max(v)).ceil() as i32;

        let min_x = min_x.max(scax0);
        let max_x = max_x.min(scax1);
        let min_y = min_y.max(scay0);
        let max_y = max_y.min(scay1);

        let edge = |a: &Vertex, b: &Vertex, px: f32, py: f32| {
            (px - a.x) * (b.y - a.y) - (py - a.y) * (b.x - a.x)
        };

        let mut area = edge(&v0, &v1, v2.x, v2.y);
        if area == 0.0 {
            return;
        }

        let zbuf = self.registers[0x4E];
        let zbp = (zbuf & 0x1FF) as usize;
        let z_base = zbp * 2048 * 4;
        let z_format = ((zbuf >> 24) & 0xF) as u32;
        let z_mask = ((zbuf >> 32) & 0x1) != 0;

        let frame_base = (self.framebuffer_fbp as usize * 2048 * 4);
        let width = self.framebuffer_fbw as usize * 64;

        for y in min_y..=max_y {
            for x in min_x..=max_x {
                let px = x as f32 + 0.5;
                let py = y as f32 + 0.5;

                let mut w0 = edge(&v1, &v2, px, py);
                let mut w1 = edge(&v2, &v0, px, py);
                let mut w2 = edge(&v0, &v1, px, py);

                if area < 0.0 {
                    w0 = -w0;
                    w1 = -w1;
                    w2 = -w2;
                }

                if w0 >= 0.0 && w1 >= 0.0 && w2 >= 0.0 {
                    w0 /= area;
                    w1 /= area;
                    w2 /= area;

                    let zf = w0 * v0.z as f32 + w1 * v1.z as f32 + w2 * v2.z as f32;
                    let z_value = zf as u32;

                    let pixel_addr = frame_base + (y as usize * width + x as usize) * 4;
                    if pixel_addr + 4 > self.vram.len() {
                        continue;
                    }

                    let mut write_pixel = !z_mask;

                    let mut old_z: u32 = 0;
                    let z_addr: usize;

                    if !z_mask {
                        match z_format {
                            0 | 1 => {
                                z_addr = z_base + (y as usize * width + x as usize) * 4;
                                if z_addr + 4 > self.vram.len() {
                                    continue;
                                }
                                old_z = u32::from_le_bytes(self.vram[z_addr..z_addr + 4].try_into().unwrap());
                                if z_format == 1 {
                                    old_z &= 0x00FFFFFF;
                                }
                                write_pixel = z_value >= old_z;
                            }
                            2 | 0xA => {
                                z_addr = z_base + (y as usize * width + x as usize) * 2;
                                if z_addr + 2 > self.vram.len() {
                                    continue;
                                }
                                old_z = u16::from_le_bytes(self.vram[z_addr..z_addr + 2].try_into().unwrap()) as u32;
                                write_pixel = z_value >= old_z;
                            }
                            _ => continue,
                        }
                    } else {
                        z_addr = 0;
                        write_pixel = true;
                    }

                    if write_pixel {
                        if !z_mask {
                            match z_format {
                                0 | 1 => {
                                    let mut z_to_write = z_value;
                                    if z_format == 1 {
                                        z_to_write &= 0x00FFFFFF;
                                    }
                                    self.vram[z_addr..z_addr + 4].copy_from_slice(&z_to_write.to_le_bytes());
                                }
                                2 | 0xA => {
                                    self.vram[z_addr..z_addr + 2].copy_from_slice(&(z_value as u16).to_le_bytes());
                                }
                                _ => {},
                            }
                        }

                        self.vram[pixel_addr] = v2.r;
                        self.vram[pixel_addr + 1] = v2.g;
                        self.vram[pixel_addr + 2] = v2.b;
                        self.vram[pixel_addr + 3] = v2.a;
                    }
                }
            }
        }
    }

    fn draw_sprite(&mut self) {
        let v0 = self.vertex_queue[0];
        let v1 = self.vertex_queue[1];

        let scissor = self.registers[0x40];
        let scax0 = (scissor & 0x7FF) as i32;
        let scax1 = ((scissor >> 16) & 0x7FF) as i32;
        let scay0 = ((scissor >> 32) & 0x7FF) as i32;
        let scay1 = ((scissor >> 48) & 0x7FF) as i32;

        let min_x = v0.x.min(v1.x).floor() as i32;
        let max_x = v0.x.max(v1.x).ceil() as i32;
        let min_y = v0.y.min(v1.y).floor() as i32;
        let max_y = v0.y.max(v1.y).ceil() as i32;

        let min_x = min_x.max(scax0);
        let max_x = max_x.min(scax1);
        let min_y = min_y.max(scay0);
        let max_y = max_y.min(scay1);

        let zbuf = self.registers[0x4E];
        let zbp = (zbuf & 0x1FF) as usize;
        let z_base = zbp * 2048 * 4;
        let z_format = ((zbuf >> 24) & 0xF) as u32;
        let z_mask = ((zbuf >> 32) & 0x1) != 0;

        let z_value = v1.z;

        let frame_base = (self.framebuffer_fbp as usize * 2048 * 4);
        let width = self.framebuffer_fbw as usize * 64;

        for y in min_y..=max_y {
            for x in min_x..=max_x {
                let pixel_addr = frame_base + (y as usize * width + x as usize) * 4;
                if pixel_addr + 4 > self.vram.len() {
                    continue;
                }

                let mut write_pixel = !z_mask;

                let mut old_z: u32 = 0;
                let z_addr: usize;

                if !z_mask {
                    match z_format {
                        0 | 1 => {
                            z_addr = z_base + (y as usize * width + x as usize) * 4;
                            if z_addr + 4 > self.vram.len() {
                                continue;
                            }
                            old_z = u32::from_le_bytes(self.vram[z_addr..z_addr + 4].try_into().unwrap());
                            if z_format == 1 {
                                old_z &= 0x00FFFFFF;
                            }
                            write_pixel = z_value >= old_z;
                        }
                        2 | 0xA => {
                            z_addr = z_base + (y as usize * width + x as usize) * 2;
                            if z_addr + 2 > self.vram.len() {
                                continue;
                            }
                            old_z = u16::from_le_bytes(self.vram[z_addr..z_addr + 2].try_into().unwrap()) as u32;
                            write_pixel = z_value >= old_z;
                        }
                        _ => continue,
                    }
                } else {
                    z_addr = 0;
                    write_pixel = true;
                }

                if write_pixel {
                    if !z_mask {
                        match z_format {
                            0 | 1 => {
                                let mut z_to_write = z_value;
                                if z_format == 1 {
                                    z_to_write &= 0x00FFFFFF;
                                }
                                self.vram[z_addr..z_addr + 4].copy_from_slice(&z_to_write.to_le_bytes());
                            }
                            2 | 0xA => {
                                self.vram[z_addr..z_addr + 2].copy_from_slice(&(z_value as u16).to_le_bytes());
                            }
                            _ => {},
                        }
                    }

                    self.vram[pixel_addr] = v1.a;
                    self.vram[pixel_addr + 1] = v1.b;
                    self.vram[pixel_addr + 2] = v1.g;
                    self.vram[pixel_addr + 3] = v1.r;
                }
            }
        }
    }
}
