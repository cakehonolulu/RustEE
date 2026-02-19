#[derive(Debug, Clone, Copy, Default, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct Vertex {
    pub x: f32,
    pub y: f32,
    pub z: u32,
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

pub trait GsRenderer: Send {
    fn name(&self) -> &'static str;

    fn draw_point(
        &mut self,
        vram: &mut [u8],
        vertex: &Vertex,
        registers: &[u64; 0x63],
        framebuffer_fbp: u32,
        framebuffer_fbw: u32,
    );

    fn draw_triangle(
        &mut self,
        vram: &mut [u8],
        vertices: &[Vertex],
        registers: &[u64; 0x63],
        framebuffer_fbp: u32,
        framebuffer_fbw: u32,
    );

    fn draw_sprite(
        &mut self,
        vram: &mut [u8],
        vertices: &[Vertex],
        registers: &[u64; 0x63],
        framebuffer_fbp: u32,
        framebuffer_fbw: u32,
    );

    #[allow(clippy::too_many_arguments)]
    fn blit_vram(
        &mut self,
        vram: &mut [u8],
        src_base_pixels: u64,
        src_buffer_width_pixels: u64,
        src_rect_x: u64,
        src_rect_y: u64,
        dst_base_pixels: u64,
        dst_buffer_width_pixels: u64,
        dst_rect_x: u64,
        dst_rect_y: u64,
        width_pixels: u64,
        height_pixels: u64,
    );

    #[allow(clippy::too_many_arguments)]
    fn transfer_hwreg(
        &mut self,
        vram: &mut [u8],
        hwreg_data: u64,
        base_addr_pixels: u64,
        rect_x: u64,
        rect_y: u64,
        buffer_width_pixels: u64,
        dest_x: &mut u64,
        dest_y: &mut u64,
        area_width: u64,
    );

    fn read_vram(&mut self, _vram: &mut [u8]) {}

    fn read_vram_region(&mut self, vram: &mut [u8], byte_offset: usize, byte_len: usize) {
        let _ = (byte_offset, byte_len);
        self.read_vram(vram);
    }

    fn write_vram(&mut self, _vram: &[u8]) {}

    fn submit_frame(&mut self, _readback_byte_offset: usize, _readback_byte_len: usize) {}

    fn collect_readback(
        &mut self,
        _vram: &mut [u8],
        _readback_byte_offset: usize,
        _readback_byte_len: usize,
    ) {
    }

    fn collect_to_display(
        &mut self,
        _back_buffer: &mut [u8],
        _dbx: u32,
        _buffer_width_pixels: u32,
        _read_width: u32,
        _read_height: u32,
    ) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RendererKind {
    Software,
    Compute,
}

impl RendererKind {
    pub fn all() -> &'static [RendererKind] {
        &[RendererKind::Software, RendererKind::Compute]
    }

    pub fn display_name(self) -> &'static str {
        match self {
            RendererKind::Software => "Software",
            RendererKind::Compute => "Compute (GPU)",
        }
    }
}
