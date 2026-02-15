#[derive(Debug, Clone, Copy, Default)]
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RendererKind {
    Software,
}

impl RendererKind {
    pub fn all() -> &'static [RendererKind] {
        &[RendererKind::Software]
    }

    pub fn display_name(self) -> &'static str {
        match self {
            RendererKind::Software => "Software",
        }
    }
}
