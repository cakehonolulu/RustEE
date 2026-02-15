use tracing::error;

use super::renderer::{GsRenderer, Vertex};

pub struct SoftwareRenderer;

impl GsRenderer for SoftwareRenderer {
    fn name(&self) -> &'static str {
        "Software"
    }

    fn draw_point(
        &mut self,
        vram: &mut [u8],
        vertex: &Vertex,
        registers: &[u64; 0x63],
        framebuffer_fbp: u32,
        framebuffer_fbw: u32,
    ) {
        let v = vertex;

        let scissor = registers[0x40];
        let scax0 = (scissor & 0x7FF) as i32;
        let scax1 = ((scissor >> 16) & 0x7FF) as i32;
        let scay0 = ((scissor >> 32) & 0x7FF) as i32;
        let scay1 = ((scissor >> 48) & 0x7FF) as i32;

        let x = (v.x.floor() as i32).clamp(scax0, scax1);
        let y = (v.y.floor() as i32).clamp(scay0, scay1);

        let zbuf = registers[0x4E];
        let z_mask = ((zbuf >> 32) & 0x1) != 0;

        let frame_base = framebuffer_fbp as usize * 2048 * 4;
        let width = framebuffer_fbw as usize * 64;

        let pixel_addr = frame_base + (y as usize * width + x as usize) * 4;
        if pixel_addr + 4 > vram.len() {
            return;
        }

        if !z_mask {
            vram[pixel_addr] = v.a;
            vram[pixel_addr + 1] = v.r;
            vram[pixel_addr + 2] = v.g;
            vram[pixel_addr + 3] = v.b;
        }
    }

    fn draw_triangle(
        &mut self,
        vram: &mut [u8],
        vertices: &[Vertex],
        registers: &[u64; 0x63],
        framebuffer_fbp: u32,
        framebuffer_fbw: u32,
    ) {
        let v0 = &vertices[0];
        let v1 = &vertices[1];
        let v2 = &vertices[2];

        let scissor = registers[0x40];
        let scax0 = (scissor & 0x7FF) as i32;
        let scax1 = ((scissor >> 16) & 0x7FF) as i32;
        let scay0 = ((scissor >> 32) & 0x7FF) as i32;
        let scay1 = ((scissor >> 48) & 0x7FF) as i32;

        let min_x = [v0.x, v1.x, v2.x]
            .iter()
            .fold(f32::INFINITY, |m, &v| m.min(v))
            .floor() as i32;
        let max_x = [v0.x, v1.x, v2.x]
            .iter()
            .fold(f32::NEG_INFINITY, |m, &v| m.max(v))
            .ceil() as i32;
        let min_y = [v0.y, v1.y, v2.y]
            .iter()
            .fold(f32::INFINITY, |m, &v| m.min(v))
            .floor() as i32;
        let max_y = [v0.y, v1.y, v2.y]
            .iter()
            .fold(f32::NEG_INFINITY, |m, &v| m.max(v))
            .ceil() as i32;

        let min_x = min_x.max(scax0);
        let max_x = max_x.min(scax1);
        let min_y = min_y.max(scay0);
        let max_y = max_y.min(scay1);

        let edge = |a: &Vertex, b: &Vertex, px: f32, py: f32| {
            (px - a.x) * (b.y - a.y) - (py - a.y) * (b.x - a.x)
        };

        let area = edge(v0, v1, v2.x, v2.y);
        if area == 0.0 {
            return;
        }

        let zbuf = registers[0x4E];
        let z_mask = ((zbuf >> 32) & 0x1) != 0;

        let frame_base = framebuffer_fbp as usize * 2048 * 4;
        let width = framebuffer_fbw as usize * 64;

        for y in min_y..=max_y {
            for x in min_x..=max_x {
                let px = x as f32 + 0.5;
                let py = y as f32 + 0.5;

                let mut w0 = edge(v1, v2, px, py);
                let mut w1 = edge(v2, v0, px, py);
                let mut w2 = edge(v0, v1, px, py);

                if area < 0.0 {
                    w0 = -w0;
                    w1 = -w1;
                    w2 = -w2;
                }

                if w0 >= 0.0 && w1 >= 0.0 && w2 >= 0.0 {
                    w0 /= area;
                    w1 /= area;
                    w2 /= area;

                    let _z_value =
                        (w0 * v0.z as f32 + w1 * v1.z as f32 + w2 * v2.z as f32) as u32;

                    let pixel_addr = frame_base + (y as usize * width + x as usize) * 4;
                    if pixel_addr + 4 > vram.len() {
                        continue;
                    }

                    if !z_mask {
                        vram[pixel_addr]     = v2.r;
                        vram[pixel_addr + 1] = v2.g;
                        vram[pixel_addr + 2] = v2.b;
                        vram[pixel_addr + 3] = v2.a;
                    }
                }
            }
        }
    }

    fn draw_sprite(
        &mut self,
        vram: &mut [u8],
        vertices: &[Vertex],
        registers: &[u64; 0x63],
        framebuffer_fbp: u32,
        framebuffer_fbw: u32,
    ) {
        let v0 = &vertices[0];
        let v1 = &vertices[1];

        let scissor = registers[0x40];
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

        let zbuf   = registers[0x4E];
        let z_mask = ((zbuf >> 32) & 0x1) != 0;

        let frame_base = framebuffer_fbp as usize * 2048 * 4;
        let width = framebuffer_fbw as usize * 64;

        for y in min_y..=max_y {
            for x in min_x..=max_x {
                let pixel_addr = frame_base + (y as usize * width + x as usize) * 4;
                if pixel_addr + 4 > vram.len() {
                    continue;
                }

                if !z_mask {
                    vram[pixel_addr] = v1.r;
                    vram[pixel_addr + 1] = v1.g;
                    vram[pixel_addr + 2] = v1.b;
                    vram[pixel_addr + 3] = v1.a;
                }
            }
        }
    }

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
    ) {
        let vram_bytes = vram.len();
        let vram_pixels = vram_bytes / 4;

        for y in 0..height_pixels as usize {
            let src_pixels = (src_base_pixels as usize)
                .saturating_add(src_rect_x as usize)
                .saturating_add(
                    (src_rect_y as usize).saturating_mul(src_buffer_width_pixels as usize),
                )
                .saturating_add(y.saturating_mul(src_buffer_width_pixels as usize));

            let dst_pixels = (dst_base_pixels as usize)
                .saturating_add(dst_rect_x as usize)
                .saturating_add(
                    (dst_rect_y as usize).saturating_mul(dst_buffer_width_pixels as usize),
                )
                .saturating_add(y.saturating_mul(dst_buffer_width_pixels as usize));

            if src_pixels
                .checked_add(width_pixels as usize)
                .map_or(false, |v| v <= vram_pixels)
                && dst_pixels
                    .checked_add(width_pixels as usize)
                    .map_or(false, |v| v <= vram_pixels)
            {
                let src_b = src_pixels * 4;
                let dst_b = dst_pixels * 4;
                let len_b = width_pixels as usize * 4;

                if src_b + len_b <= vram_bytes && dst_b + len_b <= vram_bytes {
                    vram.copy_within(src_b..src_b + len_b, dst_b);
                } else {
                    error!("SoftwareRenderer: VRAM blit out of bounds (byte range)");
                    panic!("VRAM blit out of bounds");
                }
            } else {
                error!("SoftwareRenderer: VRAM blit out of bounds (pixel range)");
                panic!("VRAM blit out of bounds");
            }
        }
    }

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
    ) {
        let pixel_offset =
            (rect_y + *dest_y) * buffer_width_pixels + (rect_x + *dest_x);
        let byte_addr = (base_addr_pixels * 4 + pixel_offset * 4) as usize;

        let data_bytes = hwreg_data.to_le_bytes();

        if byte_addr + 8 <= vram.len() {
            vram[byte_addr..byte_addr + 8].copy_from_slice(&data_bytes);
        }

        *dest_x += 2;

        if *dest_x >= area_width {
            *dest_x = 0;
            *dest_y += 1;
        }
    }
}
