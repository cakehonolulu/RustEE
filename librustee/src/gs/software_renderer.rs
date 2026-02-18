use tracing::error;

use super::renderer::{GsRenderer, Vertex};

pub struct SoftwareRenderer;

#[inline]
fn write_rgba(vram: &mut [u8], addr: usize, v: &Vertex) {
    vram[addr]     = v.r;
    vram[addr + 1] = v.g;
    vram[addr + 2] = v.b;
    vram[addr + 3] = v.a;
}

#[inline]
fn bary_lerp(w0: f32, c0: u8, w1: f32, c1: u8, w2: f32, c2: u8) -> u8 {
    (w0 * c0 as f32 + w1 * c1 as f32 + w2 * c2 as f32).round().clamp(0.0, 255.0) as u8
}

impl GsRenderer for SoftwareRenderer {
    fn name(&self) -> &'static str { "Software" }

    fn draw_point(
        &mut self,
        vram: &mut [u8],
        vertex: &Vertex,
        registers: &[u64; 0x63],
        framebuffer_fbp: u32,
        framebuffer_fbw: u32,
    ) {
        let scissor = registers[0x40];
        let scax0 = (scissor        & 0x7FF) as i32;
        let scax1 = ((scissor >> 16) & 0x7FF) as i32;
        let scay0 = ((scissor >> 32) & 0x7FF) as i32;
        let scay1 = ((scissor >> 48) & 0x7FF) as i32;

        let x = (vertex.x.floor() as i32).clamp(scax0, scax1);
        let y = (vertex.y.floor() as i32).clamp(scay0, scay1);

        let z_mask = ((registers[0x4E] >> 32) & 0x1) != 0;
        if z_mask { return; }

        let frame_base = framebuffer_fbp as usize * 2048 * 4;
        let width      = framebuffer_fbw as usize * 64;
        let pixel_addr = frame_base + (y as usize * width + x as usize) * 4;
        if pixel_addr + 4 > vram.len() { return; }

        write_rgba(vram, pixel_addr, vertex);
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
        let scax0 = (scissor        & 0x7FF) as i32;
        let scax1 = ((scissor >> 16) & 0x7FF) as i32;
        let scay0 = ((scissor >> 32) & 0x7FF) as i32;
        let scay1 = ((scissor >> 48) & 0x7FF) as i32;

        let min_x = [v0.x, v1.x, v2.x].iter().fold(f32::INFINITY,     |m, &v| m.min(v)).floor() as i32;
        let max_x = [v0.x, v1.x, v2.x].iter().fold(f32::NEG_INFINITY, |m, &v| m.max(v)).ceil()  as i32;
        let min_y = [v0.y, v1.y, v2.y].iter().fold(f32::INFINITY,     |m, &v| m.min(v)).floor() as i32;
        let max_y = [v0.y, v1.y, v2.y].iter().fold(f32::NEG_INFINITY, |m, &v| m.max(v)).ceil()  as i32;

        let min_x = min_x.max(scax0);
        let max_x = max_x.min(scax1);
        let min_y = min_y.max(scay0);
        let max_y = max_y.min(scay1);

        let edge = |ax: f32, ay: f32, bx: f32, by: f32, px: f32, py: f32| {
            (px - ax) * (by - ay) - (py - ay) * (bx - ax)
        };

        let area = edge(v0.x, v0.y, v1.x, v1.y, v2.x, v2.y);
        if area == 0.0 { return; }

        let z_mask = ((registers[0x4E] >> 32) & 0x1) != 0;
        if z_mask { return; }

        let frame_base = framebuffer_fbp as usize * 2048 * 4;
        let width      = framebuffer_fbw as usize * 64;

        for y in min_y..=max_y {
            for x in min_x..=max_x {
                let px = x as f32 + 0.5;
                let py = y as f32 + 0.5;

                let mut w0 = edge(v1.x, v1.y, v2.x, v2.y, px, py);
                let mut w1 = edge(v2.x, v2.y, v0.x, v0.y, px, py);
                let mut w2 = edge(v0.x, v0.y, v1.x, v1.y, px, py);

                if area < 0.0 { w0 = -w0; w1 = -w1; w2 = -w2; }
                if w0 < 0.0 || w1 < 0.0 || w2 < 0.0 { continue; }

                let inv = 1.0 / area.abs();
                w0 *= inv; w1 *= inv; w2 *= inv;

                let pixel_addr = frame_base + (y as usize * width + x as usize) * 4;
                if pixel_addr + 4 > vram.len() { continue; }

                let interpolated = Vertex {
                    x: 0.0, y: 0.0, z: 0,
                    r: bary_lerp(w0, v0.r, w1, v1.r, w2, v2.r),
                    g: bary_lerp(w0, v0.g, w1, v1.g, w2, v2.g),
                    b: bary_lerp(w0, v0.b, w1, v1.b, w2, v2.b),
                    a: bary_lerp(w0, v0.a, w1, v1.a, w2, v2.a),
                };
                write_rgba(vram, pixel_addr, &interpolated);
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
        let scax0 = (scissor        & 0x7FF) as i32;
        let scax1 = ((scissor >> 16) & 0x7FF) as i32;
        let scay0 = ((scissor >> 32) & 0x7FF) as i32;
        let scay1 = ((scissor >> 48) & 0x7FF) as i32;

        let min_x = (v0.x.min(v1.x).floor() as i32).max(scax0);
        let max_x = (v0.x.max(v1.x).ceil()  as i32).min(scax1);
        let min_y = (v0.y.min(v1.y).floor() as i32).max(scay0);
        let max_y = (v0.y.max(v1.y).ceil()  as i32).min(scay1);

        let z_mask = ((registers[0x4E] >> 32) & 0x1) != 0;
        if z_mask { return; }

        let frame_base = framebuffer_fbp as usize * 2048 * 4;
        let width      = framebuffer_fbw as usize * 64;

        for y in min_y..=max_y {
            for x in min_x..=max_x {
                let pixel_addr = frame_base + (y as usize * width + x as usize) * 4;
                if pixel_addr + 4 > vram.len() { continue; }
                write_rgba(vram, pixel_addr, v1);
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
        let vram_pixels = vram.len() / 4;

        for y in 0..height_pixels as usize {
            let src_pixels = (src_base_pixels as usize)
                .saturating_add(src_rect_x as usize)
                .saturating_add((src_rect_y as usize).saturating_mul(src_buffer_width_pixels as usize))
                .saturating_add(y.saturating_mul(src_buffer_width_pixels as usize));

            let dst_pixels = (dst_base_pixels as usize)
                .saturating_add(dst_rect_x as usize)
                .saturating_add((dst_rect_y as usize).saturating_mul(dst_buffer_width_pixels as usize))
                .saturating_add(y.saturating_mul(dst_buffer_width_pixels as usize));

            if src_pixels.checked_add(width_pixels as usize).map_or(false, |v| v <= vram_pixels)
                && dst_pixels.checked_add(width_pixels as usize).map_or(false, |v| v <= vram_pixels)
            {
                let src_b = src_pixels * 4;
                let dst_b = dst_pixels * 4;
                let len_b = width_pixels as usize * 4;

                if src_b + len_b <= vram.len() && dst_b + len_b <= vram.len() {
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

        if byte_addr + 8 <= vram.len() {
            vram[byte_addr..byte_addr + 8].copy_from_slice(&hwreg_data.to_le_bytes());
        }

        *dest_x += 2;
        if *dest_x >= area_width {
            *dest_x  = 0;
            *dest_y += 1;
        }
    }
}