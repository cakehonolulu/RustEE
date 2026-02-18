struct GpuVertex {
    x:            f32,
    y:            f32,
    z:            u32,
    packed_color: u32,
}

struct DrawUniforms {
    fbp:    u32,
    fbw:    u32,
    scax0:  i32,
    scax1:  i32,
    scay0:  i32,
    scay1:  i32,
    z_mask: u32,
    _pad:   u32,
    v0:     GpuVertex,
    v1:     GpuVertex,
    v2:     GpuVertex,
}

@group(0) @binding(0) var<storage, read_write> vram: array<u32>;
@group(0) @binding(1) var<uniform>             draw: DrawUniforms;

fn vram_addr(gid_x: i32, gid_y: i32) -> u32 {
    let frame_base = draw.fbp * 2048u;
    let width      = draw.fbw * 64u;
    return frame_base + u32(gid_y) * width + u32(gid_x);
}

@compute @workgroup_size(16, 8, 1)
fn cs_draw_triangle(@builtin(global_invocation_id) global_id: vec3<u32>) {
    if (draw.z_mask != 0u) { return; }

    let v0 = draw.v0;
    let v1 = draw.v1;
    let v2 = draw.v2;

    let min_x = min(v0.x, min(v1.x, v2.x));
    let max_x = max(v0.x, max(v1.x, v2.x));
    let min_y = min(v0.y, min(v1.y, v2.y));
    let max_y = max(v0.y, max(v1.y, v2.y));

    let start_x = max(i32(floor(min_x)), draw.scax0);
    let start_y = max(i32(floor(min_y)), draw.scay0);

    let gid_x = i32(global_id.x) + start_x;
    let gid_y = i32(global_id.y) + start_y;

    if (gid_x > i32(ceil(max_x)) || gid_x > draw.scax1 ||
        gid_y > i32(ceil(max_y)) || gid_y > draw.scay1) {
        return;
    }

    let px = f32(gid_x) + 0.5;
    let py = f32(gid_y) + 0.5;

    let w0 = (px - v1.x) * (v2.y - v1.y) - (py - v1.y) * (v2.x - v1.x);
    let w1 = (px - v2.x) * (v0.y - v2.y) - (py - v2.y) * (v0.x - v2.x);
    let w2 = (px - v0.x) * (v1.y - v0.y) - (py - v0.y) * (v1.x - v0.x);

    let area = (v2.x - v0.x) * (v1.y - v0.y) - (v2.y - v0.y) * (v1.x - v0.x);
    if (area <= 0.0) { return; }

    let inside = w0 >= 0.0 && w1 >= 0.0 && w2 >= 0.0;

    if (inside) {
        let inv = 1.0 / area;
        let bw0 = w0 * inv;
        let bw1 = w1 * inv;
        let bw2 = w2 * inv;

        let r = u32(clamp(
            bw0 * f32( v0.packed_color        & 0xFFu) +
            bw1 * f32( v1.packed_color        & 0xFFu) +
            bw2 * f32( v2.packed_color        & 0xFFu),
            0.0, 255.0));
        let g = u32(clamp(
            bw0 * f32((v0.packed_color >>  8u) & 0xFFu) +
            bw1 * f32((v1.packed_color >>  8u) & 0xFFu) +
            bw2 * f32((v2.packed_color >>  8u) & 0xFFu),
            0.0, 255.0));
        let b = u32(clamp(
            bw0 * f32((v0.packed_color >> 16u) & 0xFFu) +
            bw1 * f32((v1.packed_color >> 16u) & 0xFFu) +
            bw2 * f32((v2.packed_color >> 16u) & 0xFFu),
            0.0, 255.0));
        let a = u32(clamp(
            bw0 * f32((v0.packed_color >> 24u) & 0xFFu) +
            bw1 * f32((v1.packed_color >> 24u) & 0xFFu) +
            bw2 * f32((v2.packed_color >> 24u) & 0xFFu),
            0.0, 255.0));

        vram[vram_addr(gid_x, gid_y)] = r | (g << 8u) | (b << 16u) | (a << 24u);
    }
}

@compute @workgroup_size(16, 8, 1)
fn cs_draw_sprite(@builtin(global_invocation_id) global_id: vec3<u32>) {
    if (draw.z_mask != 0u) { return; }

    let v0 = draw.v0;
    let v1 = draw.v1;

    let min_x = min(v0.x, v1.x);
    let max_x = max(v0.x, v1.x);
    let min_y = min(v0.y, v1.y);
    let max_y = max(v0.y, v1.y);

    let start_x = max(i32(floor(min_x)), draw.scax0);
    let start_y = max(i32(floor(min_y)), draw.scay0);

    let gid_x = i32(global_id.x) + start_x;
    let gid_y = i32(global_id.y) + start_y;

    if (gid_x > i32(ceil(max_x)) || gid_x > draw.scax1 ||
        gid_y > i32(ceil(max_y)) || gid_y > draw.scay1) {
        return;
    }

    vram[vram_addr(gid_x, gid_y)] = v1.packed_color;
}

struct BlitParams {
    src_base:  u32,
    src_width: u32,
    src_x:     u32,
    src_y:     u32,
    dst_base:  u32,
    dst_width: u32,
    dst_x:     u32,
    dst_y:     u32,
    width:     u32,
    height:    u32,
    _p1:       u32,
    _p2:       u32,
}

@group(0) @binding(1) var<uniform>       blit_params:   BlitParams;
@group(0) @binding(2) var<storage, read> vram_snapshot: array<u32>;

@compute @workgroup_size(16, 8, 1)
fn cs_blit_vram(@builtin(global_invocation_id) global_id: vec3<u32>) {
    if (global_id.x >= blit_params.width || global_id.y >= blit_params.height) { return; }

    let src_x = blit_params.src_x + global_id.x;
    let src_y = blit_params.src_y + global_id.y;
    let dst_x = blit_params.dst_x + global_id.x;
    let dst_y = blit_params.dst_y + global_id.y;

    let src_idx = blit_params.src_base + src_y * blit_params.src_width + src_x;
    let dst_idx = blit_params.dst_base + dst_y * blit_params.dst_width + dst_x;

    vram[dst_idx] = vram_snapshot[src_idx];
}
