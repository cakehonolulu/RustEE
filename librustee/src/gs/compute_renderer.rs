use super::renderer::{GsRenderer, Vertex};
use std::borrow::Cow;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const DRAW_UNIFORM_STRIDE: usize = 256;
const DRAW_RING_CAPACITY:  u32   = 4096;

const BLIT_UNIFORM_STRIDE: usize = 256;
const BLIT_RING_CAPACITY:  u32   = 256;

pub const VRAM_SIZE: u64 = 4 * 1024 * 1024;

struct PendingReadback {
    offset:        u64,
    size:          u64,
    display_start: u64,
}

#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable, Default)]
struct GpuVertex {
    x:            f32,
    y:            f32,
    z:            u32,
    packed_color: u32,
}

impl GpuVertex {
    #[inline]
    fn from_vertex(v: &Vertex) -> Self {
        Self {
            x: v.x,
            y: v.y,
            z: v.z,
            packed_color: u32::from_le_bytes([v.r, v.g, v.b, v.a]),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
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

const _: () = assert!(
    std::mem::size_of::<DrawUniforms>() == 80,
    "DrawUniforms size mismatch — check WGSL struct"
);

#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
struct ComputeBlitParams {
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
    _pad1:     u32,
    _pad2:     u32,
}

enum PendingCmd {
    Draw {
        ring_slot: u32,
        wg_x:      u32,
        wg_y:      u32,
        is_sprite: bool,
    },
    Blit {
        ring_slot:   u32,
        wg_x:        u32,
        wg_y:        u32,
        src_base:    u32,
        src_width:   u32,
        src_rect_x:  u32,
        src_rect_y:  u32,
        width:       u32,
        height:      u32,
    },
}

pub struct ComputeRenderer {
    device: Arc<wgpu::Device>,
    queue:  Arc<wgpu::Queue>,

    vram_buffer:      wgpu::Buffer,
    readback_buffer:  wgpu::Buffer,
    temp_blit_buffer: wgpu::Buffer,

    draw_ring_buf:      wgpu::Buffer,
    draw_ring_slot:     u32,
    draw_ring_uploaded: u32,

    blit_ring_buf:      wgpu::Buffer,
    blit_ring_slot:     u32,
    blit_ring_uploaded: u32,

    pipeline_triangle: wgpu::ComputePipeline,
    pipeline_sprite:   wgpu::ComputePipeline,
    pipeline_blit:     wgpu::ComputePipeline,

    draw_bind_group: wgpu::BindGroup,
    blit_bind_group: wgpu::BindGroup,

    pending_cmds: Vec<PendingCmd>,

    draw_staging: Vec<u8>,
    blit_staging: Vec<u8>,

    hwreg_shadow:    Box<[u8]>,
    hwreg_dirty_lo:  u64,
    hwreg_dirty_hi:  u64,

    pending_readback:  Option<PendingReadback>,
    last_submission:   Option<wgpu::SubmissionIndex>,

    map_result: Arc<AtomicBool>,
}

impl ComputeRenderer {
    pub fn new() -> Self {
        let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor::default());

        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            force_fallback_adapter: false,
            compatible_surface: None,
        }))
        .expect("ComputeRenderer: no suitable GPU adapter");

        let (device, queue) = pollster::block_on(adapter.request_device(
            &wgpu::DeviceDescriptor {
                label: Some("GS Compute Device"),
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits::downlevel_defaults(),
                memory_hints: Default::default(),
                ..Default::default()
            },
        ))
        .expect("ComputeRenderer: device creation failed");

        let device = Arc::new(device);
        let queue  = Arc::new(queue);

        let vram_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("GS VRAM"),
            size:  VRAM_SIZE,
            usage: wgpu::BufferUsages::STORAGE
                 | wgpu::BufferUsages::COPY_SRC
                 | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let readback_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("GS VRAM Readback"),
            size:  VRAM_SIZE,
            usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let temp_blit_buffer = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("GS Blit Snapshot"),
            size:  VRAM_SIZE,
            usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let draw_ring_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("GS Draw Ring"),
            size:  DRAW_RING_CAPACITY as u64 * DRAW_UNIFORM_STRIDE as u64,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let blit_ring_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("GS Blit Ring"),
            size:  BLIT_RING_CAPACITY as u64 * BLIT_UNIFORM_STRIDE as u64,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label:  Some("GS Compute Shader"),
            source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(include_str!("gs_compute.wgsl"))),
        });

        let draw_bgl = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("GS Draw BGL"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding:    0,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size:   None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding:    1,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: true,
                        min_binding_size:   NonZeroU64::new(
                            std::mem::size_of::<DrawUniforms>() as u64
                        ),
                    },
                    count: None,
                },
            ],
        });

        let blit_bgl = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("GS Blit BGL"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding:    0,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: false },
                        has_dynamic_offset: false,
                        min_binding_size:   None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding:    1,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: true,
                        min_binding_size:   NonZeroU64::new(
                            std::mem::size_of::<ComputeBlitParams>() as u64
                        ),
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding:    2,
                    visibility: wgpu::ShaderStages::COMPUTE,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Storage { read_only: true },
                        has_dynamic_offset: false,
                        min_binding_size:   None,
                    },
                    count: None,
                },
            ],
        });

        let draw_pll = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label:                Some("GS Draw PL"),
            bind_group_layouts:   &[&draw_bgl],
            push_constant_ranges: &[],
        });

        let blit_pll = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label:                Some("GS Blit PL"),
            bind_group_layouts:   &[&blit_bgl],
            push_constant_ranges: &[],
        });

        let make_pipeline = |entry: &'static str, layout: &wgpu::PipelineLayout, label: &'static str| {
            device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
                label:               Some(label),
                layout:              Some(layout),
                module:              &shader,
                entry_point:         Some(entry),
                compilation_options: Default::default(),
                cache:               None,
            })
        };

        let pipeline_triangle = make_pipeline("cs_draw_triangle", &draw_pll, "GS Triangle Pipeline");
        let pipeline_sprite   = make_pipeline("cs_draw_sprite",   &draw_pll, "GS Sprite Pipeline");
        let pipeline_blit     = make_pipeline("cs_blit_vram",     &blit_pll, "GS Blit Pipeline");

        let draw_bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label:   Some("GS Draw BG"),
            layout:  &draw_bgl,
            entries: &[
                wgpu::BindGroupEntry {
                    binding:  0,
                    resource: vram_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding:  1,
                    resource: wgpu::BindingResource::Buffer(wgpu::BufferBinding {
                        buffer: &draw_ring_buf,
                        offset: 0,
                        size:   NonZeroU64::new(std::mem::size_of::<DrawUniforms>() as u64),
                    }),
                },
            ],
        });

        let blit_bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label:   Some("GS Blit BG"),
            layout:  &blit_bgl,
            entries: &[
                wgpu::BindGroupEntry {
                    binding:  0,
                    resource: vram_buffer.as_entire_binding(),
                },
                wgpu::BindGroupEntry {
                    binding:  1,
                    resource: wgpu::BindingResource::Buffer(wgpu::BufferBinding {
                        buffer: &blit_ring_buf,
                        offset: 0,
                        size:   NonZeroU64::new(std::mem::size_of::<ComputeBlitParams>() as u64),
                    }),
                },
                wgpu::BindGroupEntry {
                    binding:  2,
                    resource: temp_blit_buffer.as_entire_binding(),
                },
            ],
        });

        Self {
            device,
            queue,
            vram_buffer,
            readback_buffer,
            temp_blit_buffer,
            draw_ring_buf,
            draw_ring_slot:     0,
            draw_ring_uploaded: 0,
            blit_ring_buf,
            blit_ring_slot:     0,
            blit_ring_uploaded: 0,
            pipeline_triangle,
            pipeline_sprite,
            pipeline_blit,
            draw_bind_group,
            blit_bind_group,
            pending_cmds: Vec::with_capacity(256),
            draw_staging: vec![0u8; DRAW_RING_CAPACITY as usize * DRAW_UNIFORM_STRIDE],
            blit_staging: vec![0u8; BLIT_RING_CAPACITY as usize * BLIT_UNIFORM_STRIDE],
            hwreg_shadow: vec![0u8; VRAM_SIZE as usize].into_boxed_slice(),
            hwreg_dirty_lo: u64::MAX,
            hwreg_dirty_hi: 0,
            pending_readback: None,
            last_submission:  None,
            map_result: Arc::new(AtomicBool::new(false)),
        }
    }

    #[inline]
    fn extract_draw_meta(
        registers:       &[u64; 0x63],
        _framebuffer_fbp: u32,
        _framebuffer_fbw: u32,
    ) -> (i32, i32, i32, i32, u32) {
        let scissor = registers[0x40];
        let scax0 = (scissor        & 0x7FF) as i32;
        let scax1 = ((scissor >> 16) & 0x7FF) as i32;
        let scay0 = ((scissor >> 32) & 0x7FF) as i32;
        let scay1 = ((scissor >> 48) & 0x7FF) as i32;

        let zbuf   = registers[0x4E];
        let z_mask = ((zbuf >> 32) & 0x1) as u32;

        (scax0, scax1, scay0, scay1, z_mask)
    }

    fn enqueue_draw(
        &mut self,
        uniforms:  DrawUniforms,
        wg_x:      u32,
        wg_y:      u32,
        is_sprite: bool,
    ) {
        if self.draw_ring_slot >= DRAW_RING_CAPACITY {
            self.flush();
        }

        let slot   = self.draw_ring_slot as usize;
        let offset = slot * DRAW_UNIFORM_STRIDE;

        self.draw_staging[offset..offset + std::mem::size_of::<DrawUniforms>()]
            .copy_from_slice(bytemuck::bytes_of(&uniforms));

        self.pending_cmds.push(PendingCmd::Draw {
            ring_slot: slot as u32,
            wg_x,
            wg_y,
            is_sprite,
        });
        self.draw_ring_slot += 1;
    }

    fn encode_draw_batch(&self, encoder: &mut wgpu::CommandEncoder, batch: &[PendingCmd]) {
        if batch.is_empty() { return; }

        let mut cpass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
            label:            Some("GS Draw Batch"),
            timestamp_writes: None,
        });

        for cmd in batch {
            if let PendingCmd::Draw { ring_slot, wg_x, wg_y, is_sprite } = cmd {
                let pipeline = if *is_sprite { &self.pipeline_sprite } else { &self.pipeline_triangle };
                cpass.set_pipeline(pipeline);
                let dyn_offset = ring_slot * DRAW_UNIFORM_STRIDE as u32;
                cpass.set_bind_group(0, &self.draw_bind_group, &[dyn_offset]);
                cpass.dispatch_workgroups(*wg_x, *wg_y, 1);
            }
        }
    }

    fn encode_blit(&self, encoder: &mut wgpu::CommandEncoder, cmd: &PendingCmd) {
        let PendingCmd::Blit {
            ring_slot,
            wg_x, wg_y,
            src_base, src_width,
            src_rect_x, src_rect_y,
            width, height,
        } = *cmd else { return };

        if width == 0 || height == 0 { return; }

        if height == 1 || width * 2 >= src_width {
            let first_pixel = src_base as u64
                + src_rect_y as u64 * src_width as u64
                + src_rect_x as u64;
            let last_pixel  = src_base as u64
                + (src_rect_y as u64 + height as u64 - 1) * src_width as u64
                + (src_rect_x as u64 + width  as u64 - 1)
                + 1;
            let snap_offset = first_pixel * 4;
            let snap_end    = (last_pixel * 4).min(VRAM_SIZE);
            let snap_size   = (snap_end.saturating_sub(snap_offset) + 3) & !3;

            if snap_size > 0 {
                encoder.copy_buffer_to_buffer(
                    &self.vram_buffer,      snap_offset,
                    &self.temp_blit_buffer, snap_offset,
                    snap_size,
                );
            }
        } else {
            let row_bytes = width as u64 * 4;
            for row in 0..height as u64 {
                let pixel_offset = src_base as u64
                    + (src_rect_y as u64 + row) * src_width as u64
                    + src_rect_x as u64;
                let byte_offset = pixel_offset * 4;
                let row_end     = byte_offset + row_bytes;
                if row_end > VRAM_SIZE { break; }
                encoder.copy_buffer_to_buffer(
                    &self.vram_buffer,      byte_offset,
                    &self.temp_blit_buffer, byte_offset,
                    row_bytes,
                );
            }
        }

        let mut cpass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
            label:            Some("GS Blit"),
            timestamp_writes: None,
        });
        cpass.set_pipeline(&self.pipeline_blit);
        let dyn_offset = ring_slot * BLIT_UNIFORM_STRIDE as u32;
        cpass.set_bind_group(0, &self.blit_bind_group, &[dyn_offset]);
        cpass.dispatch_workgroups(wg_x, wg_y, 1);
    }

    fn encode_pending(&mut self, encoder: &mut wgpu::CommandEncoder) {
        if self.hwreg_dirty_lo < self.hwreg_dirty_hi {
            let lo = self.hwreg_dirty_lo as usize;
            let hi = self.hwreg_dirty_hi as usize;
            self.queue.write_buffer(
                &self.vram_buffer,
                self.hwreg_dirty_lo,
                &self.hwreg_shadow[lo..hi],
            );
            self.hwreg_dirty_lo = u64::MAX;
            self.hwreg_dirty_hi = 0;
        }

        if self.draw_ring_slot > self.draw_ring_uploaded {
            let lo = self.draw_ring_uploaded as usize * DRAW_UNIFORM_STRIDE;
            let hi = self.draw_ring_slot     as usize * DRAW_UNIFORM_STRIDE;
            self.queue.write_buffer(&self.draw_ring_buf, lo as u64, &self.draw_staging[lo..hi]);
        }
        self.draw_ring_slot     = 0;
        self.draw_ring_uploaded = 0;

        if self.blit_ring_slot > self.blit_ring_uploaded {
            let lo = self.blit_ring_uploaded as usize * BLIT_UNIFORM_STRIDE;
            let hi = self.blit_ring_slot     as usize * BLIT_UNIFORM_STRIDE;
            self.queue.write_buffer(&self.blit_ring_buf, lo as u64, &self.blit_staging[lo..hi]);
        }
        self.blit_ring_slot     = 0;
        self.blit_ring_uploaded = 0;

        let pending = std::mem::take(&mut self.pending_cmds);
        if pending.is_empty() { return; }

        let mut batch_start = 0usize;
        for (i, cmd) in pending.iter().enumerate() {
            if matches!(cmd, PendingCmd::Blit { .. }) {
                self.encode_draw_batch(encoder, &pending[batch_start..i]);
                self.encode_blit(encoder, cmd);
                batch_start = i + 1;
            }
        }
        self.encode_draw_batch(encoder, &pending[batch_start..]);
    }

    fn flush(&mut self) {
        if self.pending_cmds.is_empty()
            && self.draw_ring_slot == 0
            && self.blit_ring_slot == 0
            && self.hwreg_dirty_lo >= self.hwreg_dirty_hi
        {
            return;
        }

        let mut encoder = self.device.create_command_encoder(
            &wgpu::CommandEncoderDescriptor { label: Some("GS Flush") },
        );
        self.encode_pending(&mut encoder);
        self.queue.submit(Some(encoder.finish()));
    }

    fn submit_frame_internal(&mut self, byte_offset: usize, byte_len: usize) {
        if byte_len == 0 {
            self.flush();
            return;
        }

        let offset = (byte_offset as u64) & !3u64;
        let end    = ((byte_offset + byte_len) as u64 + 3) & !3u64;
        let size   = (end - offset).min(VRAM_SIZE - offset);

        let mut encoder = self.device.create_command_encoder(
            &wgpu::CommandEncoderDescriptor { label: Some("GS Frame Submit") },
        );

        self.encode_pending(&mut encoder);

        encoder.copy_buffer_to_buffer(
            &self.vram_buffer,     offset,
            &self.readback_buffer, offset,
            size,
        );

        self.pending_readback = Some(PendingReadback {
            offset,
            size,
            display_start: byte_offset as u64,
        });

        self.last_submission = Some(self.queue.submit(Some(encoder.finish())));
    }

    fn collect_readback_internal(&mut self, vram: &mut [u8]) {
        let Some(rb) = self.pending_readback.take() else { return };

        let slice = self.readback_buffer.slice(rb.offset..rb.offset + rb.size);
        let flag  = self.map_result.clone();
        flag.store(false, Ordering::Release);
        slice.map_async(wgpu::MapMode::Read, move |r| {
            flag.store(r.is_ok(), Ordering::Release);
        });

        let _ = self.device.poll(wgpu::PollType::Wait {
            submission_index: self.last_submission.take(),
            timeout: None,
        });

        if self.map_result.load(Ordering::Acquire) {
            let mapped = slice.get_mapped_range();
            let lo = rb.offset as usize;
            let hi = lo + rb.size as usize;
            vram[lo..hi].copy_from_slice(&mapped);
            drop(mapped);
            self.readback_buffer.unmap();
        } else {
            eprintln!("ComputeRenderer: VRAM readback failed");
        }
    }

    fn collect_to_display_internal(
        &mut self,
        back_buffer:         &mut [u8],
        dbx:                 u32,
        buffer_width_pixels: u32,
        read_width:          u32,
        read_height:         u32,
    ) -> bool {
        let Some(rb) = self.pending_readback.take() else { return false };

        let slice = self.readback_buffer.slice(rb.offset..rb.offset + rb.size);
        let flag  = self.map_result.clone();
        flag.store(false, Ordering::Release);
        slice.map_async(wgpu::MapMode::Read, move |r| {
            flag.store(r.is_ok(), Ordering::Release);
        });

        let _ = self.device.poll(wgpu::PollType::Wait {
            submission_index: self.last_submission.take(),
            timeout: None,
        });

        if self.map_result.load(Ordering::Acquire) {
            let mapped        = slice.get_mapped_range();
            let stride        = buffer_width_pixels as usize * 4;
            let row_bytes     = read_width as usize * 4;
            let row_base      = (rb.display_start - rb.offset) as usize;

            for py in 0..read_height as usize {
                let src = row_base + py * stride + dbx as usize * 4;
                let dst = py * row_bytes;
                back_buffer[dst..dst + row_bytes].copy_from_slice(&mapped[src..src + row_bytes]);
            }

            drop(mapped);
            self.readback_buffer.unmap();
            true
        } else {
            eprintln!("ComputeRenderer: collect_to_display readback failed");
            false
        }
    }
}

impl GsRenderer for ComputeRenderer {
    fn name(&self) -> &'static str { "Compute" }

    fn read_vram(&mut self, vram: &mut [u8]) {
        self.submit_frame_internal(0, VRAM_SIZE as usize);
        self.collect_readback_internal(vram);
    }

    fn read_vram_region(&mut self, vram: &mut [u8], byte_offset: usize, byte_len: usize) {
        if byte_len == 0 { return; }
        self.submit_frame_internal(byte_offset, byte_len);
        self.collect_readback_internal(vram);
    }

    fn write_vram(&mut self, vram: &[u8]) {
        self.queue.write_buffer(&self.vram_buffer, 0, vram);
        self.hwreg_shadow.copy_from_slice(vram);
        self.hwreg_dirty_lo = u64::MAX;
        self.hwreg_dirty_hi = 0;
    }

    fn draw_point(
        &mut self,
        vram:            &mut [u8],
        vertex:          &Vertex,
        registers:       &[u64; 0x63],
        framebuffer_fbp: u32,
        framebuffer_fbw: u32,
    ) {
        let vertices = [*vertex, *vertex];
        self.draw_sprite(vram, &vertices, registers, framebuffer_fbp, framebuffer_fbw);
    }

    fn draw_triangle(
        &mut self,
        _vram:           &mut [u8],
        vertices:        &[Vertex],
        registers:       &[u64; 0x63],
        framebuffer_fbp: u32,
        framebuffer_fbw: u32,
    ) {
        let (scax0, scax1, scay0, scay1, z_mask) =
            Self::extract_draw_meta(registers, framebuffer_fbp, framebuffer_fbw);

        let v0     = &vertices[0];
        let v1_raw = &vertices[1];
        let v2_raw = &vertices[2];

        let area = (v2_raw.x - v0.x) * (v1_raw.y - v0.y)
                 - (v2_raw.y - v0.y) * (v1_raw.x - v0.x);
        if area == 0.0 { return; }
        let (v1, v2) = if area < 0.0 { (v2_raw, v1_raw) } else { (v1_raw, v2_raw) };

        let min_x = v0.x.min(v1.x).min(v2.x).floor() as i32;
        let max_x = v0.x.max(v1.x).max(v2.x).ceil()  as i32;
        let min_y = v0.y.min(v1.y).min(v2.y).floor() as i32;
        let max_y = v0.y.max(v1.y).max(v2.y).ceil()  as i32;

        let start_x = min_x.max(scax0);
        let end_x   = max_x.min(scax1);
        let start_y = min_y.max(scay0);
        let end_y   = max_y.min(scay1);

        if end_x < start_x || end_y < start_y { return; }

        let width  = (end_x - start_x + 1) as u32;
        let height = (end_y - start_y + 1) as u32;

        let uniforms = DrawUniforms {
            fbp: framebuffer_fbp, fbw: framebuffer_fbw,
            scax0, scax1, scay0, scay1, z_mask, _pad: 0,
            v0: GpuVertex::from_vertex(v0),
            v1: GpuVertex::from_vertex(v1),
            v2: GpuVertex::from_vertex(v2),
        };

        self.enqueue_draw(uniforms, (width + 15) / 16, (height + 7) / 8, false);
    }

    fn draw_sprite(
        &mut self,
        _vram:           &mut [u8],
        vertices:        &[Vertex],
        registers:       &[u64; 0x63],
        framebuffer_fbp: u32,
        framebuffer_fbw: u32,
    ) {
        let (scax0, scax1, scay0, scay1, z_mask) =
            Self::extract_draw_meta(registers, framebuffer_fbp, framebuffer_fbw);

        let v0 = &vertices[0];
        let v1 = &vertices[1];

        let min_x = v0.x.min(v1.x).floor() as i32;
        let max_x = v0.x.max(v1.x).ceil()  as i32;
        let min_y = v0.y.min(v1.y).floor() as i32;
        let max_y = v0.y.max(v1.y).ceil()  as i32;

        let start_x = min_x.max(scax0);
        let end_x   = max_x.min(scax1);
        let start_y = min_y.max(scay0);
        let end_y   = max_y.min(scay1);

        if end_x < start_x || end_y < start_y { return; }

        let width  = (end_x - start_x + 1) as u32;
        let height = (end_y - start_y + 1) as u32;

        let uniforms = DrawUniforms {
            fbp: framebuffer_fbp, fbw: framebuffer_fbw,
            scax0, scax1, scay0, scay1, z_mask, _pad: 0,
            v0: GpuVertex::from_vertex(v0),
            v1: GpuVertex::from_vertex(v1),
            v2: GpuVertex::default(),
        };

        self.enqueue_draw(uniforms, (width + 15) / 16, (height + 7) / 8, true);
    }

    fn blit_vram(
        &mut self,
        _vram:                   &mut [u8],
        src_base_pixels:         u64,
        src_buffer_width_pixels: u64,
        src_rect_x:              u64,
        src_rect_y:              u64,
        dst_base_pixels:         u64,
        dst_buffer_width_pixels: u64,
        dst_rect_x:              u64,
        dst_rect_y:              u64,
        width_pixels:            u64,
        height_pixels:           u64,
    ) {
        if self.blit_ring_slot >= BLIT_RING_CAPACITY {
            self.flush();
        }

        let params = ComputeBlitParams {
            src_base:  src_base_pixels         as u32,
            src_width: src_buffer_width_pixels as u32,
            src_x:     src_rect_x             as u32,
            src_y:     src_rect_y             as u32,
            dst_base:  dst_base_pixels         as u32,
            dst_width: dst_buffer_width_pixels as u32,
            dst_x:     dst_rect_x             as u32,
            dst_y:     dst_rect_y             as u32,
            width:     width_pixels           as u32,
            height:    height_pixels          as u32,
            _pad1: 0, _pad2: 0,
        };

        let slot   = self.blit_ring_slot as usize;
        let offset = slot * BLIT_UNIFORM_STRIDE;
        self.blit_staging[offset..offset + std::mem::size_of::<ComputeBlitParams>()]
            .copy_from_slice(bytemuck::bytes_of(&params));

        let wg_x = (width_pixels  as u32 + 15) / 16;
        let wg_y = (height_pixels as u32 +  7) / 8;

        self.pending_cmds.push(PendingCmd::Blit {
            ring_slot:  slot as u32,
            wg_x,
            wg_y,
            src_base:   src_base_pixels         as u32,
            src_width:  src_buffer_width_pixels as u32,
            src_rect_x: src_rect_x             as u32,
            src_rect_y: src_rect_y             as u32,
            width:      width_pixels           as u32,
            height:     height_pixels          as u32,
        });

        self.blit_ring_slot += 1;
    }

    fn transfer_hwreg(
        &mut self,
        _vram:               &mut [u8],
        hwreg_data:          u64,
        base_addr_pixels:    u64,
        rect_x:              u64,
        rect_y:              u64,
        buffer_width_pixels: u64,
        dest_x:              &mut u64,
        dest_y:              &mut u64,
        area_width:          u64,
    ) {
        let pixel_offset = (rect_y + *dest_y) * buffer_width_pixels + (rect_x + *dest_x);
        let byte_addr    = (base_addr_pixels * 4 + pixel_offset * 4) as usize;

        if byte_addr + 8 <= self.hwreg_shadow.len() {
            self.hwreg_shadow[byte_addr..byte_addr + 8]
                .copy_from_slice(&hwreg_data.to_le_bytes());

            self.hwreg_dirty_lo = self.hwreg_dirty_lo.min(byte_addr as u64);
            self.hwreg_dirty_hi = self.hwreg_dirty_hi.max((byte_addr + 8) as u64);
        }

        *dest_x += 2;
        if *dest_x >= area_width {
            *dest_x = 0;
            *dest_y += 1;
        }
    }


    fn submit_frame(&mut self, byte_offset: usize, byte_len: usize) {
        self.submit_frame_internal(byte_offset, byte_len);
    }

    fn collect_readback(
        &mut self,
        vram:         &mut [u8],
        _byte_offset: usize,
        _byte_len:    usize,
    ) {
        self.collect_readback_internal(vram);
    }

    fn collect_to_display(
        &mut self,
        back_buffer:         &mut [u8],
        dbx:                 u32,
        buffer_width_pixels: u32,
        read_width:          u32,
        read_height:         u32,
    ) -> bool {
        self.collect_to_display_internal(back_buffer, dbx, buffer_width_pixels, read_width, read_height)
    }
}