use crate::testing::OpcodeTestSpec;
use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

pub const FRAMEWORK_H: &str = r#"
#pragma once
#include <stdint.h>

typedef struct __attribute__((aligned(16))) {
    uint32_t    pc;
    uint32_t    _pad[3];
    __uint128_t gpr[32];
    uint32_t    fpr[32];
    uint32_t    cop0[32];
    __uint128_t lo;
    __uint128_t hi;
} TestState;

void emit_result(const TestState* s, const char* path);
"#;

pub const CAPTURE_C: &str = r#"
#include "framework.h"
#include <stdio.h>

void emit_result(const TestState* s, const char* path) {
    FILE* f = fopen(path, "wb");
    if (f) { fwrite(s, sizeof(*s), 1, f); fclose(f); }
}
"#;

pub fn write_framework(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    fs::write(dir.join("framework.h"), FRAMEWORK_H)?;
    fs::write(dir.join("capture.c"), CAPTURE_C)?;
    Ok(())
}

pub fn generate_c(
    spec: &OpcodeTestSpec,
    dir: &Path,
    host_result_path: &str,
) -> std::io::Result<PathBuf> {
    let mut src = String::new();
    let _ = writeln!(
        src,
        "/* Auto-generated for {} — {} */",
        spec.family, spec.name
    );
    let _ = writeln!(src, "#include \"framework.h\"");
    let _ = writeln!(src, "#include \"kernel.h\"");
    let _ = writeln!(src, "#include <stdio.h>");

    let _ = writeln!(
        src,
        "static TestState __state __attribute__((aligned(16)));"
    );

    let _ = writeln!(src, "int main(void) {{");
    let _ = writeln!(src, "    printf(\"TEST START: {}\\n\");", spec.name);

    let _ = writeln!(src, "    asm volatile(");
    let _ = writeln!(src, "        \".set noreorder\\n\\t\"");

    let _ = writeln!(
        src,
        "        \".set at\\n\\tla $k0, __state\\n\\t.set noat\\n\\t\""
    );

    let _ = writeln!(
        src,
        "        \"move $8,$0; move $9,$0; move $10,$0;\\n\\t\""
    );
    let _ = writeln!(src, "        \"mthi $0; mtlo $0;\\n\\t\"");

    for init in &spec.init_gpr {
        let reg = init.reg;
        let v = init.val;

        if v == 0 {
            let _ = writeln!(src, "        \"move ${},$0;\\n\\t\"", reg);
        } else if v <= 0xFFFF {
            let _ = writeln!(src, "        \"ori ${},$0,0x{:X};\\n\\t\"", reg, v);
        } else if v <= 0xFFFF_FFFF {
            let upper = (v >> 16) as u16;
            let lower = v as u16;
            let _ = writeln!(
                src,
                "        \"lui ${},0x{:04X}; ori ${},${},0x{:04X}; dsll32 ${},0; dsrl32 ${},0;\\n\\t\"",
                reg, upper, reg, reg, lower, reg, reg
            );
        } else {
            let load_u64 = |dest_reg: usize, val: u64| -> String {
                let w3 = (val >> 48) as u16;
                let w2 = (val >> 32) as u16;
                let w1 = (val >> 16) as u16;
                let w0 = val as u16;
                format!(
                    "lui ${r},0x{w3:04X}; ori ${r},${r},0x{w2:04X}; dsll ${r},${r},16; ori ${r},${r},0x{w1:04X}; dsll ${r},${r},16; ori ${r},${r},0x{w0:04X}",
                    r = dest_reg,
                    w3 = w3,
                    w2 = w2,
                    w1 = w1,
                    w0 = w0
                )
            };

            let lower = v as u64;
            let upper = (v >> 64) as u64;

            if upper == 0 {
                let _ = writeln!(src, "        \"{};\\n\\t\"", load_u64(reg, lower));
            } else {
                let _ = writeln!(src, "        \"{};\\n\\t\"", load_u64(1, upper));
                let _ = writeln!(src, "        \"{};\\n\\t\"", load_u64(reg, lower));
                let _ = writeln!(src, "        \"pcpyld ${}, $1, ${};\\n\\t\"", reg, reg);
            }
        }
    }

    for line in spec.asm.lines() {
        let t = line.trim();
        if !t.is_empty() && !t.starts_with('#') && !t.starts_with("//") {
            let escaped = t.replace('\\', "\\\\").replace('"', "\\\"");
            let _ = writeln!(src, "        \"{}\\n\\t\"", escaped);
        }
    }

    let _ = writeln!(src, "        \"la $1, 1f; sw $1, 0($k0);\\n\\t\"");
    for i in 0..32 {
        let _ = writeln!(src, "        \"sq ${}, {}($k0)\\n\\t\"", i, 16 + i * 16);
    }
    let _ = writeln!(
        src,
        "        \"mflo $1; sd $1, 784($k0); mfhi $1; sd $1, 800($k0);\\n\\t\""
    );
    let _ = writeln!(src, "        \"1: nop\\n\\t\"");
    let _ = writeln!(src, "        \".set reorder\\n\\t\"");

    let _ = writeln!(src, "        :");
    let _ = writeln!(src, "        : \"r\"(0)");
    let _ = writeln!(src, "        : \"memory\", \"$k0\", \"$1\", \"$at\"");
    let _ = writeln!(src, "    );");
    let _ = writeln!(
        src,
        "    printf(\"DEBUG __state addr = 0x%p\\n\", (void*)&__state);"
    );
    let _ = writeln!(
        src,
        "    printf(\"DEBUG captured PC = 0x%08lX\\n\", __state.pc);"
    );
    for i in 0..32 {
        let _ = writeln!(
            src,
            "    printf(\"DEBUG captured $%02d (gpr[%d]) = 0x%016llX%016llX\\n\", {}, {},",
            i, i
        );
        let _ = writeln!(
            src,
            "           (unsigned long long)(__state.gpr[{}] >> 64),",
            i
        );
        let _ = writeln!(src, "           (unsigned long long)__state.gpr[{}]);", i);
    }
    let _ = writeln!(src, "    printf(\"State captured.\\n\");");
    let _ = writeln!(src, "    emit_result(&__state, \"{}\");", host_result_path);
    let _ = writeln!(src, "    SleepThread();");
    let _ = writeln!(src, "    return 0;");
    let _ = writeln!(src, "}}");

    let out = dir.join(format!("{}.c", spec.name));
    fs::write(&out, &src)?;
    Ok(out)
}

pub fn generate_makefile(spec: &OpcodeTestSpec, dir: &Path) -> std::io::Result<PathBuf> {
    let name = spec.name;
    let mk = format!(
        "# Auto-generated for {name}\n\
         EE_BIN = {name}.elf\n\
         EE_OBJS = {name}.o capture.o\n\
         EE_CFLAGS += -O0 -fno-pic -G0\n\
         all: $(EE_BIN)\n\
         clean:\n\
         \trm -f $(EE_OBJS) $(EE_BIN)\n\
         include $(PS2SDK)/samples/Makefile.pref\n\
         include $(PS2SDK)/samples/Makefile.eeglobal\n"
    );
    let out = dir.join(format!("{name}.mk"));
    fs::write(&out, mk)?;
    Ok(out)
}
