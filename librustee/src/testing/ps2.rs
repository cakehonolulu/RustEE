use crate::testing::GoldenState;
use std::io::{BufRead, BufReader};
use std::process::Stdio;
use std::thread;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

pub fn ps2_ip() -> Option<String> {
    env::var("PS2_IP").ok().filter(|s| !s.is_empty())
}

pub fn compile_elf(mk_file: &Path, test_name: &str) -> Result<PathBuf, String> {
    let dir = mk_file.parent().unwrap();
    let out = dir.join(format!("{test_name}.elf"));

    let status = Command::new("make")
        .args(["-f", mk_file.file_name().unwrap().to_str().unwrap()])
        .current_dir(dir)
        .stdout(Stdio::null())
        .status()
        .map_err(|e| format!("`make` not found — is it on PATH? ({e})"))?;

    if !status.success() {
        return Err(format!("`make` failed building {test_name}"));
    }
    Ok(out)
}

pub fn run_on_hardware(
    elf: &Path,
    test_name: &str,
    ip: &str,
    result_path: &Path,
) -> Result<GoldenState, String> {
    let _ = fs::remove_file(result_path);

    let cwd = env::current_dir().map_err(|e| e.to_string())?;
    let relative_elf = elf.strip_prefix(&cwd).unwrap_or(elf);

    println!("Sending ELF to hardware...");

    let mut child = Command::new("ps2client")
        .args([
            "-h",
            ip,
            "execee",
            &format!("host:{}", relative_elf.to_str().unwrap()),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("`ps2client` failed to start: {e}"))?;

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let stderr = child.stderr.take().expect("Failed to capture stderr");

    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for _line in reader.lines() {}
    });

    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            if let Ok(l) = line {
                eprintln!("[ps2client] {}", l);
            }
        }
    });

    println!("Waiting for completion...");
    let deadline = Instant::now() + Duration::from_secs(10);

    while !result_path.exists() {
        if Instant::now() > deadline {
            let _ = child.kill();
            return Err("Timeout waiting for result".into());
        }

        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("ps2client exited prematurely with {}", status));
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    let _ = child.kill();
    println!("Results file acknowledged, resetting hardware...");

    let _ = Command::new("ps2client")
        .args(["-h", ip, "reset"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    std::thread::sleep(Duration::from_millis(1500));
    parse_result_bin(result_path)
}

const TEST_STATE_SIZE: usize = 816;

fn parse_result_bin(path: &Path) -> Result<GoldenState, String> {
    let data = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;

    if data.len() < TEST_STATE_SIZE {
        return Err(format!(
            "result.bin is {} bytes, expected {TEST_STATE_SIZE}",
            data.len()
        ));
    }

    let mut g = GoldenState::default();
    let mut cur = 0usize;

    g.pc = u32::from_le_bytes(data[cur..cur + 4].try_into().unwrap());
    cur += 4 + 12;

    for i in 0..32 {
        g.gpr[i] = u128::from_le_bytes(data[cur..cur + 16].try_into().unwrap());
        cur += 16;
    }

    for i in 0..32 {
        g.fpr[i] = u32::from_le_bytes(data[cur..cur + 4].try_into().unwrap());
        cur += 4;
    }

    for i in 0..32 {
        g.cop0[i] = u32::from_le_bytes(data[cur..cur + 4].try_into().unwrap());
        cur += 4;
    }

    g.lo = u128::from_le_bytes(data[cur..cur + 16].try_into().unwrap());
    cur += 16;
    g.hi = u128::from_le_bytes(data[cur..cur + 16].try_into().unwrap());

    Ok(g)
}
