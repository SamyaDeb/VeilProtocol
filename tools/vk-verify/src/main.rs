/// vk-verify — M7 circuit-key integrity checker
///
/// Reads `circuit-keys/manifest.sha256` and verifies every listed file against
/// its pinned SHA-256 digest. Exits 0 on full match, non-zero on any mismatch.
///
/// Usage:
///   vk-verify [--keys-dir <path>]
///
///   --keys-dir   path to the circuit-keys/ directory (default: circuit-keys
///                relative to the current working directory).
///
/// The manifest format mirrors sha256sum(1): one line per file,
///   <hex-digest>  <path-relative-to-keys-dir>
///
/// Security note: this tool checks disk integrity only. It does NOT reach out
/// to any Soroban node. Add --rpc-url + --contract-id when on-chain comparison
/// is needed (future extension point; stub currently).

use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
    process,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let keys_dir = parse_keys_dir(&args).unwrap_or_else(|| PathBuf::from("circuit-keys"));

    let manifest_path = keys_dir.join("manifest.sha256");

    let manifest_src = fs::read_to_string(&manifest_path).unwrap_or_else(|e| {
        eprintln!("error: cannot read {}: {}", manifest_path.display(), e);
        process::exit(2);
    });

    let mut pass = 0usize;
    let mut fail = 0usize;

    for (lineno, line) in manifest_src.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (expected_hex, rel_path) = parse_manifest_line(line, lineno + 1);
        let file_path = keys_dir.join(&rel_path);

        match sha256_file(&file_path) {
            Ok(actual_hex) => {
                if actual_hex == expected_hex {
                    println!("OK  {rel_path}");
                    pass += 1;
                } else {
                    eprintln!("FAIL {rel_path}");
                    eprintln!("     expected: {expected_hex}");
                    eprintln!("     got:      {actual_hex}");
                    fail += 1;
                }
            }
            Err(e) => {
                eprintln!("MISSING {}: {}", file_path.display(), e);
                fail += 1;
            }
        }
    }

    println!("\n{pass} ok, {fail} failed");
    if fail > 0 {
        process::exit(1);
    }
}

fn parse_keys_dir(args: &[String]) -> Option<PathBuf> {
    let mut it = args.iter().skip(1);
    while let Some(arg) = it.next() {
        if arg == "--keys-dir" {
            return it.next().map(PathBuf::from);
        }
    }
    None
}

/// Parses a sha256sum-format line: `<hex>  <path>` (two spaces).
/// Panics with a clear message if the line is malformed.
fn parse_manifest_line(line: &str, lineno: usize) -> (String, String) {
    let (hex_part, path_part) = line.split_once("  ").unwrap_or_else(|| {
        eprintln!("error: manifest line {lineno} malformed (expected '<hex>  <path>'): {line}");
        process::exit(2);
    });
    (hex_part.trim().to_lowercase(), path_part.trim().to_string())
}

fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}
