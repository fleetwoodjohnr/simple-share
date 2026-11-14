//! Turning sender-supplied names into safe paths, and putting finished files
//! in place without ever overwriting anything.

use std::io;
use std::path::{Path, PathBuf};

const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4",
    "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// One path component made safe on Linux, macOS and Windows.
/// `None` means there is nothing usable (empty, `..`, control characters).
fn safe_component(part: &str) -> Option<String> {
    if matches!(part, "" | "." | "..") || part.chars().any(char::is_control) {
        return None;
    }
    let mut clean: String =
        part.chars().map(|c| if matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') { '_' } else { c }).collect();
    clean = clean.trim_end_matches(['.', ' ']).trim_start().to_string();
    let stem = clean.split('.').next().unwrap_or("").to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        clean.insert(0, '_');
    }
    // Hidden files would be easy to miss, and `.partial` names are ours.
    if clean.starts_with('.') {
        clean.replace_range(..1, "_");
    }
    // Keep under the 255-byte limit of common filesystems, on a char boundary.
    while clean.len() > 255 {
        clean.pop();
    }
    (!clean.is_empty()).then_some(clean)
}

/// The file name a browser sent, reduced to its final component and made safe.
/// Browsers send bare names, but nothing stops a hostile client sending a path.
pub fn safe_file_name(name: &str) -> Option<String> {
    let last = name.rsplit(['/', '\\']).next().unwrap_or("");
    safe_component(last)
}

/// `name.ext`, then `name (1).ext`, `name (2).ext`… until free.
pub fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !first.exists() {
        return first;
    }
    let p = Path::new(name);
    let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let ext = p.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
    (1..).map(|n| dir.join(format!("{stem} ({n}){ext}"))).find(|p| !p.exists()).unwrap_or(first)
}

/// Move a finished temp file (in `dir`) to its final name. `hard_link` fails
/// instead of replacing an existing file, so a name taken in the meantime is
/// retried, never overwritten.
pub fn finalize(tmp: &Path, dir: &Path, name: &str) -> io::Result<PathBuf> {
    let target = loop {
        let target = unique_path(dir, name);
        match std::fs::hard_link(tmp, &target) {
            Ok(()) => break target,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            // Filesystems without hard links (FAT/exFAT): check-then-rename.
            Err(_) if !target.exists() => {
                std::fs::rename(tmp, &target)?;
                return Ok(target);
            }
            Err(_) => continue,
        }
    };
    std::fs::remove_file(tmp)?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_names_are_reduced_or_refused() {
        assert_eq!(safe_file_name("../../.bashrc").as_deref(), Some("_bashrc"));
        assert_eq!(safe_file_name("C:\\Windows\\evil.exe").as_deref(), Some("evil.exe"));
        assert_eq!(safe_file_name("/etc/passwd").as_deref(), Some("passwd"));
        assert_eq!(safe_file_name(".."), None);
        assert_eq!(safe_file_name("dir/"), None);
        assert_eq!(safe_file_name("bad\u{0}name"), None);
        assert_eq!(safe_file_name("line\nbreak"), None);
        assert_eq!(safe_file_name("CON.txt").as_deref(), Some("_CON.txt"));
        assert_eq!(safe_file_name("a:b*c?.").as_deref(), Some("a_b_c_"));
        assert_eq!(safe_file_name(".simple-share-partial-1").as_deref(), Some("_simple-share-partial-1"));
        assert_eq!(safe_file_name("IMG_0001.HEIC").as_deref(), Some("IMG_0001.HEIC"));
        assert_eq!(safe_file_name("Ünïcødé 写真.jpg").as_deref(), Some("Ünïcødé 写真.jpg"));
        let long = "é".repeat(200);
        assert!(safe_file_name(&long).is_some_and(|n| n.len() <= 255));
    }

    #[test]
    fn finalize_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("simple-share-save-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(dir.join("photo.jpg"), b"original").expect("existing");
        let tmp = dir.join(".partial");
        std::fs::write(&tmp, b"new").expect("tmp");
        let saved = finalize(&tmp, &dir, "photo.jpg").expect("finalize");
        assert_eq!(saved, dir.join("photo (1).jpg"));
        assert_eq!(std::fs::read(dir.join("photo.jpg")).expect("read"), b"original");
        assert_eq!(std::fs::read(&saved).expect("read"), b"new");
        assert!(!tmp.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
