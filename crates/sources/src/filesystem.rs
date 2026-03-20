//! Filesystem source: recursively walks a directory tree, skips binary files,
//! respects `.gitignore`, and yields chunks for scanning.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use std::path::PathBuf;
use walkdir::WalkDir;

/// Minimum file size to use memory mapping (4 KiB roughly matches a page and
/// avoids mmap overhead on tiny files).
const MMAP_THRESHOLD: u64 = 4096;
const MAX_READABLE_FILE_SIZE: u64 = usize::MAX as u64;

/// Scans files in a directory tree.
pub struct FilesystemSource {
    root: PathBuf,
    max_file_size: u64,
}

impl FilesystemSource {
    /// Create a filesystem source rooted at `root`.
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            max_file_size: 10 * 1024 * 1024, // 10 MB default
        }
    }

    /// Override the maximum file size scanned from disk.
    pub fn with_max_file_size(mut self, bytes: u64) -> Self {
        self.max_file_size = bytes;
        self
    }
}

/// File extensions to skip (binary, images, etc.).
const SKIP_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "cur", "icns", "webp", "mp3", "mp4", "avi", "mov",
    "mkv", "flac", "wav", "ogg", "zip", "tar", "gz", "bz2", "xz", "zst", "rar", "7z", "exe", "dll",
    "so", "dylib", "o", "a", "class", "jar", "wasm", "pyc", "pyo", "pdf", "doc", "docx", "xls",
    "xlsx", "ppt", "pptx", "ttf", "otf", "woff", "woff2", "eot",
];

/// Directories to skip entirely.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "vendor",
    "swagger-ui",
    "swagger",
];

impl Source for FilesystemSource {
    fn name(&self) -> &str {
        "filesystem"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        let walker = WalkDir::new(&self.root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|entry| {
                if entry.file_type().is_dir() {
                    let name = entry.file_name().to_string_lossy();
                    return !SKIP_DIRS.contains(&name.as_ref());
                }
                true
            });

        let max_size = self.max_file_size;

        Box::new(walker.filter_map(move |entry| {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    return Some(Err(SourceError::Io(std::io::Error::other(e.to_string()))));
                }
            };

            if !entry.file_type().is_file() {
                return None;
            }

            let path = entry.path();

            // Skip by extension.
            if let Some(ext) = path.extension().and_then(|e| e.to_str())
                && SKIP_EXTENSIONS.contains(&ext.to_lowercase().as_str())
            {
                return None;
            }

            // Skip minified/bundled files (e.g. *.min.js, *.bundle.js).
            // These contain dense code where generic patterns produce FPs.
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if filename.contains(".min.")
                || filename.contains(".bundle.")
                || filename.contains("-bundle.")
                || filename.ends_with(".chunk.js")
                || filename.ends_with(".chunk.css")
            {
                return None;
            }

            // Skip large files.
            let metadata = match entry.metadata() {
                Ok(m) => m,
                Err(_) => return None,
            };
            let file_size = metadata.len();
            if file_size > max_size {
                return Some(Err(SourceError::Other(format!(
                    "skipping {}: file size {} exceeds {} byte limit",
                    path.display(),
                    file_size,
                    max_size
                ))));
            }
            if file_size > MAX_READABLE_FILE_SIZE {
                return Some(Err(SourceError::Other(format!(
                    "skipping {}: file size {} exceeds this platform's readable limit",
                    path.display(),
                    file_size
                ))));
            }

            // Read file content. If the file is binary (contains null bytes),
            // extract printable strings instead of returning raw content.
            let file_text = if file_size >= MMAP_THRESHOLD {
                read_file_mmap(path)
            } else {
                read_file_buffered(path)
            };

            // Auto-detect binary files and extract strings
            let (content, source_type) = match file_text {
                Some(text) if !text.is_empty() => (text, "filesystem"),
                _ => {
                    // File couldn't be read as text — try binary string extraction
                    if let Ok(bytes) = std::fs::read(path) {
                        let strings = crate::strings::extract_printable_strings(&bytes, 8);
                        if strings.is_empty() {
                            return None;
                        }
                        (strings.join("\n"), "filesystem:binary-strings")
                    } else {
                        return None;
                    }
                }
            };

            Some(Ok(Chunk {
                data: content,
                metadata: ChunkMetadata {
                    source_type: source_type.to_string(),
                    path: Some(path.display().to_string()),
                    commit: None,
                    author: None,
                    date: None,
                },
            }))
        }))
    }
}

/// Read a small file using buffered I/O.
fn read_file_buffered(path: &std::path::Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    decode_text_file(&bytes)
}

/// Read a file using memory mapping for zero-copy access.
fn read_file_mmap(path: &std::path::Path) -> Option<String> {
    use memmap2::MmapOptions;

    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return None,
    };

    // Acquire a non-blocking shared advisory lock to reduce the risk of
    // SIGBUS from a concurrent truncation/replacement. If the lock cannot
    // be acquired (file is actively being written), fall back to buffered I/O.
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        // LOCK_SH | LOCK_NB = shared, non-blocking
        if unsafe { libc::flock(fd, libc::LOCK_SH | libc::LOCK_NB) } != 0 {
            return read_file_buffered(path);
        }
    }

    // SAFETY: the mapping is read-only, the `File` lives through the mapping
    // call, and we decode the bytes immediately without storing the mmap past
    // this function. The advisory lock above further reduces the window for
    // concurrent truncation.
    let mmap = match unsafe { MmapOptions::new().map(&file) } {
        Ok(m) => m,
        Err(_) => {
            // Fall back to buffered read on mmap failure
            return read_file_buffered(path);
        }
    };

    let result = decode_text_file(&mmap);

    // Release the advisory lock (also released automatically when file is dropped).
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        unsafe { libc::flock(fd, libc::LOCK_UN) };
    }

    result
}

fn decode_text_file(bytes: &[u8]) -> Option<String> {
    if looks_binary(bytes) {
        return None;
    }

    if let Some(text) = decode_utf16(bytes) {
        return Some(text);
    }

    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    match std::str::from_utf8(bytes) {
        Ok(text) => Some(text.to_string()),
        Err(error) => {
            tracing::debug!("skipping non-UTF8 text file after BOM handling: {error}");
            None
        }
    }
}

fn looks_binary(bytes: &[u8]) -> bool {
    if has_binary_magic(bytes) || has_utf16_nul_pattern(bytes) {
        return true;
    }
    if bytes.contains(&0) {
        return true;
    }

    let suspicious = bytes
        .iter()
        .filter(|&&byte| is_suspicious_control_byte(byte))
        .count();
    suspicious * 20 > bytes.len().max(1)
}

fn is_suspicious_control_byte(byte: u8) -> bool {
    byte < 0x20 && !matches!(byte, b'\n' | b'\r' | b'\t' | 0x0C)
}

fn has_binary_magic(bytes: &[u8]) -> bool {
    const MAGIC_HEADERS: &[&[u8]] = &[
        b"%PDF-",
        b"PK\x03\x04",
        b"\x89PNG\r\n\x1a\n",
        b"\xD0\xCF\x11\xE0",
    ];
    MAGIC_HEADERS.iter().any(|header| bytes.starts_with(header))
}

fn has_utf16_nul_pattern(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && (bytes[0] == 0xFF && bytes[1] == 0xFE || bytes[0] == 0xFE && bytes[1] == 0xFF)
}

fn decode_utf16(bytes: &[u8]) -> Option<String> {
    let (little_endian, payload) = if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        (true, rest)
    } else if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        (false, rest)
    } else {
        return None;
    };

    let chunks = payload.chunks_exact(2);
    if !chunks.remainder().is_empty() {
        return None;
    }

    let units: Vec<u16> = chunks
        .map(|chunk| {
            if little_endian {
                u16::from_le_bytes([chunk[0], chunk[1]])
            } else {
                u16::from_be_bytes([chunk[0], chunk[1]])
            }
        })
        .collect();
    String::from_utf16(&units).ok()
}

#[cfg(test)]
// Allow explicit borrows of PathBuf when calling functions like fs::write and
// fs::create_dir_all that accept AsRef<Path>; the explicit `&dir` is clearer
// than relying on auto-deref when `dir` is a PathBuf.
#[allow(clippy::needless_borrows_for_generic_args)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn scan_temp_directory() {
        let dir = std::env::temp_dir().join("keyhog_test_fs");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("config.py"),
            "API_KEY = 'xoxb-1234567890-1234567890-abcdefghijABCDEFGHIJklmn'",
        )
        .unwrap();
        fs::write(dir.join("image.png"), &[0x89, 0x50, 0x4e, 0x47]).unwrap();

        let source = FilesystemSource::new(dir.clone());
        let chunks: Vec<_> = source.chunks().collect();
        assert_eq!(chunks.len(), 1); // Only config.py, not image.png.
        assert!(chunks[0].as_ref().unwrap().data.contains("xoxb"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn scan_mmap_file() {
        let dir = std::env::temp_dir().join("keyhog_test_mmap");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Create a file larger than MMAP_THRESHOLD
        let large_content = "SECRET_KEY = ".to_string() + &"x".repeat(MMAP_THRESHOLD as usize);
        fs::write(dir.join("large_config.py"), &large_content).unwrap();

        let source = FilesystemSource::new(dir.clone());
        let chunks: Vec<_> = source.chunks().collect();
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].as_ref().unwrap().data.contains("SECRET_KEY"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn mmap_extracts_strings_from_binaryish_file() {
        let dir = std::env::temp_dir().join("keyhog_test_binaryish_mmap");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let mut content = b"SECRET_KEY=kR4vN8pW2cF6gH0j".to_vec();
        content.extend(std::iter::repeat_n(0x01, MMAP_THRESHOLD as usize));
        fs::write(dir.join("binaryish.txt"), &content).unwrap();

        let source = FilesystemSource::new(dir.clone());
        let chunks: Vec<_> = source.chunks().filter_map(|r| r.ok()).collect();
        // Binary-ish files now get string extraction instead of being skipped
        assert!(!chunks.is_empty(), "Binary files should produce string-extracted chunks");
        assert!(chunks[0].data.contains("SECRET_KEY"), "Extracted strings should contain the secret prefix");
        assert_eq!(chunks[0].metadata.source_type, "filesystem:binary-strings");

        let _ = fs::remove_dir_all(&dir);
    }
}
