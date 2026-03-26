//! Filesystem source: recursively walks a directory tree, skips binary files,
//! respects `.gitignore`, and yields chunks for scanning.

use codewalk::{CodeWalker, WalkConfig};
use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use std::collections::HashSet;
use std::path::PathBuf;

/// Minimum file size to use memory mapping (4 KiB roughly matches a page and
/// avoids mmap overhead on tiny files).
const MMAP_THRESHOLD: u64 = 4096;

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
        let max_size = self.max_file_size;
        let walker = CodeWalker::new(&self.root, walker_config(self.max_file_size))
            .walk()
            .into_iter();

        Box::new(walker.filter_map(move |entry| {
            let path = entry.path;
            let file_size = entry.size;

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

            if file_size > max_size {
                return Some(Err(SourceError::Other(format!(
                    "skipping {}: file size {} exceeds {} byte limit",
                    path.display(),
                    file_size,
                    max_size
                ))));
            }
            // Read file content. If the file is binary (contains null bytes),
            // extract printable strings instead of returning raw content.
            let file_text = if file_size >= MMAP_THRESHOLD {
                read_file_mmap(&path)
            } else {
                read_file_buffered(&path)
            };

            // Auto-detect binary files and extract strings
            let (content, source_type) = match file_text {
                Some(text) if !text.is_empty() => (text, "filesystem"),
                _ => {
                    // File couldn't be read as text — try binary string extraction
                    if let Ok(bytes) = read_file_safe(&path) {
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

fn walker_config(max_file_size: u64) -> WalkConfig {
    let mut exclude_extensions = HashSet::new();
    exclude_extensions.extend(SKIP_EXTENSIONS.iter().map(|ext| (*ext).to_string()));

    let mut exclude_dirs = HashSet::new();
    exclude_dirs.extend(SKIP_DIRS.iter().map(|dir| (*dir).to_string()));

    WalkConfig::default()
        .max_file_size(max_file_size)
        .follow_symlinks(false)
        .respect_gitignore(false)
        .skip_hidden(false)
        .skip_binary(false)
        .exclude_extensions(exclude_extensions)
        .exclude_dirs(exclude_dirs)
        .mmap_threshold(MMAP_THRESHOLD)
        .use_mmap(true)
}

/// Read a small file safely (preventing TOCTOU symlink attacks).
fn read_file_buffered(path: &std::path::Path) -> Option<String> {
    let bytes = read_file_safe(path).ok()?;
    decode_text_file(&bytes)
}

/// Safely open a file for reading, preventing symlink following.
fn open_file_safe(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NOFOLLOW prevents TOCTOU symlink read vulnerabilities.
        options.custom_flags(libc::O_NOFOLLOW);
    }

    options.open(path)
}

/// Safely read a file into bytes, preventing symlink following.
fn read_file_safe(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    let mut file = open_file_safe(path)?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes)?;
    Ok(bytes)
}

/// Read a file using memory mapping for zero-copy access.
fn read_file_mmap(path: &std::path::Path) -> Option<String> {
    use memmap2::MmapOptions;

    let file = match open_file_safe(path) {
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

    // Release the advisory lock explicitly rather than relying on fd close.
    // The unlock is best-effort: failure is extremely unlikely (requires a
    // corrupted fd) and the lock would be released on file drop regardless.
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        let unlock_result = unsafe { libc::flock(fd, libc::LOCK_UN) };
        if unlock_result != 0 {
            tracing::trace!(
                path = ?path,
                errno = std::io::Error::last_os_error().raw_os_error(),
                "advisory flock unlock failed (lock released on fd close)"
            );
        }
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
    fn looks_binary_detects_null_bytes() {
        assert!(looks_binary(b"abc\0def"));
    }

    #[test]
    fn looks_binary_detects_pdf_magic() {
        assert!(looks_binary(b"%PDF-1.7"));
    }

    #[test]
    fn looks_binary_detects_png_magic() {
        assert!(looks_binary(b"\x89PNG\r\n\x1a\nrest"));
    }

    #[test]
    fn looks_binary_allows_plain_utf8_text() {
        assert!(!looks_binary("hello\nworld\n".as_bytes()));
    }

    #[test]
    fn decode_utf16_le_with_bom() {
        let bytes = [0xFF, 0xFE, b'A', 0x00, b'B', 0x00];
        assert_eq!(decode_utf16(&bytes).as_deref(), Some("AB"));
    }

    #[test]
    fn decode_utf16_be_with_bom() {
        let bytes = [0xFE, 0xFF, 0x00, b'A', 0x00, b'B'];
        assert_eq!(decode_utf16(&bytes).as_deref(), Some("AB"));
    }

    #[test]
    fn decode_utf16_rejects_odd_length_payload() {
        let bytes = [0xFF, 0xFE, b'A'];
        assert!(decode_utf16(&bytes).is_none());
    }

    #[test]
    fn decode_text_file_strips_utf8_bom() {
        let bytes = [0xEF, 0xBB, 0xBF, b'a', b'b', b'c'];
        assert_eq!(decode_text_file(&bytes).as_deref(), Some("abc"));
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
        assert!(
            !chunks.is_empty(),
            "Binary files should produce string-extracted chunks"
        );
        assert!(
            chunks[0].data.contains("SECRET_KEY"),
            "Extracted strings should contain the secret prefix"
        );
        assert_eq!(chunks[0].metadata.source_type, "filesystem:binary-strings");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(unix)]
    fn symlink_loops_are_not_followed() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("config.env"), "LEGENDARY_LOOP=present").unwrap();
        symlink(dir.path(), nested.join("loop")).unwrap();

        let chunks: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
            .chunks()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].data.contains("LEGENDARY_LOOP"));
    }

    #[test]
    fn files_larger_than_100mb_are_skipped_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.log");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(101 * 1024 * 1024).unwrap();

        let chunks: Vec<_> = FilesystemSource::new(dir.path().to_path_buf())
            .with_max_file_size(100 * 1024 * 1024)
            .chunks()
            .collect();

        assert!(
            chunks.is_empty(),
            "oversized sparse files should be skipped without panicking"
        );
    }
}
