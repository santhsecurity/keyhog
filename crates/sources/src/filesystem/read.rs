use memmap2::MmapOptions;
use std::fs::File;
use std::path::Path;

pub(super) fn read_file_buffered(path: &Path) -> Option<String> {
    let bytes = read_file_safe(path).ok()?;
    decode_text_file(&bytes)
}

fn open_file_safe(path: &Path) -> std::io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

pub(super) fn read_file_safe(path: &Path) -> std::io::Result<Vec<u8>> {
    #[cfg(target_os = "linux")]
    {
        if io_uring_available()
            && let Some(bytes) = read_file_io_uring(path)
        {
            return Ok(bytes);
        }
    }

    let mut file = open_file_safe(path)?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes)?;
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn io_uring_available() -> bool {
    use std::sync::OnceLock;
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        let kernel_ok = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .ok()
            .and_then(|s| {
                let parts: Vec<&str> = s.trim().split('.').collect();
                if parts.len() >= 2 {
                    let major = parts[0].parse::<u32>().ok()?;
                    let minor = parts[1].parse::<u32>().ok()?;
                    Some(major > 5 || (major == 5 && minor >= 1))
                } else {
                    None
                }
            })
            .unwrap_or(false);
        if !kernel_ok {
            return false;
        }
        io_uring::IoUring::new(1).is_ok()
    })
}

#[cfg(target_os = "linux")]
fn read_file_io_uring(path: &Path) -> Option<Vec<u8>> {
    use io_uring::{IoUring, opcode, types};
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::AsRawFd;

    let file = open_file_safe(path).ok()?;
    let size = file.metadata().ok()?.size() as usize;
    if size == 0 {
        return Some(Vec::new());
    }

    let mut uring = IoUring::new(1).ok()?;
    let mut buf = vec![0u8; size];

    let fd = types::Fd(file.as_raw_fd());
    let read_e = opcode::Read::new(fd, buf.as_mut_ptr(), size as u32)
        .offset(0)
        .build();

    unsafe {
        uring.submission().push(&read_e).ok()?;
    }

    uring.submit_and_wait(1).ok()?;

    let cqe = uring.completion().next()?;
    if cqe.result() < 0 {
        return None;
    }

    let read_len = cqe.result() as usize;
    buf.truncate(read_len);
    Some(buf)
}

pub(super) fn read_file_mmap(path: &Path) -> Option<String> {
    let file = open_file_safe(path).ok()?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        // SAFETY: Simple advisory lock FFI call.
        if unsafe { libc::flock(fd, libc::LOCK_SH | libc::LOCK_NB) } != 0 {
            return read_file_buffered(path);
        }
    }

    // SAFETY: the mapping is read-only, the `File` lives through the mapping
    // call, and we decode the bytes immediately without storing the mmap past
    // this function.
    let mmap = match unsafe { MmapOptions::new().map(&file) } {
        Ok(m) => m,
        Err(_) => return read_file_buffered(path),
    };

    let result = decode_text_file(&mmap);

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        // SAFETY: Simple advisory unlock FFI call.
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

    // Use lossy decoding to ensure we don't skip files with minor UTF-8 corruption.
    // This maximizes recall for secrets hidden near invalid bytes.
    Some(String::from_utf8_lossy(bytes).into_owned())
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
        .filter(|&&byte| byte < 0x20 && !matches!(byte, b'\n' | b'\r' | b'\t' | 0x0C))
        .count();
    suspicious * 20 > bytes.len().max(1)
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
