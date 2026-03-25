//! Binary analysis source: extract secrets from compiled executables.
//!
//! Two-tier approach:
//! 1. **Ghidra mode** (when `analyzeHeadless` is on PATH): runs Ghidra's headless
//!    analyzer + decompiler, parses decompiled C output for string literals, data
//!    section dumps, and cross-references. Catches secrets embedded in optimized code.
//! 2. **Strings mode** (fallback): extracts printable ASCII runs ≥ 8 chars from raw
//!    bytes. Fast but shallow — misses encoded or split secrets.
//!
//! The Ghidra integration is a runtime dependency, not compile-time.
//! `cargo build -F binary` pulls in `goblin` for format detection; Ghidra is optional.

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::Command;

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use wait_timeout::ChildExt;

/// Minimum printable string length for strings-mode extraction.
const MIN_STRING_LEN: usize = 8;

/// Maximum Ghidra analysis time before we kill the process.
const GHIDRA_TIMEOUT_SECS: u64 = 300;

/// Maximum decompiled output size we'll process (50 MB).
const MAX_DECOMPILED_SIZE: u64 = 50 * 1024 * 1024;

pub struct BinarySource {
    path: PathBuf,
    ghidra_path: Option<PathBuf>,
}

impl BinarySource {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let ghidra_path = find_ghidra_headless();
        Self {
            path: path.into(),
            ghidra_path,
        }
    }

    /// Explicitly set the Ghidra analyzeHeadless path.
    pub fn with_ghidra(mut self, ghidra_path: PathBuf) -> Self {
        self.ghidra_path = Some(ghidra_path);
        self
    }

    /// Force strings-only mode (skip Ghidra even if available).
    pub fn strings_only(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            ghidra_path: None,
        }
    }

    fn ghidra_chunks(&self, ghidra_bin: &Path) -> Result<Vec<Chunk>, SourceError> {
        let tmp_dir = tempfile::tempdir().map_err(SourceError::Io)?;
        let project_dir = tmp_dir.path().join("ghidra_project");
        std::fs::create_dir_all(&project_dir).map_err(SourceError::Io)?;

        let script_path = tmp_dir.path().join("ExportDecompiled.java");
        let output_path = tmp_dir.path().join("decompiled.c");
        write_ghidra_script(&script_path, &output_path)?;

        let status = Command::new(ghidra_bin)
            .arg(&project_dir)
            .arg("keyhog_analysis")
            .arg("-import")
            .arg(&self.path)
            .arg("-postScript")
            .arg(&script_path)
            .arg("-deleteProject")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .and_then(|mut child| {
                let timeout = std::time::Duration::from_secs(GHIDRA_TIMEOUT_SECS);
                match child
                    .wait_timeout(timeout)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
                {
                    Some(status) => Ok(status),
                    None => {
                        let _ = child.kill();
                        let _ = child.wait();
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!("Ghidra analysis timed out after {GHIDRA_TIMEOUT_SECS}s"),
                        ))
                    }
                }
            });

        match status {
            Ok(s) if s.success() && output_path.exists() => {
                self.parse_decompiled_output(&output_path)
            }
            Ok(_) | Err(_) => {
                tracing::debug!(
                    path = %self.path.display(),
                    "Ghidra analysis failed or produced no output, falling back to strings"
                );
                Ok(self.strings_chunks())
            }
        }
    }

    fn parse_decompiled_output(&self, output_path: &Path) -> Result<Vec<Chunk>, SourceError> {
        let metadata = std::fs::metadata(output_path).map_err(SourceError::Io)?;
        if metadata.len() > MAX_DECOMPILED_SIZE {
            tracing::warn!(
                path = %self.path.display(),
                size = metadata.len(),
                "Decompiled output too large, falling back to strings"
            );
            return Ok(self.strings_chunks());
        }

        let file = std::fs::File::open(output_path).map_err(SourceError::Io)?;
        let reader = std::io::BufReader::new(file);

        let mut decompiled_text = String::new();
        let mut string_literals = Vec::new();

        for line in reader.lines() {
            let line = line.map_err(SourceError::Io)?;
            decompiled_text.push_str(&line);
            decompiled_text.push('\n');

            // Extract string literals from decompiled C code
            extract_string_literals(&line, &mut string_literals);
        }

        let mut chunks = Vec::new();

        // Chunk 1: full decompiled output (for pattern matching on variable names, etc.)
        if !decompiled_text.is_empty() {
            chunks.push(Chunk {
                data: decompiled_text,
                metadata: ChunkMetadata {
                    source_type: "binary:ghidra:decompiled".to_string(),
                    path: Some(self.path.display().to_string()),
                    commit: None,
                    author: None,
                    date: None,
                },
            });
        }

        // Chunk 2: extracted string literals (higher signal, less noise)
        if !string_literals.is_empty() {
            chunks.push(Chunk {
                data: string_literals.join("\n"),
                metadata: ChunkMetadata {
                    source_type: "binary:ghidra:strings".to_string(),
                    path: Some(self.path.display().to_string()),
                    commit: None,
                    author: None,
                    date: None,
                },
            });
        }

        // Also run basic strings extraction for anything Ghidra might miss
        let strings_chunk = self.strings_chunks();
        chunks.extend(strings_chunk);

        Ok(chunks)
    }

    fn strings_chunks(&self) -> Vec<Chunk> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };

        let mut chunks = Vec::new();
        let path_str = self.path.display().to_string();

        // Try section-aware extraction using goblin (ELF/PE/Mach-O)
        #[cfg(feature = "binary")]
        {
            if let Some(section_chunks) = extract_sections(&bytes, &path_str) {
                chunks.extend(section_chunks);
            }
        }

        // Always do full strings extraction as fallback/supplement
        let strings = extract_printable_strings(&bytes, MIN_STRING_LEN);
        if !strings.is_empty() {
            chunks.push(Chunk {
                data: strings.join("\n"),
                metadata: ChunkMetadata {
                    source_type: "binary:strings".to_string(),
                    path: Some(path_str),
                    commit: None,
                    author: None,
                    date: None,
                },
            });
        }

        chunks
    }
}

impl Source for BinarySource {
    fn name(&self) -> &str {
        "binary"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        let result = if let Some(ghidra_bin) = &self.ghidra_path {
            self.ghidra_chunks(ghidra_bin)
        } else {
            Ok(self.strings_chunks())
        };

        match result {
            Ok(chunks) => Box::new(chunks.into_iter().map(Ok)),
            Err(e) => Box::new(std::iter::once(Err(e))),
        }
    }
}

/// Search standard locations for Ghidra's `analyzeHeadless` script.
fn find_ghidra_headless() -> Option<PathBuf> {
    // Check GHIDRA_HOME env var first
    if let Ok(home) = std::env::var("GHIDRA_HOME") {
        let path = PathBuf::from(&home).join("support").join("analyzeHeadless");
        if path.exists() {
            return Some(path);
        }
    }

    // Check PATH
    if let Ok(output) = Command::new("which").arg("analyzeHeadless").output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }

    // Common installation paths
    for pattern in &[
        "/opt/ghidra*/support/analyzeHeadless",
        "/usr/share/ghidra/support/analyzeHeadless",
        "/usr/local/share/ghidra/support/analyzeHeadless",
    ] {
        for entry in glob::glob(pattern).into_iter().flatten().flatten() {
            if entry.exists() {
                return Some(entry);
            }
        }
    }

    None
}

/// Write a Ghidra postScript that runs analysis and exports decompiled C.
fn write_ghidra_script(script_path: &Path, output_path: &Path) -> Result<(), SourceError> {
    let script = format!(
        r#"// KeyHog Ghidra export script — runs full analysis then decompiles all functions.
// @category KeyHog
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.FileWriter;
import java.io.PrintWriter;

public class ExportDecompiled extends GhidraScript {{
    @Override
    public void run() throws Exception {{
        // Run full analysis first
        analyzeAll(currentProgram);

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        PrintWriter writer = new PrintWriter(new FileWriter("{output}"));

        // Export all string data from the program
        var dataIterator = currentProgram.getListing().getDefinedData(true);
        while (dataIterator.hasNext()) {{
            var data = dataIterator.next();
            if (data.hasStringValue()) {{
                writer.println("// DATA @ " + data.getAddress() + ": " + data.getValue());
            }}
        }}

        // Decompile all functions
        FunctionIterator funcs = currentProgram.getListing().getFunctions(true);
        while (funcs.hasNext()) {{
            Function func = funcs.next();
            DecompileResults results = decomp.decompileFunction(func, 30, monitor);
            if (results != null && results.decompileCompleted()) {{
                String decompiled = results.getDecompiledFunction().getC();
                if (decompiled != null) {{
                    writer.println("// FUNCTION: " + func.getName() + " @ " + func.getEntryPoint());
                    writer.println(decompiled);
                    writer.println();
                }}
            }}
        }}

        decomp.dispose();
        writer.close();
    }}
}}
"#,
        // Escape the path for Java string literal: backslashes and quotes must
        // be doubled/escaped so the generated Java source compiles correctly.
        output = output_path
            .display()
            .to_string()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    );

    std::fs::write(script_path, script).map_err(SourceError::Io)
}

/// Extract C string literals from a line of decompiled code.
fn extract_string_literals(line: &str, out: &mut Vec<String>) {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            i += 1;
            let start = i;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' {
                    i += 1; // skip escaped char
                }
                i += 1;
            }
            if i > start + MIN_STRING_LEN {
                // Unescape basic C escapes
                let raw = &line[start..i.min(line.len())];
                let unescaped = unescape_c_string(raw);
                if unescaped.len() >= MIN_STRING_LEN {
                    out.push(unescaped);
                }
            }
            i += 1; // skip closing quote
        } else {
            i += 1;
        }
    }
}

fn unescape_c_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => result.push('\n'),
                Some('t') => result.push('\t'),
                Some('r') => result.push('\r'),
                Some('\\') => result.push('\\'),
                Some('"') => result.push('"'),
                Some('0') => result.push('\0'),
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        } else {
            result.push(c);
        }
    }
    result
}

pub(crate) fn extract_printable_strings(bytes: &[u8], min_len: usize) -> Vec<String> {
    crate::strings::extract_printable_strings(bytes, min_len)
}

/// Extract strings from specific binary sections (ELF .rodata/.data, PE .rdata/.data).
/// These sections are the most likely to contain embedded secrets.
#[cfg(feature = "binary")]
fn extract_sections(bytes: &[u8], path: &str) -> Option<Vec<Chunk>> {
    use goblin::Object;

    let obj = match Object::parse(bytes) {
        Ok(o) => o,
        Err(_) => return None,
    };

    let mut chunks = Vec::new();

    // High-value section names where secrets are commonly embedded
    let target_sections = &[
        ".rodata",
        ".rdata",
        ".data",
        ".const",
        ".cstring",
        "__cstring",
        "__const",
        "__data",
    ];

    match obj {
        Object::Elf(elf) => {
            for sh in &elf.section_headers {
                let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("");
                if target_sections.iter().any(|t| name == *t) {
                    let start = sh.sh_offset as usize;
                    let end = (start + sh.sh_size as usize).min(bytes.len());
                    if start < end {
                        let section_bytes = &bytes[start..end];
                        let strings = extract_printable_strings(section_bytes, MIN_STRING_LEN);
                        if !strings.is_empty() {
                            chunks.push(Chunk {
                                data: strings.join("\n"),
                                metadata: ChunkMetadata {
                                    source_type: format!("binary:elf:{name}"),
                                    path: Some(path.to_string()),
                                    commit: None,
                                    author: None,
                                    date: None,
                                },
                            });
                        }
                    }
                }
            }
        }
        Object::PE(pe) => {
            for section in &pe.sections {
                let name = std::str::from_utf8(&section.name)
                    .unwrap_or("")
                    .trim_end_matches('\0');
                if target_sections.iter().any(|t| name == *t) {
                    let start = section.pointer_to_raw_data as usize;
                    let end = (start + section.size_of_raw_data as usize).min(bytes.len());
                    if start < end {
                        let section_bytes = &bytes[start..end];
                        let strings = extract_printable_strings(section_bytes, MIN_STRING_LEN);
                        if !strings.is_empty() {
                            chunks.push(Chunk {
                                data: strings.join("\n"),
                                metadata: ChunkMetadata {
                                    source_type: format!("binary:pe:{name}"),
                                    path: Some(path.to_string()),
                                    commit: None,
                                    author: None,
                                    date: None,
                                },
                            });
                        }
                    }
                }
            }
        }
        Object::Mach(mach) => {
            if let goblin::mach::Mach::Binary(macho) = mach {
                for seg in &macho.segments {
                    for (section, _) in seg.sections().unwrap_or_default() {
                        let name = section.name().unwrap_or("");
                        if target_sections.iter().any(|t| name == *t) {
                            let start = section.offset as usize;
                            let end = (start + section.size as usize).min(bytes.len());
                            if start < end {
                                let section_bytes = &bytes[start..end];
                                let strings =
                                    extract_printable_strings(section_bytes, MIN_STRING_LEN);
                                if !strings.is_empty() {
                                    chunks.push(Chunk {
                                        data: strings.join("\n"),
                                        metadata: ChunkMetadata {
                                            source_type: format!("binary:macho:{name}"),
                                            path: Some(path.to_string()),
                                            commit: None,
                                            author: None,
                                            date: None,
                                        },
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    if chunks.is_empty() {
        None
    } else {
        Some(chunks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_printable_strings_from_bytes() {
        let data = b"\x00\x00Hello World\x00\x00SecretKey123\x00\x01\x02";
        let strings = extract_printable_strings(data, 8);
        assert!(strings.iter().any(|s| s.contains("Hello World")));
        assert!(strings.iter().any(|s| s.contains("SecretKey123")));
    }

    #[test]
    fn skip_short_strings() {
        let data = b"\x00abc\x00longerstringhere\x00xy\x00";
        let strings = extract_printable_strings(data, 8);
        assert!(strings.iter().all(|s| s.len() >= 8));
        assert!(strings.iter().any(|s| s.contains("longerstringhere")));
    }

    #[test]
    fn empty_input() {
        let strings = extract_printable_strings(b"", 8);
        assert!(strings.is_empty());
    }

    #[test]
    fn all_binary_no_strings() {
        let data: Vec<u8> = (0..100).map(|i| (i % 32) as u8).collect();
        let strings = extract_printable_strings(&data, 8);
        assert!(strings.is_empty());
    }

    #[test]
    fn extract_c_string_literals() {
        let mut out = Vec::new();
        extract_string_literals(
            r#"char *key = "sk-proj-kR4vN8pW2cF6gH0jL3mQsT7u";"#,
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("sk-proj-"));
    }

    #[test]
    fn extract_escaped_c_strings() {
        let mut out = Vec::new();
        extract_string_literals(
            r#"printf("secret: %s\n", "AKIA1234567890ABCDEF");"#,
            &mut out,
        );
        assert!(out.iter().any(|s| s.contains("AKIA")));
    }

    #[test]
    fn unescape_basic_sequences() {
        assert_eq!(unescape_c_string(r"hello\nworld"), "hello\nworld");
        assert_eq!(unescape_c_string(r"tab\there"), "tab\there");
        assert_eq!(unescape_c_string("quote\\\"end"), "quote\"end");
    }

    #[test]
    fn ghidra_not_found_returns_none() {
        // With an invalid GHIDRA_HOME, find should still return None gracefully
        std::env::remove_var("GHIDRA_HOME");
        // find_ghidra_headless should not panic
        let _ = find_ghidra_headless();
    }

    #[test]
    fn binary_source_strings_only_mode() {
        // Create a temp file with embedded strings
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(
            tmp.path(),
            b"\x00\x00AKIA1234567890ABCDEF\x00\x00ghp_realTokenValue12345678901234\x00\x00",
        )
        .unwrap();

        let source = BinarySource::strings_only(tmp.path());
        let chunks: Vec<_> = source.chunks().collect();
        assert!(!chunks.is_empty());
        let chunk = chunks[0].as_ref().unwrap();
        assert!(chunk.data.contains("AKIA"));
        assert_eq!(chunk.metadata.source_type, "binary:strings");
    }
}
