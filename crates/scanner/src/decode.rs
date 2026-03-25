//! Decode-through scanning: decode base64 and hex strings before pattern matching.
//!
//! Catches secrets hidden behind encoding layers — Kubernetes manifests,
//! CI/CD configs, hex-encoded credentials.

/// Decoding layer: decode base64 and hex strings before pattern matching.
/// Catches secrets hidden behind encoding (evasion technique).
use crate::context;
use keyhog_core::{Chunk, ChunkMetadata};
use std::collections::{HashSet, VecDeque};

/// A trait for decoding chunks to find hidden secrets.
pub trait Decoder: Send + Sync {
    fn name(&self) -> &'static str;
    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk>;
}

struct Base64Decoder;
impl Decoder for Base64Decoder {
    fn name(&self) -> &'static str {
        "base64"
    }
    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        let mut decoded_chunks = Vec::new();
        let lines: Vec<&str> = chunk.data.lines().collect();
        for (line_idx, line) in lines.iter().enumerate() {
            if context::is_false_positive_context(&lines, line_idx, chunk.metadata.path.as_deref())
            {
                continue;
            }
            for b64_match in find_base64_strings(line, 20) {
                match base64_decode(&b64_match.value) {
                    Ok(decoded) => match String::from_utf8(decoded) {
                        Ok(text)
                            if text.chars().all(|c| {
                                !c.is_control() || c == '\n' || c == '\r' || c == '\t'
                            }) =>
                        {
                            decoded_chunks.push(Chunk {
                                data: text,
                                metadata: ChunkMetadata {
                                    source_type: format!("{}/base64", chunk.metadata.source_type),
                                    path: chunk.metadata.path.clone(),
                                    commit: chunk.metadata.commit.clone(),
                                    author: chunk.metadata.author.clone(),
                                    date: chunk.metadata.date.clone(),
                                },
                            });
                        }
                        Ok(_) => {
                            tracing::trace!(
                                path = ?chunk.metadata.path,
                                "base64 decoded to text with control characters, skipping"
                            );
                        }
                        Err(_) => {
                            tracing::trace!(
                                path = ?chunk.metadata.path,
                                "base64 decoded to non-UTF-8 bytes, skipping"
                            );
                        }
                    },
                    Err(()) => {
                        tracing::trace!(
                            path = ?chunk.metadata.path,
                            candidate_len = b64_match.value.len(),
                            "base64 decode failed for candidate"
                        );
                    }
                }
            }
        }
        decoded_chunks
    }
}

struct HexDecoder;
impl Decoder for HexDecoder {
    fn name(&self) -> &'static str {
        "hex"
    }
    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        let mut decoded_chunks = Vec::new();
        for hex_match in find_hex_strings(&chunk.data, 40) {
            if let Ok(decoded) = hex_decode(&hex_match.value)
                && let Ok(text) = String::from_utf8(decoded)
                && text
                    .chars()
                    .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t')
            {
                decoded_chunks.push(Chunk {
                    data: text,
                    metadata: ChunkMetadata {
                        source_type: format!("{}/hex", chunk.metadata.source_type),
                        path: chunk.metadata.path.clone(),
                        commit: chunk.metadata.commit.clone(),
                        author: chunk.metadata.author.clone(),
                        date: chunk.metadata.date.clone(),
                    },
                });
            }
        }
        decoded_chunks
    }
}

struct UrlDecoder;
impl Decoder for UrlDecoder {
    fn name(&self) -> &'static str {
        "url"
    }
    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        decode_candidates(
            chunk,
            extract_encoded_values(&chunk.data)
                .into_iter()
                .filter(|candidate| candidate.contains('%'))
                .collect(),
            url_decode,
            self.name(),
        )
    }
}

struct QuotedPrintableDecoder;
impl Decoder for QuotedPrintableDecoder {
    fn name(&self) -> &'static str {
        "quoted-printable"
    }
    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        let mut decoded_chunks = Vec::new();
        let lines: Vec<&str> = chunk.data.lines().collect();
        for (line_idx, line) in lines.iter().enumerate() {
            if context::is_false_positive_context(&lines, line_idx, chunk.metadata.path.as_deref())
            {
                continue;
            }
            let mut candidates = extract_encoded_values(line);
            let trimmed = line.trim();
            if trimmed.contains('=') && !trimmed.is_empty() {
                candidates.push(trimmed.to_string());
            }
            decoded_chunks.extend(decode_candidates(
                chunk,
                candidates
                    .into_iter()
                    .filter(|candidate| candidate.contains('='))
                    .collect(),
                quoted_printable_decode,
                self.name(),
            ));
        }
        decoded_chunks
    }
}

struct HtmlNamedEntityDecoder;
impl Decoder for HtmlNamedEntityDecoder {
    fn name(&self) -> &'static str {
        "html-named-entity"
    }
    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        let mut candidates = extract_encoded_values(&chunk.data);
        let trimmed = chunk.data.trim();
        if trimmed.contains('&') && !trimmed.is_empty() {
            candidates.push(trimmed.to_string());
        }
        decode_candidates(
            chunk,
            candidates
                .into_iter()
                .filter(|candidate| candidate.contains('&'))
                .collect(),
            html_named_entity_decode,
            self.name(),
        )
    }
}

struct HtmlNumericEntityDecoder;
impl Decoder for HtmlNumericEntityDecoder {
    fn name(&self) -> &'static str {
        "html-numeric-entity"
    }
    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        let mut candidates = extract_encoded_values(&chunk.data);
        let trimmed = chunk.data.trim();
        if trimmed.contains("&#") && !trimmed.is_empty() {
            candidates.push(trimmed.to_string());
        }
        decode_candidates(
            chunk,
            candidates
                .into_iter()
                .filter(|candidate| candidate.contains("&#"))
                .collect(),
            html_numeric_entity_decode,
            self.name(),
        )
    }
}

struct HexEscapeDecoder;
impl Decoder for HexEscapeDecoder {
    fn name(&self) -> &'static str {
        "hex-escape"
    }
    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        let mut candidates = extract_encoded_values(&chunk.data);
        let trimmed = chunk.data.trim();
        if trimmed.contains("\\x") && !trimmed.is_empty() {
            candidates.push(trimmed.to_string());
        }
        decode_candidates(
            chunk,
            candidates
                .into_iter()
                .filter(|candidate| candidate.contains("\\x"))
                .collect(),
            hex_escape_decode,
            self.name(),
        )
    }
}

struct OctalEscapeDecoder;
impl Decoder for OctalEscapeDecoder {
    fn name(&self) -> &'static str {
        "octal-escape"
    }
    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        let mut candidates = extract_encoded_values(&chunk.data);
        let trimmed = chunk.data.trim();
        if trimmed.contains('\\') && !trimmed.is_empty() {
            candidates.push(trimmed.to_string());
        }
        decode_candidates(
            chunk,
            candidates
                .into_iter()
                .filter(|candidate| contains_octal_escape(candidate))
                .collect(),
            octal_escape_decode,
            self.name(),
        )
    }
}

struct MimeEncodedWordDecoder;
impl Decoder for MimeEncodedWordDecoder {
    fn name(&self) -> &'static str {
        "mime-encoded-word"
    }
    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        let mut candidates = Vec::new();
        for line in chunk.data.lines() {
            candidates.extend(find_mime_encoded_words(line));
        }
        decode_candidates(chunk, candidates, mime_encoded_word_decode, self.name())
    }
}

struct UnicodeEscapeDecoder;
impl Decoder for UnicodeEscapeDecoder {
    fn name(&self) -> &'static str {
        "unicode-escape"
    }
    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        decode_candidates(
            chunk,
            extract_encoded_values(&chunk.data)
                .into_iter()
                .filter(|candidate| candidate.contains("\\u") || candidate.contains("\\x"))
                .collect(),
            unicode_escape_decode,
            self.name(),
        )
    }
}

static DECODERS: std::sync::OnceLock<std::sync::RwLock<Vec<Box<dyn Decoder>>>> =
    std::sync::OnceLock::new();

fn get_decoders() -> &'static std::sync::RwLock<Vec<Box<dyn Decoder>>> {
    DECODERS.get_or_init(|| {
        std::sync::RwLock::new(vec![
            Box::new(Base64Decoder),
            Box::new(HexDecoder),
            Box::new(UrlDecoder),
            Box::new(QuotedPrintableDecoder),
            Box::new(HtmlNamedEntityDecoder),
            Box::new(HtmlNumericEntityDecoder),
            Box::new(HexEscapeDecoder),
            Box::new(OctalEscapeDecoder),
            Box::new(MimeEncodedWordDecoder),
            Box::new(UnicodeEscapeDecoder),
        ])
    })
}

/// Register a custom decoder that participates in decode-through scanning.
pub fn register_decoder(decoder: Box<dyn Decoder>) {
    let mut registry = get_decoders()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    registry.push(decoder);
}

/// Maximum decode recursion depth. Two levels handle the common case of
/// `base64(hex(secret))` or `hex(base64(secret))`. Higher depths are
/// theoretically possible but:
///   - Real-world triple-encoding is vanishingly rare in codebases.
///   - Each level multiplies the candidate set combinatorially.
///   - The `seen` dedup set prevents repeat work, but O(candidates²) growth
///     still makes depth > 2 impractical for large chunks.
///
/// Attackers who triple-encode to evade scanners will also evade TruffleHog,
/// Semgrep, and every other current-generation scanner.
const MAX_DECODE_DEPTH: usize = 2;

/// Decode base64, hex, URL, and other encoded strings in a chunk, producing
/// additional chunks with decoded content for scanning.
///
/// Uses BFS with deduplication to avoid redundant decode–re-decode cycles.
/// The search is bounded by [`MAX_DECODE_DEPTH`] to prevent combinatorial
/// explosion on pathological inputs.
pub fn decode_chunk(chunk: &Chunk) -> Vec<Chunk> {
    let mut decoded_chunks = Vec::new();
    let mut queue = VecDeque::from([(chunk.clone(), 0usize)]);
    let mut seen = HashSet::from([chunk.data.clone()]);
    let registry = get_decoders()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    while let Some((current, depth)) = queue.pop_front() {
        if depth >= MAX_DECODE_DEPTH {
            continue;
        }
        for decoder in registry.iter() {
            for decoded in decoder.decode_chunk(&current) {
                if seen.insert(decoded.data.clone()) {
                    queue.push_back((decoded.clone(), depth + 1));
                    decoded_chunks.push(decoded);
                }
            }
        }
    }
    decoded_chunks
}

struct EncodedString {
    value: String,
}

/// Find base64-encoded strings in text (minimum length, valid base64 charset).
fn find_base64_strings(text: &str, min_length: usize) -> Vec<EncodedString> {
    let mut results = Vec::new();
    let b64_chars = |c: char| {
        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'
    };

    for line in text.lines() {
        // Look for base64 after = or : or in quotes
        let candidates = extract_encoded_values(line);
        for candidate in candidates {
            if candidate.len() >= min_length
                && candidate.chars().all(b64_chars)
                && classify_base64(candidate.as_str()).is_some()
            {
                results.push(EncodedString { value: candidate });
            }
        }
    }

    results
}

/// Find hex-encoded strings (even length, all hex chars, minimum length).
fn find_hex_strings(text: &str, min_length: usize) -> Vec<EncodedString> {
    let mut results = Vec::new();

    for line in text.lines() {
        let candidates = extract_encoded_values(line);
        for candidate in candidates {
            if candidate.len() >= min_length
                && candidate.len() % 2 == 0
                && candidate.chars().all(|c| c.is_ascii_hexdigit())
            {
                results.push(EncodedString { value: candidate });
            }
        }
    }

    results
}

/// Extract potential encoded values from a line (after =, :, or in quotes).
fn extract_encoded_values(line: &str) -> Vec<String> {
    let mut values = Vec::new();

    // After : or = (try : first — it's the YAML/JSON key-value separator
    // and won't match inside base64 padding like = does)
    if let Some(pos) = line.find(':').or_else(|| line.find('=')) {
        let candidate_value = line[pos + 1..]
            .trim()
            .trim_matches(|c: char| c == '"' || c == '\'' || c == '`');
        if !candidate_value.is_empty() {
            values.push(candidate_value.to_string());
        }
    }

    // Quoted strings
    for quote in ['"', '\''] {
        let mut start = None;
        for (i, ch) in line.char_indices() {
            if ch == quote {
                match start {
                    None => start = Some(i + 1),
                    Some(s) => {
                        let content = &line[s..i];
                        if !content.is_empty() {
                            values.push(content.to_string());
                        }
                        start = None;
                    }
                }
            }
        }
    }

    values
}

#[derive(Clone, Copy)]
enum Base64Variant {
    Standard,
    StandardNoPad,
    UrlSafe,
    UrlSafeNoPad,
}

fn classify_base64(candidate: &str) -> Option<Base64Variant> {
    if !has_valid_base64_padding(candidate) {
        return None;
    }

    let has_standard = candidate.contains('+') || candidate.contains('/');
    let has_urlsafe = candidate.contains('-') || candidate.contains('_');
    if has_standard && has_urlsafe {
        return None;
    }

    let padded = candidate.contains('=');
    match (has_urlsafe, padded, candidate.len() % 4) {
        (_, true, 0) => Some(if has_urlsafe {
            Base64Variant::UrlSafe
        } else {
            Base64Variant::Standard
        }),
        (_, true, _) => None,
        (_, false, 1) => None,
        (true, false, _) => Some(Base64Variant::UrlSafeNoPad),
        (false, false, 0) => Some(Base64Variant::Standard),
        (false, false, _) => Some(Base64Variant::StandardNoPad),
    }
}

fn has_valid_base64_padding(candidate: &str) -> bool {
    let first_padding = match candidate.find('=') {
        Some(index) => index,
        None => return true,
    };

    let padding = &candidate[first_padding..];
    first_padding > 0
        && padding.len() <= 2
        && padding.bytes().all(|byte| byte == b'=')
        && candidate[..first_padding].bytes().all(|byte| byte != b'=')
}

fn base64_decode(input: &str) -> Result<Vec<u8>, ()> {
    use base64::{Engine, engine::general_purpose};

    let variant = classify_base64(input).ok_or(())?;
    match variant {
        Base64Variant::Standard => general_purpose::STANDARD.decode(input),
        Base64Variant::StandardNoPad => general_purpose::STANDARD_NO_PAD.decode(input),
        Base64Variant::UrlSafe => general_purpose::URL_SAFE.decode(input),
        Base64Variant::UrlSafeNoPad => general_purpose::URL_SAFE_NO_PAD.decode(input),
    }
    .map_err(|_| ())
}

fn hex_decode(input: &str) -> Result<Vec<u8>, ()> {
    if !input.len().is_multiple_of(2) {
        return Err(());
    }
    let mut decoded_bytes = Vec::with_capacity(input.len() / 2);
    for offset in (0..input.len()).step_by(2) {
        let high = hex_val(input.as_bytes()[offset])?;
        let low = hex_val(input.as_bytes()[offset + 1])?;
        decoded_bytes.push((high << 4) | low);
    }
    Ok(decoded_bytes)
}

fn hex_val(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

fn decode_candidates<F>(
    chunk: &Chunk,
    candidates: Vec<String>,
    mut decode: F,
    decoder_name: &str,
) -> Vec<Chunk>
where
    F: FnMut(&str) -> Result<String, ()>,
{
    let mut decoded_chunks = Vec::new();
    for candidate in candidates {
        if let Ok(text) = decode(&candidate)
            && !text.is_empty()
            && text
                .chars()
                .all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t')
        {
            decoded_chunks.push(Chunk {
                data: text,
                metadata: ChunkMetadata {
                    source_type: format!("{}/{}", chunk.metadata.source_type, decoder_name),
                    path: chunk.metadata.path.clone(),
                    commit: chunk.metadata.commit.clone(),
                    author: chunk.metadata.author.clone(),
                    date: chunk.metadata.date.clone(),
                },
            });
        }
    }
    decoded_chunks
}

fn percent_decode(input: &str) -> Result<String, ()> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut i = 0;
    let input_bytes = input.as_bytes();
    while i < input_bytes.len() {
        match input_bytes[i] {
            b'%' if i + 2 < input_bytes.len() => {
                let high = hex_val(input_bytes[i + 1])?;
                let low = hex_val(input_bytes[i + 2])?;
                bytes.push((high << 4) | low);
                i += 3;
            }
            byte => {
                bytes.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(bytes).map_err(|_| ())
}

fn url_decode(input: &str) -> Result<String, ()> {
    let decoded = percent_decode(input)?;
    if contains_percent_escape(&decoded) {
        percent_decode(&decoded)
    } else {
        Ok(decoded)
    }
}

fn contains_percent_escape(input: &str) -> bool {
    input
        .as_bytes()
        .windows(3)
        .any(|window| window[0] == b'%' && hex_val(window[1]).is_ok() && hex_val(window[2]).is_ok())
}

fn quoted_printable_decode(input: &str) -> Result<String, ()> {
    let mut bytes = Vec::with_capacity(input.len());
    let mut i = 0;
    let input_bytes = input.as_bytes();
    while i < input_bytes.len() {
        match input_bytes[i] {
            b'=' if i + 2 < input_bytes.len() => {
                if input_bytes[i + 1] == b'\r' && input_bytes[i + 2] == b'\n' {
                    i += 3;
                    continue;
                }
                let high = hex_val(input_bytes[i + 1])?;
                let low = hex_val(input_bytes[i + 2])?;
                bytes.push((high << 4) | low);
                i += 3;
            }
            byte => {
                bytes.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8(bytes).map_err(|_| ())
}

fn html_named_entity_decode(input: &str) -> Result<String, ()> {
    let mut decoded = String::with_capacity(input.len());
    let mut changed = false;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '&' {
            decoded.push(ch);
            continue;
        }

        let mut entity = String::new();
        while let Some(&next) = chars.peek() {
            entity.push(next);
            chars.next();
            if next == ';' || entity.len() > 10 {
                break;
            }
        }

        let replacement = match entity.as_str() {
            "amp;" => Some('&'),
            "lt;" => Some('<'),
            "gt;" => Some('>'),
            "quot;" => Some('"'),
            "apos;" => Some('\''),
            "nbsp;" => Some('\u{00A0}'),
            _ => None,
        };

        if let Some(replacement) = replacement {
            decoded.push(replacement);
            changed = true;
        } else {
            decoded.push('&');
            decoded.push_str(&entity);
        }
    }

    changed.then_some(decoded).ok_or(())
}

fn html_numeric_entity_decode(input: &str) -> Result<String, ()> {
    let mut decoded = String::with_capacity(input.len());
    let mut changed = false;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '&' || chars.peek() != Some(&'#') {
            decoded.push(ch);
            continue;
        }

        chars.next();
        let is_hex = matches!(chars.peek(), Some('x') | Some('X'));
        if is_hex {
            chars.next();
        }

        let mut digits = String::new();
        while let Some(&next) = chars.peek() {
            if next == ';' {
                chars.next();
                break;
            }
            if (is_hex && next.is_ascii_hexdigit()) || (!is_hex && next.is_ascii_digit()) {
                digits.push(next);
                chars.next();
            } else {
                decoded.push('&');
                decoded.push('#');
                if is_hex {
                    decoded.push('x');
                }
                decoded.push_str(&digits);
                decoded.push(next);
                chars.next();
                digits.clear();
                break;
            }
        }

        if digits.is_empty() {
            decoded.push('&');
            decoded.push('#');
            if is_hex {
                decoded.push('x');
            }
            continue;
        }

        let radix = if is_hex { 16 } else { 10 };
        let code = u32::from_str_radix(&digits, radix).map_err(|_| ())?;
        let replacement = char::from_u32(code).ok_or(())?;
        decoded.push(replacement);
        changed = true;
    }

    changed.then_some(decoded).ok_or(())
}

fn hex_escape_decode(input: &str) -> Result<String, ()> {
    let mut decoded = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut changed = false;

    while let Some(ch) = chars.next() {
        if ch != '\\' || chars.peek() != Some(&'x') {
            decoded.push(ch);
            continue;
        }

        chars.next();
        let high = chars.next().ok_or(())?.to_digit(16).ok_or(())?;
        let low = chars.next().ok_or(())?.to_digit(16).ok_or(())?;
        let byte = ((high << 4) | low) as u8;
        decoded.push(char::from(byte));
        changed = true;
    }

    changed.then_some(decoded).ok_or(())
}

fn octal_escape_decode(input: &str) -> Result<String, ()> {
    let mut decoded = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut changed = false;

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded.push(ch);
            continue;
        }

        let Some(&next) = chars.peek() else {
            return Err(());
        };
        if !('0'..='7').contains(&next) {
            decoded.push(ch);
            continue;
        }

        let mut value = 0u8;
        for _ in 0..3 {
            let digit = chars.next().ok_or(())?;
            let digit = digit.to_digit(8).ok_or(())? as u8;
            value = (value << 3) | digit;
        }
        decoded.push(char::from(value));
        changed = true;
    }

    changed.then_some(decoded).ok_or(())
}

fn contains_octal_escape(input: &str) -> bool {
    let bytes = input.as_bytes();
    bytes.windows(4).any(|window| {
        window[0] == b'\\'
            && (b'0'..=b'7').contains(&window[1])
            && (b'0'..=b'7').contains(&window[2])
            && (b'0'..=b'7').contains(&window[3])
    })
}

fn mime_encoded_word_decode(input: &str) -> Result<String, ()> {
    if !input.starts_with("=?") || !input.ends_with("?=") {
        return Err(());
    }

    let inner = &input[2..input.len() - 2];
    let mut parts = inner.splitn(3, '?');
    let _charset = parts.next().ok_or(())?;
    let encoding = parts.next().ok_or(())?;
    let encoded = parts.next().ok_or(())?;

    let bytes = match encoding {
        "B" | "b" => base64_decode(encoded)?,
        "Q" | "q" => mime_q_decode(encoded)?,
        _ => return Err(()),
    };

    String::from_utf8(bytes).map_err(|_| ())
}

fn mime_q_decode(input: &str) -> Result<Vec<u8>, ()> {
    let normalized = input.replace('_', " ");
    let mut bytes = Vec::with_capacity(normalized.len());
    let mut i = 0;
    let input_bytes = normalized.as_bytes();

    while i < input_bytes.len() {
        match input_bytes[i] {
            b'=' if i + 2 < input_bytes.len() => {
                let high = hex_val(input_bytes[i + 1])?;
                let low = hex_val(input_bytes[i + 2])?;
                bytes.push((high << 4) | low);
                i += 3;
            }
            byte => {
                bytes.push(byte);
                i += 1;
            }
        }
    }

    Ok(bytes)
}

fn find_mime_encoded_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut offset = 0;

    while let Some(start) = line[offset..].find("=?") {
        let absolute_start = offset + start;
        if let Some(end) = line[absolute_start + 2..].find("?=") {
            let absolute_end = absolute_start + 2 + end + 2;
            words.push(line[absolute_start..absolute_end].to_string());
            offset = absolute_end;
        } else {
            break;
        }
    }

    words
}

fn unicode_escape_decode(input: &str) -> Result<String, ()> {
    let mut decoded_text = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            decoded_text.push(ch);
            continue;
        }

        match chars.next() {
            Some('u') => {
                let code = take_hex_digits(&mut chars, 4)?;
                let ch = char::from_u32(code).ok_or(())?;
                decoded_text.push(ch);
            }
            Some('x') => {
                let code = take_hex_digits(&mut chars, 2)?;
                decoded_text.push(char::from_u32(code).ok_or(())?);
            }
            Some(escaped) => decoded_text.push(escaped),
            None => return Err(()),
        }
    }

    Ok(decoded_text)
}

fn take_hex_digits<I>(chars: &mut std::iter::Peekable<I>, count: usize) -> Result<u32, ()>
where
    I: Iterator<Item = char>,
{
    let mut value = 0u32;
    for _ in 0..count {
        let ch = chars.next().ok_or(())?;
        let digit = ch.to_digit(16).ok_or(())?;
        value = (value << 4) | digit;
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_base64_secret() {
        // "sk-proj-abc123" in base64
        let encoded = "c2stcHJvai1hYmMxMjM=";
        let decoded = base64_decode(encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "sk-proj-abc123");
    }

    #[test]
    fn decode_hex_secret() {
        // "sk-proj-abc" in hex
        let encoded = "736b2d70726f6a2d616263";
        let decoded = hex_decode(encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "sk-proj-abc");
    }

    #[test]
    fn decode_url_safe_base64() {
        let encoded = "c2stcHJvai1hYmMxMjM"; // URL-safe, no padding
        let decoded = base64_decode(encoded).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "sk-proj-abc123");
    }

    #[test]
    fn find_base64_in_text() {
        let text = r#"TOKEN = "c2stcHJvai1hYmMxMjM=""#;
        let matches = find_base64_strings(text, 10);
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].value, "c2stcHJvai1hYmMxMjM=");
        assert_eq!(matches[1].value, "c2stcHJvai1hYmMxMjM=");
    }

    #[test]
    fn decode_chunk_finds_encoded_secret() {
        let chunk = Chunk {
            data: "SECRET=c2stcHJvai1hYmMxMjM=\n".to_string(),
            metadata: ChunkMetadata {
                source_type: "test".into(),
                path: Some("test.env".into()),
                commit: None,
                author: None,
                date: None,
            },
        };
        let decoded = decode_chunk(&chunk);
        assert!(!decoded.is_empty());
        assert!(decoded[0].data.contains("sk-proj-abc123"));
        assert!(decoded[0].metadata.source_type.contains("base64"));
    }

    #[test]
    fn decode_url_encoded_secret() {
        let decoded = percent_decode("ghp_%61%62%63defghijklmnopqrstuvwxyz1234567890").unwrap();
        assert_eq!(decoded, "ghp_abcdefghijklmnopqrstuvwxyz1234567890");
    }

    #[test]
    fn decode_unicode_escaped_secret() {
        let decoded = unicode_escape_decode(
            "\\u0067\\u0068\\u0070\\u005Fabcdefghijklmnopqrstuvwxyz1234567890",
        )
        .unwrap();
        assert_eq!(decoded, "ghp_abcdefghijklmnopqrstuvwxyz1234567890");
    }

    #[test]
    fn decode_quoted_printable_secret() {
        let decoded =
            quoted_printable_decode("ghp=5Fabcdefghijklmnopqrstuvwxyz1234567890").unwrap();
        assert_eq!(decoded, "ghp_abcdefghijklmnopqrstuvwxyz1234567890");
    }

    #[test]
    fn decode_double_url_encoded_secret() {
        let decoded =
            url_decode("%2567%2568%2570%255Fabcdefghijklmnopqrstuvwxyz1234567890").unwrap();
        assert_eq!(decoded, "ghp_abcdefghijklmnopqrstuvwxyz1234567890");
    }

    #[test]
    fn decode_html_named_entities() {
        let decoded = html_named_entity_decode("&lt;tag&gt;&amp;&quot;&apos;&nbsp;").unwrap();
        assert_eq!(decoded, "<tag>&\"'\u{00A0}");
    }

    #[test]
    fn decode_html_numeric_entities() {
        let decoded = html_numeric_entity_decode(
            "&#103;&#104;&#112;&#95;&#x61;&#x62;&#x63;defghijklmnopqrstuvwxyz1234567890",
        )
        .unwrap();
        assert_eq!(decoded, "ghp_abcdefghijklmnopqrstuvwxyz1234567890");
    }

    #[test]
    fn decode_hex_escape_secret() {
        let decoded =
            hex_escape_decode("\\x67\\x68\\x70\\x5Fabcdefghijklmnopqrstuvwxyz1234567890").unwrap();
        assert_eq!(decoded, "ghp_abcdefghijklmnopqrstuvwxyz1234567890");
    }

    #[test]
    fn decode_octal_escape_secret() {
        let decoded =
            octal_escape_decode("\\147\\150\\160\\137abcdefghijklmnopqrstuvwxyz1234567890")
                .unwrap();
        assert_eq!(decoded, "ghp_abcdefghijklmnopqrstuvwxyz1234567890");
    }

    #[test]
    fn decode_mime_encoded_word_base64_secret() {
        let decoded = mime_encoded_word_decode("=?utf-8?B?c2stcHJvai1hYmMxMjM=?=").unwrap();
        assert_eq!(decoded, "sk-proj-abc123");
    }

    #[test]
    fn decode_mime_encoded_word_q_secret() {
        let decoded = mime_encoded_word_decode(
            "=?utf-8?Q?xoxb=2DEXAMPLE1234=2DEXAMPLE5678=2DExAmPlEtOkEnVaLuEhErE?=",
        )
        .unwrap();
        assert_eq!(
            decoded,
            "xoxb-EXAMPLE1234-EXAMPLE5678-ExAmPlEtOkEnVaLuEhErE"
        );
    }

    #[test]
    fn rejects_base64_with_non_terminal_padding() {
        assert!(classify_base64("=abc").is_none());
        assert!(classify_base64("ab=c").is_none());
        assert!(classify_base64("abc===").is_none());
    }
}
