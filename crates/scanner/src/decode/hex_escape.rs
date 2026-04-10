use super::pipeline::push_decoded_text_chunk;
use super::Decoder;
use keyhog_core::Chunk;

/// Decodes `\xNN` style hex escapes common in obfuscated source code.
pub(super) struct HexEscapeDecoder;

impl Decoder for HexEscapeDecoder {
    fn name(&self) -> &'static str {
        "hex-escape"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        let mut decoded_chunks = Vec::new();
        for candidate in find_hex_escape_candidates(&chunk.data) {
            if let Ok(text) = hex_escape_decode(&candidate) {
                push_decoded_text_chunk(&mut decoded_chunks, chunk, text, self.name());
            }
        }
        decoded_chunks
    }
}

fn find_hex_escape_candidates(text: &str) -> Vec<String> {
    let mut candidates = Vec::new();

    if text.contains("\\x") {
        candidates.push(text.to_string());
    }

    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let ch = bytes[index];
        if ch == b'"' || ch == b'\'' || ch == b'`' {
            let quote = ch;
            index += 1;
            let mut content = String::with_capacity(32);
            let mut escaping = false;
            while index < bytes.len() {
                let current = bytes[index];
                if escaping {
                    content.push('\\');
                    content.push(current as char);
                    escaping = false;
                } else if current == b'\\' {
                    escaping = true;
                } else if current == quote {
                    break;
                } else {
                    content.push(current as char);
                }
                index += 1;
            }
            if content.contains("\\x") && content.len() >= 4 {
                candidates.push(content);
            }
        }
        index += 1;
    }

    candidates
}

/// Decode `\xNN` hex escape sequences in the input string.
pub fn hex_escape_decode(input: &str) -> Result<String, ()> {
    let mut decoded = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut changed = false;

    while let Some(ch) = chars.next() {
        if ch != '\\' || chars.peek() != Some(&'x') {
            decoded.push(ch);
            continue;
        }

        chars.next(); // consume 'x'
        let high = chars.next().ok_or(())?.to_digit(16).ok_or(())?;
        let low = chars.next().ok_or(())?.to_digit(16).ok_or(())?;
        decoded.push(char::from_u32(((high << 4) | low) as u32).ok_or(())?);
        changed = true;
    }

    changed.then_some(decoded).ok_or(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyhog_core::ChunkMetadata;

    #[test]
    fn decodes_simple_hex_escape() {
        assert_eq!(
            hex_escape_decode(r"abc\x73\x65\x63\x72\x65\x74").unwrap(),
            "abcsecret"
        );
    }

    #[test]
    fn rejects_unchanged_input() {
        assert!(hex_escape_decode("no escapes here").is_err());
    }

    #[test]
    fn decoder_finds_quoted_hex_escapes() {
        let chunk = Chunk {
            data: r#"const x = "\x73\x6b\x2d";"#.to_string(),
            metadata: ChunkMetadata {
                source_type: "test".into(),
                path: None,
                commit: None,
                author: None,
                date: None,
            },
        };
        let decoder = HexEscapeDecoder;
        let result = decoder.decode_chunk(&chunk);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].data, "sk-");
    }
}
