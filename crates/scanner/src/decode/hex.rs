use super::pipeline::{extract_encoded_values, push_decoded_text_chunk};
use super::{Decoder, EncodedString};
use keyhog_core::Chunk;

pub(super) struct HexDecoder;

impl Decoder for HexDecoder {
    fn name(&self) -> &'static str {
        "hex"
    }

    fn decode_chunk(&self, chunk: &Chunk) -> Vec<Chunk> {
        let mut decoded_chunks = Vec::new();
        for hex_match in find_hex_strings(&chunk.data, 32) {
            if let Ok(decoded) = hex_decode(&hex_match.value)
                && let Ok(text) = String::from_utf8(decoded)
            {
                push_decoded_text_chunk(&mut decoded_chunks, chunk, text, self.name());
            }
        }
        decoded_chunks
    }
}

fn find_hex_strings(text: &str, min_length: usize) -> Vec<EncodedString> {
    let mut results = Vec::new();
    for candidate in extract_encoded_values(text) {
        if candidate.len() >= min_length
            && candidate.len() % 2 == 0
            && candidate.chars().all(|ch| ch.is_ascii_hexdigit())
        {
            results.push(EncodedString { value: candidate });
        }
    }
    results
}

/// Maximum hex input length we'll decode (prevents OOM from malicious input).
const MAX_HEX_INPUT_LEN: usize = 32 * 1024 * 1024; // 32 MB -> 16 MB decoded

#[allow(clippy::result_unit_err)]
pub fn hex_decode(input: &str) -> Result<Vec<u8>, ()> {
    if !input.len().is_multiple_of(2) || input.len() > MAX_HEX_INPUT_LEN {
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

pub(super) fn hex_val(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(()),
    }
}
