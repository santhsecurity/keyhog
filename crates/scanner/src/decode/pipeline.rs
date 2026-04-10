use super::Decoder;
use super::base64::{Base64Decoder, Z85Decoder};
use super::hex::HexDecoder;
use super::url::{
    HexEscapeDecoder, HtmlNamedEntityDecoder, HtmlNumericEntityDecoder, MimeEncodedWordDecoder,
    OctalEscapeDecoder, QuotedPrintableDecoder, UnicodeEscapeDecoder, UrlDecoder,
};
use keyhog_core::{Chunk, ChunkMetadata};
use std::collections::{HashSet, VecDeque};

static DECODERS: std::sync::OnceLock<parking_lot::RwLock<Vec<Box<dyn Decoder>>>> =
    std::sync::OnceLock::new();

const MAX_DECODED_CHUNKS_PER_ROOT: usize = 1000;
const MAX_DECODED_TOTAL_BYTES: usize = 64 * 1024 * 1024;

fn get_decoders() -> &'static parking_lot::RwLock<Vec<Box<dyn Decoder>>> {
    DECODERS.get_or_init(|| {
        parking_lot::RwLock::new(vec![
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
            Box::new(Z85Decoder),
        ])
    })
}

pub fn register_decoder(decoder: Box<dyn Decoder>) {
    let mut registry = get_decoders().write();
    registry.push(decoder);
}

pub fn decode_chunk(
    chunk: &Chunk,
    max_depth: usize,
    _validate: bool,
    deadline: Option<std::time::Instant>,
    screen: Option<&crate::alphabet_filter::AlphabetScreen>,
) -> Vec<Chunk> {
    let mut decoded_chunks = Vec::new();
    let mut queue = VecDeque::from([(chunk.clone(), 0usize)]);
    let mut seen = HashSet::from([chunk.data.clone()]);
    let mut total_bytes = 0usize;

    let registry = get_decoders().read();

    while let Some((current, depth)) = queue.pop_front() {
        if let Some(deadline) = deadline
            && std::time::Instant::now() > deadline
        {
            break;
        }
        if depth >= max_depth {
            continue;
        }

        for decoder in registry.iter() {
            for decoded in decoder.decode_chunk(&current) {
                if seen.insert(decoded.data.clone()) {
                    if let Some(screen) = screen
                        && !screen.screen(decoded.data.as_bytes())
                    {
                        continue;
                    }

                    total_bytes += decoded.data.len();
                    if decoded_chunks.len() >= MAX_DECODED_CHUNKS_PER_ROOT
                        || total_bytes > MAX_DECODED_TOTAL_BYTES
                    {
                        tracing::warn!(
                            path = ?chunk.metadata.path,
                            "Recursive decoding limit reached. Fix: reduce decode depth or decode size limits"
                        );
                        return decoded_chunks;
                    }

                    queue.push_back((decoded.clone(), depth + 1));
                    decoded_chunks.push(decoded);
                }
            }
        }
    }
    decoded_chunks
}

pub(super) fn push_decoded_text_chunk(
    decoded_chunks: &mut Vec<Chunk>,
    chunk: &Chunk,
    text: String,
    decoder_name: &str,
) {
    if text.is_empty()
        || !text
            .chars()
            .all(|ch| !ch.is_control() || ch == '\n' || ch == '\r' || ch == '\t')
    {
        return;
    }

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

pub(super) fn decode_candidates<F>(
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
        if let Ok(text) = decode(&candidate) {
            push_decoded_text_chunk(&mut decoded_chunks, chunk, text, decoder_name);
        }
    }
    decoded_chunks
}

pub(super) fn extract_encoded_values(text: &str) -> Vec<String> {
    let mut values = Vec::new();
    let bytes = text.as_bytes();

    let mut index = 0;
    while index < bytes.len() {
        let ch = bytes[index];

        if ch == b'"' || ch == b'\'' || ch == b'`' {
            let quote = ch;
            index += 1;
            let mut escaping = false;
            let mut cleaned = String::with_capacity(32);

            while index < bytes.len() {
                let current = bytes[index];
                if escaping {
                    cleaned.push(current as char);
                    escaping = false;
                } else if current == b'\\' {
                    escaping = true;
                } else if current == quote {
                    if cleaned.len() >= 4 {
                        values.push(cleaned);
                    }
                    break;
                } else if !current.is_ascii_whitespace() {
                    cleaned.push(current as char);
                }
                index += 1;
            }
        } else if ch == b':' || ch == b'=' {
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            let mut cleaned = String::with_capacity(32);
            while index < bytes.len()
                && !bytes[index].is_ascii_whitespace()
                && bytes[index] != b';'
                && bytes[index] != b','
                && bytes[index] != b'"'
                && bytes[index] != b'\''
                && bytes[index] != b'`'
            {
                cleaned.push(bytes[index] as char);
                index += 1;
            }
            if cleaned.len() >= 4 {
                values.push(cleaned);
            }
            continue;
        }
        index += 1;
    }

    let mut current_block = String::new();
    let is_b64_char = |ch: char| {
        ch.is_ascii_alphanumeric() || ch == '+' || ch == '/' || ch == '=' || ch == '-' || ch == '_'
    };

    for ch in text.chars() {
        if is_b64_char(ch) {
            current_block.push(ch);
        } else if !ch.is_whitespace() {
            if current_block.len() >= 16 {
                values.push(std::mem::take(&mut current_block));
            }
            current_block.clear();
        }
    }
    if current_block.len() >= 16 {
        values.push(current_block);
    }

    values
}
