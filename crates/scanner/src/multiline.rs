//! Multi-line string concatenation preprocessor.
//!
//! Detects and joins string concatenation patterns across lines for multiple languages.
//! This allows the scanner to detect secrets that are split across lines using various
//! concatenation syntaxes.

const MAX_MULTILINE_PREPROCESS_BYTES: usize = 2 * 1024 * 1024;
const MAX_MULTILINE_LINE_BYTES: usize = 64 * 1024;

/// A mapping from an offset in the joined text back to the original line number.
#[derive(Debug, Clone)]
pub struct LineMapping {
    /// Start offset in the joined text (inclusive)
    pub start_offset: usize,
    /// End offset in the joined text (exclusive)
    pub end_offset: usize,
    /// Original line number (1-indexed)
    pub line_number: usize,
}

/// Result of preprocessing text for multi-line concatenation.
///
/// The `text` field contains the **original text unchanged**, followed by any
/// multiline-joined segments appended after a separator. This ensures:
/// 1. Structural regex patterns (`secret_key = "..."`) match in the original text
/// 2. Multiline-joined secrets (`"sk-proj-" + "abc..."`) match in the appended segments
/// 3. No double-scanning or heuristic thresholds needed
#[derive(Debug, Clone)]
pub struct PreprocessedText {
    /// Original text + appended multiline-joined segments
    pub text: String,
    /// Byte offset where the appended joined segments start (= original text length)
    pub original_end: usize,
    /// Mapping from offsets in text to original line numbers
    pub mappings: Vec<LineMapping>,
}

impl PreprocessedText {
    /// Get the original line number for a given offset in the joined text.
    pub fn line_for_offset(&self, offset: usize) -> Option<usize> {
        self.mappings
            .iter()
            .find(|m| offset >= m.start_offset && offset < m.end_offset)
            .map(|m| m.line_number)
    }

    /// Create a passthrough (no preprocessing) — one mapping per line.
    pub fn passthrough(text: &str) -> Self {
        let mut mappings = Vec::new();
        let mut offset = 0;
        for (line_idx, line) in text.split('\n').enumerate() {
            let end = offset + line.len();
            mappings.push(LineMapping {
                line_number: line_idx + 1, // 1-indexed
                start_offset: offset,
                end_offset: end + 1, // +1 for the \n
            });
            offset = end + 1; // skip past \n
        }
        if let Some(last) = mappings.last_mut() {
            last.end_offset = text.len();
        }
        let original_end = text.len();
        Self {
            text: text.to_string(),
            original_end,
            mappings,
        }
    }
}

/// Configuration for the multi-line preprocessor.
#[derive(Debug, Clone)]
pub struct MultilineConfig {
    /// Maximum number of lines to join in a single concatenation chain
    pub max_join_lines: usize,
    /// Whether to enable Python-style implicit concatenation
    pub python_implicit: bool,
    /// Whether to enable backslash line continuation
    pub backslash_continuation: bool,
    /// Whether to enable explicit concatenation with + operator
    pub plus_concatenation: bool,
    /// Whether to enable JavaScript template literal concatenation
    pub template_literals: bool,
}

impl Default for MultilineConfig {
    fn default() -> Self {
        Self {
            max_join_lines: 10,
            python_implicit: true,
            backslash_continuation: true,
            plus_concatenation: true,
            template_literals: true,
        }
    }
}

/// Check if text contains any concatenation indicators.
pub(crate) fn has_concatenation_indicators(text: &str) -> bool {
    // FAST PATH: skip structured data formats that never contain programming
    // string concatenation.  YAML is intentionally NOT excluded because it is
    // one of the highest-value secret formats and the multiline preprocessor
    // must still see the original content for downstream scanning.
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') // JSON / TOML
        || trimmed.starts_with("<?xml") || trimmed.starts_with('<')
    // XML/HTML
    {
        return false;
    }

    // Only trigger multiline preprocessing when actual concatenation patterns exist:
    // - `" +` or `' +` (string concat with +)
    // - `" \` or `' \` (backslash continuation)
    // - `` ` `` (template literals)
    // - `paste0(` (R language)
    // NOT just quotes or plus signs alone — those appear in every source file.
    // Check for actual multi-line concatenation indicators:
    // - `" +` or `' +` (explicit concat)
    // - `" \` or `' \` (backslash continuation)
    // - `"` followed by newline then `"` (implicit concat: Python, Go)
    // - Template literals (backtick)
    // - R paste0()
    let bytes = text.as_bytes();
    let has_explicit_concat = text.contains("\" +") || text.contains("' +");
    let has_backslash_cont = text.contains("\" \\") || text.contains("' \\");
    let has_template = memchr::memchr(b'`', bytes).is_some();
    let has_paste = text.contains("paste0(");
    // Implicit concat: adjacent strings `"..." "..."` or `"...\n "..."`
    let has_implicit = bytes.windows(3).any(|w| {
        // Same-line: `" "` or `' '`
        (w[0] == b'"' && w[1] == b' ' && w[2] == b'"')
            || (w[0] == b'\'' && w[1] == b' ' && w[2] == b'\'')
            // Cross-line: `"\n "` or `"\n"`
            || (w[0] == b'"' && w[1] == b'\n' && (w[2] == b'"' || w[2] == b' ' || w[2] == b'\t'))
            || (w[0] == b'\'' && w[1] == b'\n' && (w[2] == b'\'' || w[2] == b' ' || w[2] == b'\t'))
    });
    if !has_explicit_concat && !has_backslash_cont && !has_template && !has_paste && !has_implicit {
        return false;
    }

    // Look for programming concatenation patterns in a single pass.
    for line in text.lines() {
        let t = line.trim();

        // Line ends with + or starts with + (multi-line concat)
        if t.ends_with('+') || t.starts_with('+') || t.starts_with("+ ") {
            return true;
        }
        if t.contains("paste0(") || t.contains("paste(") {
            return true;
        }
        // "str" + "str" pattern mid-line (single-line concat)
        if t.contains("\" +") || t.contains("' +") || t.contains("+ \"") || t.contains("+ '") {
            return true;
        }
        // Line ends with \ (line continuation)
        if t.ends_with('\\') && !t.ends_with("\\\\") {
            return true;
        }
        if t.contains("\" \"") || t.contains("' '") {
            return true;
        }
        if t.ends_with('`') && t.matches('`').count() == 1 {
            return true;
        }
    }

    false
}

/// Preprocess text to join multi-line string concatenations.
///
/// This function detects various concatenation patterns across multiple languages:
/// - Python: implicit concatenation of adjacent strings, backslash continuation
/// - JavaScript/TypeScript: + operator, template literals, backslash continuation
/// - Ruby: + operator, backslash continuation, line continuation without operator
/// - Go: implicit concatenation of adjacent strings, + operator
/// - Rust: + operator for strings, implicit array concatenation (less common)
/// - Java/C#: + operator for string concatenation
///
/// Returns the preprocessed text with a mapping from joined offsets back to original line numbers.
pub fn preprocess_multiline(text: &str, config: &MultilineConfig) -> PreprocessedText {
    if text.len() > MAX_MULTILINE_PREPROCESS_BYTES
        || text
            .lines()
            .any(|line| line.len() > MAX_MULTILINE_LINE_BYTES)
    {
        return passthrough_text(text);
    }

    // Fast path: skip preprocessing if no concatenation indicators present
    if !has_concatenation_indicators(text) {
        return passthrough_text(text);
    }
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return PreprocessedText {
            text: String::new(),
            original_end: 0,
            mappings: Vec::new(),
        };
    }

    // Fast path: content that starts with { or [ is likely JSON/data — pass through.
    // The multiline preprocessor's string extraction mangles JSON structure.
    let first_nonwhite = text.trim_start().chars().next().unwrap_or(' ');
    if first_nonwhite == '{' || first_nonwhite == '[' {
        return passthrough_text(text);
    }

    let mut result_lines: Vec<String> = Vec::new();
    let mut mappings: Vec<LineMapping> = Vec::new();
    let mut current_offset: usize = 0;

    let mut i = 0;
    while i < lines.len() {
        let (joined_line, lines_consumed, line_mappings) =
            process_line_chain(&lines, i, config, current_offset);

        if !joined_line.is_empty() {
            // Track the mapping for this joined line
            let total_len = joined_line.len();
            for mapping in line_mappings {
                mappings.push(mapping);
            }
            current_offset += total_len + 1; // +1 for newline
        }

        result_lines.push(joined_line);
        i += lines_consumed.max(1);
    }

    let joined_text = result_lines.join("\n");

    // Build the final text: original text + separator + joined segments.
    // This ensures structural patterns match in the original, AND multiline-joined
    // secrets match in the appended segments. No double-scanning needed.
    let original_end = text.len();
    let mut final_text = text.to_string();

    // Only append joined segments that differ from the original lines
    // (i.e., segments that were actually joined from multiple lines)
    if joined_text != text && !joined_text.is_empty() {
        final_text.push('\n');
        final_text.push_str(&joined_text);

        // Remap the appended joined text offsets
        let append_start = original_end + 1; // +1 for the separator newline
        for mapping in &mut mappings {
            mapping.start_offset += append_start;
            mapping.end_offset += append_start;
        }
    }

    // Build mappings for the ORIGINAL text (first part)
    let mut original_mappings = Vec::new();
    let mut offset = 0;
    for (line_idx, line) in text.split('\n').enumerate() {
        let end = offset + line.len();
        original_mappings.push(LineMapping {
            line_number: line_idx + 1,
            start_offset: offset,
            end_offset: (end + 1).min(original_end),
        });
        offset = end + 1;
    }

    // Combine: original mappings first, then joined mappings
    original_mappings.extend(mappings);

    PreprocessedText {
        text: final_text,
        original_end,
        mappings: original_mappings,
    }
}

fn passthrough_text(text: &str) -> PreprocessedText {
    let mut mappings = Vec::new();
    let mut offset = 0;
    for (i, line) in text.lines().enumerate() {
        mappings.push(LineMapping {
            line_number: i + 1,
            start_offset: offset,
            end_offset: offset + line.len(),
        });
        offset += line.len() + 1;
    }
    let original_end = text.len();
    PreprocessedText {
        text: text.to_string(),
        original_end,
        mappings,
    }
}

/// Process a potential chain of concatenated lines starting at the given index.
/// Returns (joined_line, number_of_lines_consumed, line_mappings).
fn process_line_chain(
    lines: &[&str],
    start_idx: usize,
    config: &MultilineConfig,
    base_offset: usize,
) -> (String, usize, Vec<LineMapping>) {
    let mut joined_parts: Vec<String> = Vec::new();
    let mut line_mappings: Vec<LineMapping> = Vec::new();
    let mut current_idx = start_idx;
    let mut current_offset = base_offset;
    // Track the original starting line for the entire joined result
    let original_start_line = start_idx + 1;

    while current_idx < lines.len() && (current_idx - start_idx) < config.max_join_lines {
        let line = lines[current_idx];
        let line_number = current_idx + 1;

        // Check if this line continues a concatenation chain
        let (part, continues, continuation_type) =
            extract_string_part(line, config, current_idx > start_idx);

        if current_idx == start_idx {
            // First line in the chain
            if !part.is_empty() {
                let part_start = current_offset;
                let part_len = part.len();
                joined_parts.push(part);
                line_mappings.push(LineMapping {
                    start_offset: part_start,
                    end_offset: part_start + part_len,
                    line_number,
                });
                current_offset += part_len;
            }

            // If first line doesn't continue, we're done
            if !continues {
                break;
            }
        } else {
            // Subsequent line in a chain
            if continuation_type == ContinuationType::Backslash {
                // Backslash continuation: the entire line continues
                // We need to handle the case where the backslash continues
                // but there might be string content before it
                if !part.is_empty() {
                    let part_start = current_offset;
                    let part_len = part.len();
                    joined_parts.push(part);
                    line_mappings.push(LineMapping {
                        start_offset: part_start,
                        end_offset: part_start + part_len,
                        line_number,
                    });
                    current_offset += part_len;
                }
            } else if continuation_type == ContinuationType::PlusOperator
                || continuation_type == ContinuationType::Implicit
            {
                // + operator or implicit concatenation
                if !part.is_empty() {
                    let part_start = current_offset;
                    let part_len = part.len();
                    joined_parts.push(part);
                    line_mappings.push(LineMapping {
                        start_offset: part_start,
                        end_offset: part_start + part_len,
                        line_number,
                    });
                    current_offset += part_len;
                }
            } else if !part.is_empty() {
                let part_start = current_offset;
                let part_len = part.len();
                joined_parts.push(part);
                line_mappings.push(LineMapping {
                    start_offset: part_start,
                    end_offset: part_start + part_len,
                    line_number,
                });
                current_offset += part_len;
            }

            if !continues {
                break;
            }
        }

        current_idx += 1;
    }

    let joined = joined_parts.join("");

    // Create a single mapping entry for the entire joined line
    // pointing to the original starting line
    let final_mappings = if joined.is_empty() {
        Vec::new()
    } else {
        vec![LineMapping {
            start_offset: base_offset,
            end_offset: base_offset + joined.len(),
            line_number: original_start_line,
        }]
    };

    let lines_consumed = (current_idx - start_idx) + 1;
    (joined, lines_consumed, final_mappings)
}

#[derive(Debug, PartialEq)]
enum ContinuationType {
    None,
    Backslash,
    PlusOperator,
    Implicit,
    TemplateLiteral,
}

/// Extract the string part from a line and determine if it continues.
/// Returns (extracted_part, continues, continuation_type).
fn extract_string_part(
    line: &str,
    config: &MultilineConfig,
    _is_continuation: bool,
) -> (String, bool, ContinuationType) {
    let trimmed = line.trim();

    // Check for backslash continuation at end of line.
    // Only treat a single trailing `\` as continuation — `\\` (escaped backslash)
    // is a literal backslash, NOT a line continuation.
    if config.backslash_continuation && trimmed.ends_with('\\') && !trimmed.ends_with("\\\\") {
        // Strip exactly one trailing backslash (not all of them).
        let without_backslash = line
            .trim_end()
            .strip_suffix('\\')
            .unwrap_or(line)
            .trim_end();
        let part = extract_string_content(without_backslash);
        return (part, true, ContinuationType::Backslash);
    }

    // Check for + operator continuation
    if config.plus_concatenation {
        // Match patterns like: "str" + or 'str' + or var + "str"
        if let Some((part, continues)) = extract_plus_concatenation(line) {
            return (part, continues, ContinuationType::PlusOperator);
        }
    }

    if let Some((part, continues)) = extract_function_concatenation(line) {
        return (part, continues, ContinuationType::Implicit);
    }

    // Check for Python-style implicit concatenation
    if config.python_implicit
        && let Some((part, continues)) = extract_python_implicit_concatenation(line)
    {
        return (part, continues, ContinuationType::Implicit);
    }

    // NOTE: Parenthesized implicit concatenation (Python `key = ("str"\n"str")`)
    // is not yet supported. It requires a state machine to track parenthesis depth
    // across lines, which the current line-by-line architecture doesn't support.
    // This is a known limitation — tracked for a future refactor.

    // Check for template literal continuation (JavaScript)
    if config.template_literals
        && let Some((part, continues)) = extract_template_literal_continuation(line)
    {
        return (part, continues, ContinuationType::TemplateLiteral);
    }

    // Regular line — pass through UNCHANGED.
    // Only concatenation chains get transformed.
    (line.to_string(), false, ContinuationType::None)
}

/// Extract string content handling various quote types.
fn extract_string_content(line: &str) -> String {
    let trimmed = line.trim();

    // Try to extract content from quoted strings
    // Handle single quotes, double quotes, and backticks
    for (open, close) in [('"', '"'), ('\'', '\''), ('`', '`')] {
        if let Some(content) = extract_quoted_content(trimmed, open, close) {
            return content;
        }
    }

    // If no quoted content found, return the trimmed line
    // but filter out common non-secret parts
    filter_line_content(trimmed)
}

/// Extract content between matching quotes.
fn extract_quoted_content(s: &str, open: char, close: char) -> Option<String> {
    let mut chars = s.chars().peekable();

    // Skip leading non-quote characters (like variable names, operators)
    while let Some(&ch) = chars.peek() {
        if ch == open {
            break;
        }
        chars.next();
    }

    // Check for opening quote
    if chars.next() != Some(open) {
        return None;
    }

    let mut content = String::new();
    let mut escaped = false;

    for ch in chars {
        if escaped {
            content.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
            content.push(ch);
        } else if ch == close {
            return Some(content);
        } else {
            content.push(ch);
        }
    }

    None // Unclosed string
}

/// Filter line content to extract potential secret material.
fn filter_line_content(line: &str) -> String {
    // Remove common assignment operators and variable names
    let line = line
        .trim_start_matches("const ")
        .trim_start_matches("let ")
        .trim_start_matches("var ")
        .trim_start_matches("val ")
        .trim_start_matches("final ")
        .trim_start_matches("static ")
        .trim_start_matches("string ")
        .trim_start_matches("String ")
        .trim_start_matches("auto ")
        .trim_start_matches("dim ")
        .trim_start_matches("my ");

    // Remove assignment operators
    if let Some(pos) = line.find(" = ") {
        let after_assign = &line[pos + 3..];
        return after_assign.trim().to_string();
    }

    if let Some(pos) = line.find("= ") {
        let after_assign = &line[pos + 2..];
        return after_assign.trim().to_string();
    }

    if let Some(pos) = line.find('=') {
        let after_assign = &line[pos + 1..];
        return after_assign.trim().to_string();
    }

    line.to_string()
}

/// Extract content from a + operator concatenation.
/// Handles multiple + operators on the same line.
/// Returns (extracted_part, continues).
fn extract_plus_concatenation(line: &str) -> Option<(String, bool)> {
    let trimmed = line.trim();

    // Pattern: ... + "string" or ... + 'string' or ... + `string`
    // or: "string" + ...

    // Check if line ends with + (indicates continuation)
    let ends_with_plus = trimmed.ends_with('+');

    // Check if line has any + operators
    if !trimmed.contains('+') {
        return None;
    }

    // Split by + and extract string content from each part
    let parts: Vec<&str> = trimmed.split('+').collect();
    if parts.len() < 2 {
        return None;
    }

    let mut result = String::new();
    for part in &parts {
        let content = extract_string_content(part.trim());
        if !content.is_empty() {
            result.push_str(&content);
        }
    }

    Some((result, ends_with_plus))
}

/// Extract content from Python-style implicit concatenation.
/// Returns (extracted_part, continues).
fn extract_python_implicit_concatenation(line: &str) -> Option<(String, bool)> {
    let parts = extract_quoted_strings(line);

    if parts.is_empty() {
        return None;
    }

    // Join all adjacent string parts
    let joined = parts.join("");
    Some((joined, false))
}

fn extract_function_concatenation(line: &str) -> Option<(String, bool)> {
    let trimmed = line.trim();
    if !trimmed.contains("paste0(") && !trimmed.contains("paste(") {
        return None;
    }

    let parts = extract_quoted_strings(trimmed);
    if parts.len() < 2 {
        return None;
    }

    Some((parts.join(""), false))
}

fn extract_quoted_strings(line: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut i = 0;
    let chars: Vec<char> = line.chars().collect();

    while i < chars.len() {
        if chars[i] == '"' || chars[i] == '\'' {
            let quote = chars[i];
            let mut j = i + 1;
            let mut content = String::new();
            let mut escaped = false;

            while j < chars.len() {
                if escaped {
                    content.push(chars[j]);
                    escaped = false;
                } else if chars[j] == '\\' {
                    escaped = true;
                    content.push(chars[j]);
                } else if chars[j] == quote {
                    parts.push(content);
                    i = j;
                    break;
                } else {
                    content.push(chars[j]);
                }
                j += 1;
            }
        }
        i += 1;
    }

    parts
}

/// Extract content from JavaScript template literal continuation.
/// Returns (extracted_part, continues).
fn extract_template_literal_continuation(line: &str) -> Option<(String, bool)> {
    let trimmed = line.trim();

    // Check if this is a template literal that continues
    // Template literals use backticks: `content ${...} content`

    if !trimmed.contains('`') {
        return None;
    }

    // Check for continuation pattern: line ends without closing backtick
    let backtick_count = trimmed.chars().filter(|&c| c == '`').count();

    // If odd number of backticks, the template literal is unclosed
    let continues = backtick_count % 2 == 1;

    // Extract content between backticks
    let mut result = String::new();
    let mut in_template = false;
    let mut chars = trimmed.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '`' {
            in_template = !in_template;
            continue;
        }
        if in_template && ch == '$' && chars.peek() == Some(&'{') {
            // Skip interpolation
            chars.next(); // consume '{'
            let mut brace_depth = 1;
            for c in chars.by_ref() {
                if c == '{' {
                    brace_depth += 1;
                } else if c == '}' {
                    brace_depth -= 1;
                    if brace_depth == 0 {
                        break;
                    }
                }
            }
            continue;
        }
        if in_template {
            result.push(ch);
        }
    }

    Some((result, continues))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_backslash_continuation() {
        let text = r#"key = 'sk-proj-' + \
    'abcdef1234567890'"#;

        let config = MultilineConfig::default();
        let preprocessed = preprocess_multiline(text, &config);

        assert!(preprocessed.text.contains("sk-proj-"));
        assert!(preprocessed.text.contains("abcdef1234567890"));
        assert!(preprocessed.text.contains("sk-proj-abcdef1234567890"));
    }

    #[test]
    fn test_python_implicit_concatenation() {
        let text = r#"api_key = "sk-" "live_" "abcdef123456""#;

        let config = MultilineConfig::default();
        let preprocessed = preprocess_multiline(text, &config);

        assert!(preprocessed.text.contains("sk-live_abcdef123456"));
    }

    #[test]
    fn test_javascript_plus_concatenation() {
        let text = r#"const key = "sk-" +
    "test_" +
    "secret123";"#;

        let config = MultilineConfig::default();
        let preprocessed = preprocess_multiline(text, &config);

        assert!(preprocessed.text.contains("sk-test_secret123"));
    }

    #[test]
    fn test_javascript_template_literal() {
        // Template literals with interpolation - each part is extracted
        // Template literals that continue with backslash or have content after interpolation
        let text = r#"const key = `sk-proj-${id}abcdef123456`;"#;

        let config = MultilineConfig::default();
        let preprocessed = preprocess_multiline(text, &config);

        assert!(preprocessed.text.contains("sk-proj-"));
        assert!(preprocessed.text.contains("abcdef123456"));
    }

    #[test]
    fn test_go_string_concatenation() {
        let text = r#"apiKey := "sk-" +
    "live_" +
    "abcdef123456""#;

        let config = MultilineConfig::default();
        let preprocessed = preprocess_multiline(text, &config);

        assert!(preprocessed.text.contains("sk-live_abcdef123456"));
    }

    #[test]
    fn test_go_implicit_concatenation() {
        let text = r#"apiKey := "sk-" "live_" "abcdef123456""#;

        let config = MultilineConfig::default();
        let preprocessed = preprocess_multiline(text, &config);

        assert!(preprocessed.text.contains("sk-live_abcdef123456"));
    }

    #[test]
    fn test_java_plus_concatenation() {
        let text = r#"String apiKey = "sk-" +
    "live_" +
    "abcdef123456";"#;

        let config = MultilineConfig::default();
        let preprocessed = preprocess_multiline(text, &config);

        assert!(preprocessed.text.contains("sk-live_abcdef123456"));
    }

    #[test]
    fn test_csharp_plus_concatenation() {
        let text = r#"var apiKey = "sk-" +
    "live_" +
    "abcdef123456";"#;

        let config = MultilineConfig::default();
        let preprocessed = preprocess_multiline(text, &config);

        assert!(preprocessed.text.contains("sk-live_abcdef123456"));
    }

    #[test]
    fn test_ruby_concatenation() {
        let text = r#"api_key = "sk-" \
    + "live_" \
    + "abcdef123456""#;

        let config = MultilineConfig::default();
        let preprocessed = preprocess_multiline(text, &config);

        assert!(preprocessed.text.contains("sk-live_abcdef123456"));
    }

    #[test]
    fn test_rust_string_concatenation() {
        let text = r#"let api_key = "sk-".to_string() +
    "live_" +
    "abcdef123456";"#;

        let config = MultilineConfig::default();
        let preprocessed = preprocess_multiline(text, &config);

        assert!(preprocessed.text.contains("sk-live_abcdef123456"));
    }

    #[test]
    fn test_multiline_openai_key() {
        // Real-world pattern: OpenAI API key split across lines
        let text = r#"OPENAI_API_KEY = "sk-proj-" + \
    "AbCdEfGhIjKlMnOpQrStUvWxYz" + \
    "1234567890abcdefghij""#;

        let config = MultilineConfig::default();
        let preprocessed = preprocess_multiline(text, &config);

        assert!(preprocessed.text.contains("sk-proj-"));
        assert!(preprocessed.text.contains("AbCdEfGhIjKlMnOpQrStUvWxYz"));
    }

    #[test]
    fn test_line_mapping_basic() {
        let text = "line1\nline2\nline3";
        let config = MultilineConfig::default();
        let preprocessed = preprocess_multiline(text, &config);

        let line1 = preprocessed.line_for_offset(0);
        assert_eq!(line1, Some(1));
    }

    #[test]
    fn test_empty_input() {
        let config = MultilineConfig::default();
        let preprocessed = preprocess_multiline("", &config);

        assert!(preprocessed.text.is_empty());
        assert!(preprocessed.mappings.is_empty());
    }

    #[test]
    fn test_single_line_no_concatenation() {
        let text = r#"api_key = "sk-abcdef123456""#;
        let config = MultilineConfig::default();
        let preprocessed = preprocess_multiline(text, &config);

        assert!(preprocessed.text.contains("sk-abcdef123456"));
    }

    #[test]
    fn test_aws_key_multiline() {
        // AWS key split with backslash continuation
        let text = r#"AWS_ACCESS_KEY_ID = "AKIA" \
    "IOSFODNN7EXAMPLE""#;

        let config = MultilineConfig::default();
        let preprocessed = preprocess_multiline(text, &config);

        assert!(preprocessed.text.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_github_token_multiline() {
        // GitHub token split with + operator
        let text = r#"const token = "ghp_" +
    "xxxxxxxxxxxxxxxxxxxx" +
    "xxxxxxxxxxxxxxxxxxxx";"#;

        let config = MultilineConfig::default();
        let preprocessed = preprocess_multiline(text, &config);

        assert!(preprocessed.text.contains("ghp_"));
        assert!(preprocessed.text.contains("xxxxxxxxxxxxxxxxxxxx"));
    }

    #[test]
    fn test_slack_token_multiline() {
        // Slack token with implicit concatenation
        let text =
            r#"slack_token = "xoxb-" "1234567890" "-" "1234567890" "-" "abcdefghijABCDEFGHIJklmn""#;

        let config = MultilineConfig::default();
        let preprocessed = preprocess_multiline(text, &config);

        assert!(preprocessed.text.contains("xoxb-"));
        assert!(preprocessed.text.contains("1234567890"));
    }

    #[test]
    fn test_config_disables_features() {
        let text = r#"key = "part1" + "part2""#;

        // With plus concatenation disabled
        let config = MultilineConfig {
            plus_concatenation: false,
            ..Default::default()
        };
        let preprocessed = preprocess_multiline(text, &config);

        assert!(preprocessed.text.contains("part1"));
        assert!(preprocessed.text.contains("part2"));
    }

    #[test]
    fn test_single_line_plus_concatenation() {
        // Test single-line + concatenation (like JS/Python inline string joining)
        let text = r#"token = "xoxb-1234567890-" + "1234567890-" + "abcdefghijABCDEFGHIJklmn""#;

        let config = MultilineConfig::default();
        let preprocessed = preprocess_multiline(text, &config);

        eprintln!("Input: {}", text);
        eprintln!("Output: {}", preprocessed.text);

        assert!(preprocessed.text.contains("xoxb-1234567890-"));
        assert!(preprocessed.text.contains("1234567890-"));
        assert!(preprocessed.text.contains("abcdefghijABCDEFGHIJklmn"));
    }
}
