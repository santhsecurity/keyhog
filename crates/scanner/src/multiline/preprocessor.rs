use super::config::{LineMapping, MultilineConfig, PreprocessedText, should_passthrough};
use regex::Regex;

#[derive(Debug, PartialEq)]
enum ContinuationType {
    None,
    Backslash,
    PlusOperator,
    Implicit,
    TemplateLiteral,
}

/// Join adjacent string fragments and continuations before scanning.
pub fn preprocess_multiline(text: &str, config: &MultilineConfig) -> PreprocessedText {
    if should_passthrough(text) {
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

    let first_nonwhite = text.trim_start().chars().next().unwrap_or(' ');
    if first_nonwhite == '{' || first_nonwhite == '[' {
        return passthrough_text(text);
    }

    let mut result_lines = Vec::new();
    let mut mappings = Vec::new();
    let mut current_offset = 0usize;
    let mut index = 0;
    while index < lines.len() {
        let (joined_line, lines_consumed, line_mappings) =
            process_line_chain(&lines, index, config, current_offset);

        if !joined_line.is_empty() {
            let total_len = joined_line.len();
            mappings.extend(line_mappings);
            current_offset += total_len + 1;
        }

        result_lines.push(joined_line);
        index += lines_consumed.max(1);
    }

    let joined_text = result_lines.join("\n");
    let original_end = text.len();
    let mut final_text = text.to_string();

    let mut appended_any = false;
    if joined_text != text && !joined_text.is_empty() {
        final_text.push('\n');
        final_text.push_str(&joined_text);

        let append_start = original_end + 1;
        for mapping in &mut mappings {
            mapping.start_offset += append_start;
            mapping.end_offset += append_start;
        }
        appended_any = true;
    }

    let (structural_joined, structural_mappings) =
        collect_structural_fragments(&lines, final_text.len() + 1);
    if !structural_joined.is_empty() {
        if !appended_any {
            final_text.push('\n');
        }
        final_text.push_str(&structural_joined.join("\n"));
        mappings.extend(structural_mappings);
    }

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
    original_mappings.extend(mappings);

    PreprocessedText {
        text: final_text,
        original_end,
        mappings: original_mappings,
    }
}

fn collect_structural_fragments(
    lines: &[&str],
    initial_offset: usize,
) -> (Vec<String>, Vec<LineMapping>) {
    let Ok(assign_re) =
        Regex::new(r#"(?i)([a-z0-9_-]{2,32})\s*[:=]\s*["'`]([a-zA-Z0-9/+=_-]{4,})["'`](?:;|,)?$"#)
    else {
        return (Vec::new(), Vec::new());
    };

    let mut current_struct_offset = initial_offset;
    let mut structural_joined = Vec::new();
    let mut structural_mappings = Vec::new();
    let mut clusters: Vec<Vec<(usize, String, String)>> = Vec::new();
    let mut active_clusters: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for (index, line) in lines.iter().enumerate() {
        if line.contains('[') && line.contains(']') {
            let array_joined = join_inline_array_strings(line);
            if array_joined.len() >= 16 {
                structural_joined.push(array_joined.clone());
                structural_mappings.push(LineMapping {
                    start_offset: current_struct_offset,
                    end_offset: current_struct_offset + array_joined.len(),
                    line_number: index + 1,
                });
                current_struct_offset += array_joined.len() + 1;
            }
        }

        if let Some(caps) = assign_re.captures(line) {
            let Some(var_name_match) = caps.get(1) else {
                continue;
            };
            let Some(value_match) = caps.get(2) else {
                continue;
            };
            let var_name = var_name_match.as_str();
            let value = value_match.as_str();
            let prefix = extract_prefix(var_name);
            let mut added = false;

            if let Some(&cluster_idx) = active_clusters.get(&prefix) {
                let cluster = &mut clusters[cluster_idx];
                if is_related_variable(&cluster[0].1, var_name)
                    && let Some(last) = cluster.last()
                    && index.saturating_sub(last.0) < 10
                {
                    cluster.push((index, var_name.to_string(), value.to_string()));
                    added = true;
                }
            }

            if !added {
                let new_idx = clusters.len();
                clusters.push(vec![(index, var_name.to_string(), value.to_string())]);
                active_clusters.insert(prefix, new_idx);
            }
        }
    }

    for cluster in clusters {
        if cluster.len() >= 2 {
            let joined: String = cluster.iter().map(|(_, _, value)| value.as_str()).collect();
            if joined.len() >= 12 {
                let start_line = cluster[0].0 + 1;
                structural_joined.push(joined.clone());
                structural_mappings.push(LineMapping {
                    start_offset: current_struct_offset,
                    end_offset: current_struct_offset + joined.len(),
                    line_number: start_line,
                });
                current_struct_offset += joined.len() + 1;
            }
        }

        for (line_idx, var_name, value) in cluster {
            crate::fragment_cache::get_fragment_cache().record_and_reassemble(
                crate::fragment_cache::SecretFragment {
                    prefix: extract_prefix(&var_name),
                    var_name,
                    value,
                    line: line_idx + 1,
                    path: None,
                },
            );
        }
    }

    (structural_joined, structural_mappings)
}

fn join_inline_array_strings(line: &str) -> String {
    let mut array_joined = String::new();
    let mut in_str = false;
    let mut quote_char = '\0';
    let mut current_str = String::new();

    for ch in line.chars() {
        if !in_str {
            if ch == '"' || ch == '\'' || ch == '`' {
                in_str = true;
                quote_char = ch;
            }
        } else if ch == quote_char {
            in_str = false;
            array_joined.push_str(&current_str);
            current_str.clear();
        } else {
            current_str.push(ch);
        }
    }

    array_joined
}

fn passthrough_text(text: &str) -> PreprocessedText {
    let mut mappings = Vec::new();
    let mut offset = 0;
    for (index, line) in text.lines().enumerate() {
        mappings.push(LineMapping {
            line_number: index + 1,
            start_offset: offset,
            end_offset: offset + line.len(),
        });
        offset += line.len() + 1;
    }
    PreprocessedText {
        text: text.to_string(),
        original_end: text.len(),
        mappings,
    }
}

fn process_line_chain(
    lines: &[&str],
    start_idx: usize,
    config: &MultilineConfig,
    base_offset: usize,
) -> (String, usize, Vec<LineMapping>) {
    let mut joined_parts = Vec::new();
    let mut current_idx = start_idx;
    let original_start_line = start_idx + 1;

    while current_idx < lines.len() && (current_idx - start_idx) < config.max_join_lines {
        let line = lines[current_idx];
        let (part, continues, continuation_type) =
            extract_string_part(line, config, current_idx > start_idx);

        if current_idx == start_idx {
            if !part.is_empty() {
                joined_parts.push(part);
            }
            if !continues {
                break;
            }
        } else {
            if continuation_type == ContinuationType::Backslash
                || continuation_type == ContinuationType::PlusOperator
                || continuation_type == ContinuationType::Implicit
                || !part.is_empty()
            {
                joined_parts.push(part);
            }
            if !continues {
                break;
            }
        }

        current_idx += 1;
    }

    let joined = joined_parts.join("");
    let mappings = if joined.is_empty() {
        Vec::new()
    } else {
        vec![LineMapping {
            start_offset: base_offset,
            end_offset: base_offset + joined.len(),
            line_number: original_start_line,
        }]
    };

    let lines_consumed = (current_idx - start_idx) + 1;
    (joined, lines_consumed, mappings)
}

pub(crate) fn extract_prefix(var_name: &str) -> String {
    var_name
        .to_lowercase()
        .replace("part", "")
        .replace(['_', '-'], "")
        .trim_end_matches(|ch: char| ch.is_ascii_digit())
        .to_string()
}

fn is_related_variable(v1: &str, v2: &str) -> bool {
    v1 == v2 || extract_prefix(v1) == extract_prefix(v2)
}

fn extract_string_part(
    line: &str,
    config: &MultilineConfig,
    _is_continuation: bool,
) -> (String, bool, ContinuationType) {
    let trimmed = line.trim();

    if config.backslash_continuation && trimmed.ends_with('\\') && !trimmed.ends_with("\\\\") {
        let without_backslash = line
            .trim_end()
            .strip_suffix('\\')
            .unwrap_or(line)
            .trim_end();
        let part = extract_string_content(without_backslash);
        return (part, true, ContinuationType::Backslash);
    }

    if config.plus_concatenation
        && let Some((part, continues)) = extract_plus_concatenation(line)
    {
        return (part, continues, ContinuationType::PlusOperator);
    }

    if let Some((part, continues)) = extract_function_concatenation(line) {
        return (part, continues, ContinuationType::Implicit);
    }

    if config.python_implicit
        && let Some((part, continues)) = extract_python_implicit_concatenation(line)
    {
        return (part, continues, ContinuationType::Implicit);
    }

    if config.template_literals
        && let Some((part, continues)) = extract_template_literal_continuation(line)
    {
        return (part, continues, ContinuationType::TemplateLiteral);
    }

    (line.to_string(), false, ContinuationType::None)
}

fn extract_string_content(line: &str) -> String {
    let trimmed = line.trim();
    for (open, close) in [('"', '"'), ('\'', '\''), ('`', '`')] {
        if let Some(content) = extract_quoted_content(trimmed, open, close) {
            return content;
        }
    }
    filter_line_content(trimmed)
}

pub(crate) fn extract_quoted_content(s: &str, open: char, close: char) -> Option<String> {
    let mut chars = s.chars().peekable();
    let mut is_fstring = false;
    while let Some(&ch) = chars.peek() {
        if ch == open {
            break;
        }
        if ch == 'f' || ch == 'F' {
            is_fstring = true;
        }
        chars.next();
    }

    if chars.next() != Some(open) {
        return None;
    }

    let mut content = String::new();
    let mut escaped = false;
    while let Some(ch) = chars.next() {
        if escaped {
            content.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
            content.push(ch);
        } else if ch == close {
            return Some(content);
        } else if is_fstring && ch == '{' && chars.peek() != Some(&'{') {
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
        } else {
            content.push(ch);
        }
    }

    None
}

fn filter_line_content(line: &str) -> String {
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

    if let Some(pos) = line.find(" = ") {
        return line[pos + 3..].trim().to_string();
    }
    if let Some(pos) = line.find("= ") {
        return line[pos + 2..].trim().to_string();
    }
    if let Some(pos) = line.find('=') {
        return line[pos + 1..].trim().to_string();
    }

    line.to_string()
}

fn extract_plus_concatenation(line: &str) -> Option<(String, bool)> {
    let trimmed = line.trim();
    let ends_with_plus = trimmed.ends_with('+');
    if !trimmed.contains('+') {
        return None;
    }

    let content_to_split = if let Some(pos) = trimmed.find('=') {
        &trimmed[pos + 1..]
    } else {
        trimmed
    };

    let parts: Vec<&str> = content_to_split.split('+').collect();
    if parts.len() < 2 && !ends_with_plus {
        return None;
    }

    let mut result = String::new();
    for part in &parts {
        let content = extract_string_content(part.trim());
        if !content.is_empty() {
            result.push_str(&content);
        }
    }

    if result.is_empty() {
        None
    } else {
        Some((result, ends_with_plus))
    }
}

fn extract_python_implicit_concatenation(line: &str) -> Option<(String, bool)> {
    let parts = extract_quoted_strings(line);
    if parts.is_empty() {
        return None;
    }
    Some((parts.join(""), false))
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
    let mut index = 0;
    let chars: Vec<char> = line.chars().collect();

    while index < chars.len() {
        if chars[index] == '"' || chars[index] == '\'' {
            let quote = chars[index];
            let mut j = index + 1;
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
                    index = j;
                    break;
                } else {
                    content.push(chars[j]);
                }
                j += 1;
            }
        }
        index += 1;
    }

    parts
}

fn extract_template_literal_continuation(line: &str) -> Option<(String, bool)> {
    let trimmed = line.trim();
    if !trimmed.contains('`') {
        return None;
    }

    let continues = trimmed.chars().filter(|&ch| ch == '`').count() % 2 == 1;
    let mut result = String::new();
    let mut in_template = false;
    let mut chars = trimmed.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '`' {
            in_template = !in_template;
            continue;
        }
        if in_template && ch == '$' && chars.peek() == Some(&'{') {
            chars.next();
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
