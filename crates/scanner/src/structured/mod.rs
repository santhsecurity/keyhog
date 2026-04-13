//! Structured format preprocessor.
//!
//! Detects known configuration formats (.env, Kubernetes Secrets, Docker Compose,
//! Terraform state, Jupyter notebooks), extracts (context, value) pairs, and
//! appends them as scannable lines to the original text.  This lets the regex
//! pipeline see values with their keys as context while keeping original line
//! mappings intact.

use crate::types::ScannerPreprocessedText;

mod parsers;

const MAX_STRUCTURED_PARSE_BYTES: usize = 2 * 1024 * 1024;

pub struct ExtractedPair {
    pub context: String,
    pub value: String,
    pub line: usize,
}

/// Detect format by path and/or content, parse it, and build a preprocessed text.
/// Returns `None` when the file is not a recognised structured format, when it
/// exceeds the size limit, or when no pairs could be extracted.
pub fn preprocess(text: &str, path: Option<&str>) -> Option<ScannerPreprocessedText> {
    if text.len() > MAX_STRUCTURED_PARSE_BYTES {
        return None;
    }
    let pairs = detect_and_parse(text, path)?;
    if pairs.is_empty() {
        return None;
    }
    Some(build_preprocessed_text(text, pairs))
}

fn detect_and_parse(text: &str, path: Option<&str>) -> Option<Vec<ExtractedPair>> {
    let lower_path = path.map(|p| p.to_lowercase()).unwrap_or_default();
    let file_name = lower_path.rsplit(['/', '\\']).next().unwrap_or(&lower_path);

    if file_name.starts_with(".env") || file_name.ends_with(".env") {
        return Some(parsers::parse_env(text));
    }

    if (lower_path.ends_with(".yaml") || lower_path.ends_with(".yml"))
        && text.contains("kind: Secret")
    {
        return Some(parsers::parse_k8s_secret(text));
    }

    if (file_name.contains("docker-compose") || file_name.contains("compose"))
        && (lower_path.ends_with(".yaml") || lower_path.ends_with(".yml"))
    {
        return Some(parsers::parse_docker_compose(text));
    }

    if lower_path.ends_with(".tfstate") {
        return Some(parsers::parse_tfstate(text));
    }

    if lower_path.ends_with(".ipynb") {
        return Some(parsers::parse_jupyter(text));
    }

    None
}

#[cfg(feature = "multiline")]
fn build_preprocessed_text(text: &str, pairs: Vec<ExtractedPair>) -> ScannerPreprocessedText {
    use crate::multiline::LineMapping;
    let original_end = text.len();
    let mut final_text = text.to_string();
    let mut mappings: Vec<LineMapping> = Vec::new();
    let mut offset = 0usize;

    for (line_idx, line) in text.split('\n').enumerate() {
        let end = offset + line.len();
        mappings.push(LineMapping {
            line_number: line_idx + 1,
            start_offset: offset,
            end_offset: (end + 1).min(original_end),
        });
        offset = end + 1;
    }

    final_text.push('\n');
    let mut current_offset = original_end + 1;
    for pair in pairs {
        let appended_line = format!("{}: {}", pair.context, pair.value);
        let line_len = appended_line.len();
        mappings.push(LineMapping {
            line_number: pair.line,
            start_offset: current_offset,
            end_offset: current_offset + line_len,
        });
        final_text.push_str(&appended_line);
        final_text.push('\n');
        current_offset += line_len + 1;
    }

    crate::multiline::PreprocessedText {
        text: final_text,
        original_end,
        mappings,
    }
}

#[cfg(not(feature = "multiline"))]
fn build_preprocessed_text(text: &str, pairs: Vec<ExtractedPair>) -> ScannerPreprocessedText {
    use crate::types::LineMapping;
    let mut final_text = text.to_string();
    let mut mappings: Vec<LineMapping> = Vec::new();
    let mut offset = 0usize;

    for (line_idx, line) in text.split('\n').enumerate() {
        let end = offset + line.len();
        mappings.push(LineMapping {
            line_number: line_idx + 1,
            start_offset: offset,
            end_offset: end + 1,
        });
        offset = end + 1;
    }
    if let Some(last) = mappings.last_mut() {
        last.end_offset = text.len();
    }

    final_text.push('\n');
    let mut current_offset = text.len() + 1;
    for pair in pairs {
        let appended_line = format!("{}: {}", pair.context, pair.value);
        let line_len = appended_line.len();
        mappings.push(LineMapping {
            line_number: pair.line,
            start_offset: current_offset,
            end_offset: current_offset + line_len,
        });
        final_text.push_str(&appended_line);
        final_text.push('\n');
        current_offset += line_len + 1;
    }

    crate::types::PreprocessedText {
        text: final_text,
        mappings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_basic_and_quotes() {
        let text = "API_KEY=sk-12345\n# comment\nDB_PASS=secret\n\nEMPTY=\nexport TOKEN=\"tok\"\nQUOTED='single'\n";
        let pairs = parsers::parse_env(text);
        assert_eq!(pairs.len(), 5);
        assert_eq!(pairs[0].context, "API_KEY");
        assert_eq!(pairs[0].value, "sk-12345");
        assert_eq!(pairs[0].line, 1);
        assert_eq!(pairs[1].context, "DB_PASS");
        assert_eq!(pairs[1].value, "secret");
        assert_eq!(pairs[1].line, 3);
        assert_eq!(pairs[2].context, "EMPTY");
        assert_eq!(pairs[2].value, "");
        assert_eq!(pairs[2].line, 5);
        assert_eq!(pairs[3].context, "TOKEN");
        assert_eq!(pairs[3].value, "tok");
        assert_eq!(pairs[3].line, 6);
        assert_eq!(pairs[4].context, "QUOTED");
        assert_eq!(pairs[4].value, "single");
        assert_eq!(pairs[4].line, 7);
    }

    #[test]
    fn test_env_malicious_input() {
        // no crash on malformed lines
        let pairs = parsers::parse_env("=nokey\nNOVALUE\n  \n#only\nKEY=\n");
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].context, "KEY");
        assert_eq!(pairs[0].value, "");
    }

    #[test]
    fn test_k8s_secret_base64() {
        let text = r#"
apiVersion: v1
kind: Secret
metadata:
  name: test
data:
  password: c2VjcmV0
  token: dG9rZW4x
"#;
        let pairs = parsers::parse_k8s_secret(text);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].context, "password");
        assert_eq!(pairs[0].value, "secret");
        assert_eq!(pairs[1].context, "token");
        assert_eq!(pairs[1].value, "token1");
    }

    #[test]
    fn test_k8s_invalid_base64_ignored() {
        let text = r#"
kind: Secret
data:
  bad: !!!
  good: c2VjcmV0
"#;
        let pairs = parsers::parse_k8s_secret(text);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].context, "good");
    }

    #[test]
    fn test_docker_compose_map_and_list() {
        let text = r#"
version: "3"
services:
  web:
    environment:
      DB_HOST: postgres
      API_KEY: key123
  worker:
    environment:
      - REDIS_URL=redis://localhost
"#;
        let pairs = parsers::parse_docker_compose(text);
        assert_eq!(pairs.len(), 3);
        let contexts: Vec<_> = pairs.iter().map(|p| p.context.as_str()).collect();
        assert!(contexts.contains(&"DB_HOST"));
        assert!(contexts.contains(&"API_KEY"));
        assert!(contexts.contains(&"REDIS_URL"));
    }

    #[test]
    fn test_tfstate_recursive_values() {
        let text = r#"{"modules":[{"resources":{"aws_db_instance":{"primary":{"attributes":{"password":{"value":"supersecret"},"port":{"value":5432}}}}}}]}"#;
        let pairs = parsers::parse_tfstate(text);
        assert_eq!(pairs.len(), 2);
        let values: Vec<_> = pairs.iter().map(|p| p.value.as_str()).collect();
        assert!(values.contains(&"supersecret"));
        assert!(values.contains(&"5432"));
    }

    #[test]
    fn test_jupyter_code_cells_only() {
        let text = r##"{"cells":[{"cell_type":"markdown","source":"# Hello"},{"cell_type":"code","source":"api_key = 'sk-123'"},{"cell_type":"code","source":["x = 1\n","print(x)"]}]}"##;
        let pairs = parsers::parse_jupyter(text);
        assert_eq!(pairs.len(), 2);
        assert!(pairs[0].value.contains("api_key"));
        assert!(pairs[1].value.contains("print(x)"));
    }

    #[test]
    fn test_preprocess_builds_mappings() {
        let text = "A=1\nB=2\n";
        let pairs = vec![
            ExtractedPair {
                context: "A".into(),
                value: "1".into(),
                line: 1,
            },
            ExtractedPair {
                context: "B".into(),
                value: "2".into(),
                line: 2,
            },
        ];
        let pp = build_preprocessed_text(text, pairs);
        assert!(pp.text.contains("A: 1"));
        assert!(pp.text.contains("B: 2"));
        assert_eq!(pp.line_for_offset(text.len() + 1), Some(1));
    }

    #[test]
    fn test_size_limit_bypass() {
        let huge = "x".repeat(MAX_STRUCTURED_PARSE_BYTES + 1);
        assert!(preprocess(&huge, Some(".env")).is_none());
    }
}
