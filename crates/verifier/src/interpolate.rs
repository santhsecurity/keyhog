//! Template interpolation helpers for verification requests.

use std::collections::HashMap;

/// Resolve a field reference to an actual value.
/// - "match" → the primary credential
/// - "companion.<name>" → the companion credential with given name
/// - anything else → literal string
pub(crate) fn resolve_field(
    field: &str,
    credential: &str,
    companions: &HashMap<String, String>,
) -> String {
    match field {
        "match" => credential.to_string(),
        s if s.starts_with("companion.") => {
            let name = &s["companion.".len()..];
            companions.get(name).cloned().unwrap_or_default()
        }
        "" => String::new(),
        other => other.to_string(),
    }
}

/// URL-encode a value for safe interpolation into URLs.
fn url_encode(s: &str) -> String {
    percent_encoding::percent_encode(s.as_bytes(), percent_encoding::NON_ALPHANUMERIC).to_string()
}

/// Strip CRLF characters from raw credential values to prevent HTTP header
/// injection when the credential is returned as-is for header templates.
fn sanitize_raw_value(s: &str) -> String {
    s.chars().filter(|c| !matches!(c, '\r' | '\n')).collect()
}

/// Replace `{{match}}` and `{{companion.*}}` placeholders in a template string.
pub(crate) fn interpolate(
    template: &str,
    credential: &str,
    companions: &HashMap<String, String>,
) -> String {
    const MAX_INTERPOLATION_REPLACEMENTS: usize = 1024;

    if template == "{{match}}" {
        return sanitize_raw_value(credential);
    }
    if template.starts_with("{{companion.")
        && template.ends_with("}}")
        && template.matches("{{").count() == 1
    {
        let name = &template["{{companion.".len()..template.len() - 2];
        return sanitize_raw_value(companions.get(name).map(String::as_str).unwrap_or(""));
    }

    let mut interpolated = template.replace("{{match}}", &url_encode(credential));

    let mut search_from = 0;
    let mut replacements = 0usize;
    while replacements < MAX_INTERPOLATION_REPLACEMENTS {
        let Some(offset) = interpolated[search_from..].find("{{companion.") else {
            break;
        };
        let start = search_from + offset;
        if let Some(end_offset) = interpolated[start..].find("}}") {
            let name_start = start + "{{companion.".len();
            let name_end = start + end_offset;
            let name = &interpolated[name_start..name_end];
            let replacement = url_encode(companions.get(name).map(String::as_str).unwrap_or(""));

            let end = start + end_offset + 2;
            interpolated = format!(
                "{}{}{}",
                &interpolated[..start],
                replacement,
                &interpolated[end..]
            );
            search_from = (start + replacement.len()).min(interpolated.len());
            replacements += 1;
        } else {
            break;
        }
    }
    interpolated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_field_match() {
        assert_eq!(
            resolve_field("match", "cred123", &HashMap::new()),
            "cred123"
        );
    }

    #[test]
    fn resolve_field_companion() {
        let mut companions = HashMap::new();
        companions.insert("secret".to_string(), "sec123".to_string());
        assert_eq!(
            resolve_field("companion.secret", "key", &companions),
            "sec123"
        );
    }

    #[test]
    fn resolve_field_literal() {
        assert_eq!(resolve_field("Bearer", "cred", &HashMap::new()), "Bearer");
    }

    #[test]
    fn resolve_field_empty() {
        assert_eq!(resolve_field("", "cred", &HashMap::new()), "");
    }

    #[test]
    fn interpolate_match_in_url() {
        let result = interpolate(
            "https://api.example.com/check?key={{match}}",
            "abc123",
            &HashMap::new(),
        );
        assert!(result.contains("abc123"));
    }

    #[test]
    fn interpolate_companion() {
        let mut companions = HashMap::new();
        companions.insert("secret".to_string(), "mysecret".to_string());
        let result = interpolate("{{companion.secret}}", "key", &companions);
        assert_eq!(result, "mysecret");
    }

    #[test]
    fn interpolate_strips_crlf_from_raw_match() {
        let result = interpolate(
            "{{match}}",
            "value\r\nInjected-Header: evil",
            &HashMap::new(),
        );
        assert_eq!(result, "valueInjected-Header: evil");
        assert!(!result.contains('\r'));
        assert!(!result.contains('\n'));
    }
}
