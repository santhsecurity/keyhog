//! Template interpolation helpers for verification requests.

/// Resolve a field reference to an actual value.
/// - "match" → the primary credential
/// - "companion.<name>" → the companion credential
/// - anything else → literal string
pub(crate) fn resolve_field(field: &str, credential: &str, companion: Option<&str>) -> String {
    match field {
        "match" => credential.to_string(),
        s if s.starts_with("companion.") => companion.unwrap_or("").to_string(),
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
///
/// # URL encoding behavior
///
/// When the template is EXACTLY `"{{match}}"` or `"{{companion.*}}"`, the value
/// is returned **raw** (no URL encoding) but with CRLF characters stripped to
/// prevent HTTP header injection. This is correct for auth headers and body
/// templates where the credential is the entire value.
///
/// When the template contains `{{match}}` or `{{companion.*}}` embedded in a
/// larger string (typically a URL), the substituted values are **URL-encoded**
/// to prevent injection via crafted credentials.
pub(crate) fn interpolate(template: &str, credential: &str, companion: Option<&str>) -> String {
    const MAX_INTERPOLATION_REPLACEMENTS: usize = 1024;

    if template == "{{match}}" {
        return sanitize_raw_value(credential);
    }
    if template.starts_with("{{companion.")
        && template.ends_with("}}")
        && template.matches("{{").count() == 1
    {
        return sanitize_raw_value(companion.unwrap_or(""));
    }

    let mut interpolated = template.replace("{{match}}", &url_encode(credential));
    if let Some(comp) = companion {
        let mut search_from = 0;
        let mut replacements = 0usize;
        while replacements < MAX_INTERPOLATION_REPLACEMENTS {
            let Some(offset) = interpolated[search_from..].find("{{companion.") else {
                break;
            };
            let start = search_from + offset;
            if let Some(end_offset) = interpolated[start..].find("}}") {
                let replacement = url_encode(comp);
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
    }
    interpolated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_field_match() {
        assert_eq!(resolve_field("match", "cred123", None), "cred123");
    }

    #[test]
    fn resolve_field_companion() {
        assert_eq!(
            resolve_field("companion.secret", "key", Some("sec123")),
            "sec123"
        );
    }

    #[test]
    fn resolve_field_literal() {
        assert_eq!(resolve_field("Bearer", "cred", None), "Bearer");
    }

    #[test]
    fn resolve_field_empty() {
        assert_eq!(resolve_field("", "cred", None), "");
    }

    #[test]
    fn interpolate_match_in_url() {
        let result = interpolate(
            "https://api.example.com/check?key={{match}}",
            "abc123",
            None,
        );
        assert!(result.contains("abc123"));
    }

    #[test]
    fn interpolate_no_recursion() {
        // Credential containing {{match}} should NOT cause recursive interpolation
        let result = interpolate(
            "https://api.example.com/check?key={{match}}",
            "{{match}}",
            None,
        );
        assert!(!result.contains("{{match}}") || result.matches("{{match}}").count() <= 1);
    }

    #[test]
    fn interpolate_url_encodes_special_chars() {
        let result = interpolate(
            "https://api.example.com/check?key={{match}}",
            "a b&c=d",
            None,
        );
        // Special chars should be URL-encoded
        assert!(!result.contains(' ') || result.contains("%20") || result.contains('+'));
    }

    #[test]
    fn interpolate_companion() {
        let result = interpolate("{{companion.secret}}", "key", Some("mysecret"));
        assert_eq!(result, "mysecret");
    }

    #[test]
    fn interpolate_strips_crlf_from_raw_match() {
        // A crafted credential containing CRLF should have those characters
        // stripped to prevent HTTP header injection.
        let result = interpolate("{{match}}", "value\r\nInjected-Header: evil", None);
        assert_eq!(result, "valueInjected-Header: evil");
        assert!(!result.contains('\r'));
        assert!(!result.contains('\n'));
    }

    #[test]
    fn interpolate_strips_crlf_from_raw_companion() {
        let result = interpolate("{{companion.secret}}", "key", Some("sec\r\nret"));
        assert_eq!(result, "secret");
    }
}
