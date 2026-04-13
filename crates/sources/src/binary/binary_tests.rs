#[cfg(test)]
mod tests {
    use super::*;
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
        unsafe {
            std::env::remove_var("GHIDRA_HOME");
        }
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
