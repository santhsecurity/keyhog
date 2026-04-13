/// Confidence signals for a potential match.
pub struct ConfidenceSignals {
    /// Pattern has a distinctive literal prefix (e.g., `sk-proj-`, `ghp_`).
    pub has_literal_prefix: bool,
    /// Pattern uses a capture group with context anchoring.
    pub has_context_anchor: bool,
    /// Shannon entropy of the matched credential.
    pub entropy: f64,
    /// A secret-related keyword appears nearby.
    pub keyword_nearby: bool,
    /// File extension suggests config/env/secret file.
    pub sensitive_file: bool,
    /// Matched credential length.
    pub match_length: usize,
    /// Companion credential was found.
    pub has_companion: bool,
}

/// Check if a file path suggests a sensitive file.
/// Check if a file path suggests a sensitive file using Aho-Corasick.
///
/// Single AC automaton replaces O(n*m) nested loop with O(n) scan.
pub fn is_sensitive_path(path: &str) -> bool {
    use std::sync::OnceLock;

    static AC: OnceLock<aho_corasick::AhoCorasick> = OnceLock::new();

    let ac = AC.get_or_init(|| {
        aho_corasick::AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build([
                // Sensitive filenames
                ".env", ".env.local", ".env.production", ".env.staging",
                "credentials", "secrets", "apikeys", "api_keys",
                ".npmrc", ".pypirc", ".netrc", ".pgpass",
                "terraform.tfvars", "variables.tf",
                "docker-compose",
                "application.yml", "application.properties",
                "config.json", "config.yaml", "config.toml",
                // Sensitive extensions (matched as substrings — works because
                // extensions are at end of path and names are distinctive)
                ".pem", ".key", ".p12", ".pfx", ".jks",
                ".keystore", ".cer", ".crt",
                // CI/CD secret files
                ".github/workflows", "gitlab-ci.yml",
                "Jenkinsfile", "buildspec.yml",
                // Cloud config
                "serverless.yml", "sam-template",
                "helm/values", "chart/values",
            ])
            .unwrap()
    });

    ac.is_match(path)
}

#[cfg(test)]
mod tests {
    use super::is_sensitive_path;

    #[test]
    fn sensitive_paths() {
        assert!(is_sensitive_path(".env.production"));
        assert!(is_sensitive_path("config/credentials.json"));
        assert!(is_sensitive_path("server.key"));
        assert!(!is_sensitive_path("src/main.rs"));
        assert!(!is_sensitive_path("README.md"));
    }

    #[test]
    fn sensitive_path_matches_case_insensitively() {
        assert!(is_sensitive_path("CONFIG/.ENV.PRODUCTION"));
        assert!(is_sensitive_path("Secrets/CREDENTIALS.JSON"));
        assert!(is_sensitive_path("keys/CLIENT.P12"));
    }

    #[test]
    fn sensitive_path_rejects_empty_and_non_sensitive_values() {
        assert!(!is_sensitive_path(""));
        assert!(!is_sensitive_path("notes/environment.txt"));
        assert!(!is_sensitive_path("docs/secretary.txt"));
    }

    #[test]
    fn sensitive_path_detects_embedded_sensitive_names_with_special_characters() {
        assert!(is_sensitive_path("deploy/docker-compose.override.yml"));
        assert!(is_sensitive_path("dir/my api_keys-backup.txt"));
        assert!(is_sensitive_path("nested/application.properties.template"));
    }

    #[test]
    fn sensitive_path_handles_huge_input() {
        let long_prefix = "a/".repeat(4096);
        let long_sensitive = format!("{long_prefix}terraform.tfvars");
        let long_non_sensitive = format!("{long_prefix}plain-text-file.txt");
        assert!(is_sensitive_path(&long_sensitive));
        assert!(!is_sensitive_path(&long_non_sensitive));
    }
}
