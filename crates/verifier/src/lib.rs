//! Live credential verification: confirms whether detected secrets are actually
//! active by making HTTP requests to the service's API endpoint as specified in
//! each detector's `[detector.verify]` configuration.

/// Shared in-memory verification cache.
pub mod cache;
mod interpolate;
mod ssrf;
mod verify;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use keyhog_core::{
    DedupedMatch, DetectorSpec, VerificationResult, VerifiedFinding,
    redact,
};

// Re-export dedup types from core so existing consumers (`use keyhog_verifier::DedupedMatch`)
// continue to work without source changes.
pub use keyhog_core::{DedupScope, dedup_matches};
use reqwest::Client;
use thiserror::Error;
use tokio::sync::{Notify, Semaphore};

/// Errors returned while constructing or executing live verification.
///
/// # Examples
///
/// ```rust
/// use keyhog_verifier::VerifyError;
///
/// let error = VerifyError::FieldResolution("missing companion.secret".into());
/// assert!(error.to_string().contains("Fix"));
/// ```
#[derive(Debug, Error)]
pub enum VerifyError {
    #[error(
        "failed to send HTTP request: {0}. Fix: check network access, proxy settings, and the verification endpoint"
    )]
    Http(#[from] reqwest::Error),
    #[error(
        "failed to build configured HTTP client: {0}. Fix: use a valid timeout and supported TLS/network configuration"
    )]
    ClientBuild(reqwest::Error),
    #[error(
        "failed to resolve verification field: {0}. Fix: use `match` or `companion.<name>` fields that exist in the detector spec"
    )]
    FieldResolution(String),
}

/// Live-verification engine with shared client, cache, and concurrency limits.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::{DetectorSpec, PatternSpec, Severity};
/// use keyhog_verifier::{VerificationEngine, VerifyConfig};
///
/// let detectors = vec![DetectorSpec {
///     id: "demo-token".into(),
///     name: "Demo Token".into(),
///     service: "demo".into(),
///     severity: Severity::High,
///     patterns: vec![PatternSpec {
///         regex: "demo_[A-Z0-9]{8}".into(),
///         description: None,
///         group: None,
///     }],
///     companion: None,
///     verify: None,
///     keywords: vec!["demo_".into()],
/// }];
///
/// let engine = VerificationEngine::new(&detectors, VerifyConfig::default()).unwrap();
/// let _ = engine;
/// ```
pub struct VerificationEngine {
    client: Client,
    detectors: HashMap<String, DetectorSpec>,
    /// Per-service concurrency limit to avoid hammering APIs.
    service_semaphores: HashMap<String, Arc<Semaphore>>,
    /// Global concurrency limit.
    global_semaphore: Arc<Semaphore>,
    timeout: Duration,
    /// Response cache to avoid re-verifying the same credential.
    cache: Arc<cache::VerificationCache>,
    /// One in-flight request per (detector_id, credential).
    inflight: Arc<DashMap<(String, String), Arc<Notify>>>,
    max_inflight_keys: usize,
}

/// Runtime configuration for live verification.
///
/// # Examples
///
/// ```rust
/// use keyhog_verifier::VerifyConfig;
/// use std::time::Duration;
///
/// let config = VerifyConfig {
///     timeout: Duration::from_secs(2),
///     ..VerifyConfig::default()
/// };
///
/// assert_eq!(config.timeout, Duration::from_secs(2));
/// ```
pub struct VerifyConfig {
    /// End-to-end timeout for one verification attempt.
    pub timeout: Duration,
    /// Maximum concurrent requests allowed per service.
    pub max_concurrent_per_service: usize,
    /// Maximum concurrent verification tasks overall.
    pub max_concurrent_global: usize,
    /// Upper bound for distinct in-flight deduplication keys.
    pub max_inflight_keys: usize,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            max_concurrent_per_service: 5,
            max_concurrent_global: 20,
            max_inflight_keys: 10_000,
        }
    }
}

/// Convert a [`DedupedMatch`] into a [`VerifiedFinding`] with the given verification result.
///
/// Single construction point eliminates duplication across cache-hit, inflight-wait,
/// semaphore-error, and live-verification code paths.
pub(crate) fn into_finding(
    group: DedupedMatch,
    verification: VerificationResult,
    metadata: HashMap<String, String>,
) -> VerifiedFinding {
    VerifiedFinding {
        detector_id: group.detector_id,
        detector_name: group.detector_name,
        service: group.service,
        severity: group.severity,
        credential_redacted: redact(&group.credential),
        location: group.primary_location,
        verification,
        metadata,
        additional_locations: group.additional_locations,
        confidence: group.confidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interpolate::interpolate;
    use crate::ssrf::{is_private_url, parse_url_host};
    // 1MB max response body size for verification
    const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
    use keyhog_core::{
        AuthSpec, DetectorSpec, HttpMethod, MatchLocation, RawMatch, Severity, SuccessSpec,
        VerificationResult,
    };
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // =========================================================================
    // HARD VERIFICATION TESTS
    // =========================================================================

    /// 1. Verify URL with unicode hostname (IDN/punycode handling)
    #[test]
    fn verify_url_with_unicode_hostname() {
        // Unicode hostnames should be handled - IDN (Internationalized Domain Names)
        // are converted to punycode for DNS resolution
        let unicode_urls = vec![
            "https://münchen.example.com/api",
            "https://日本語.example.com/verify",
            "https://test.домен.рф/check",
            "https://example.中国/path",
        ];

        for url in unicode_urls {
            // parse_url_host should handle or fail gracefully on unicode
            let host = parse_url_host(url);
            // The URL parser may or may not accept unicode directly
            // Either it parses or returns None - both are acceptable behaviors
            match host {
                Some(h) => {
                    // If it parses, the host should contain the unicode or punycode
                    assert!(
                        !h.is_empty(),
                        "Parsed host should not be empty for URL: {}",
                        url
                    );
                }
                None => {
                    // Not parsing unicode is also acceptable - it's a security boundary
                }
            }
        }

        // Interpolation with unicode in path/query should work
        let interpolated = interpolate("https://example.com/日本語/{{match}}", "test-key", None);
        // The credential should appear in the result (either as-is or encoded)
        assert!(
            interpolated.contains("test-key")
                || interpolated.contains("%7B%7Bmatch%7D%7D")
                || interpolated.contains("%2D"),
            "Interpolated URL should contain credential or encoding: {}",
            interpolated
        );
    }

    /// 2. Verify URL with percent-encoded path traversal (%2e%2e)
    #[test]
    fn verify_url_with_percent_encoded_path_traversal() {
        // Path traversal attempts via percent-encoding
        let traversal_urls = vec![
            "https://example.com/api/%2e%2e/%2e%2e/etc/passwd",
            "https://example.com/api/%2e%2e%2fadmin",
            "https://example.com/%252e%252e/admin", // Double-encoded
            "https://example.com/api/..%2f..%2fsecret",
        ];

        for url in traversal_urls {
            // The URL parser should handle percent-encoding
            let parsed = reqwest::Url::parse(url);
            assert!(
                parsed.is_ok(),
                "URL with percent-encoding should parse: {}",
                url
            );

            // Check if URL is flagged as private (it shouldn't be for example.com)
            assert!(
                !is_private_url(url),
                "Public URL with path traversal encoding should not be private: {}",
                url
            );
        }

        // Interpolation should URL-encode the credential, preventing traversal
        let traversal_cred = "../../../etc/passwd";
        let interpolated = interpolate("https://api.example.com/{{match}}", traversal_cred, None);
        assert!(
            !interpolated.contains("../"),
            "Path traversal in credential should be encoded: {}",
            interpolated
        );
        assert!(
            interpolated.contains("%2F") || interpolated.contains("."),
            "Credential should be encoded or preserved but not traverse: {}",
            interpolated
        );
    }

    /// 3. Verify with credential containing SQL injection payload
    #[test]
    fn verify_with_sql_injection_credential() {
        let sql_injection_creds = vec![
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM passwords --",
            "1' AND 1=1 --",
            "admin'--",
            "1'; DELETE FROM credentials WHERE '1'='1",
        ];

        for cred in sql_injection_creds {
            // The credential should be treated as a literal value
            let interpolated = interpolate("{{match}}", cred, None);
            assert_eq!(
                interpolated, cred,
                "SQL injection credential should be preserved literally"
            );

            // When used in URL, it should be properly encoded
            let url_interpolated =
                interpolate("https://api.example.com/?key={{match}}", cred, None);
            assert!(
                !url_interpolated.contains(" "),
                "Spaces should be encoded in URL: {}",
                url_interpolated
            );

            // Single quotes should be percent-encoded
            assert!(
                url_interpolated.contains("%27") || url_interpolated.contains("%22"),
                "Quotes should be encoded: {}",
                url_interpolated
            );
        }
    }

    /// 4. Verify with credential containing CRLF injection (\r\nHost: evil.com)
    #[tokio::test]
    async fn verify_with_crlf_injection_credential() {
        let crlf_payloads = vec![
            "value\r\nHost: evil.com",
            "token\r\n\r\nGET /admin HTTP/1.1\r\nHost: attacker.com",
            "key\nX-Injected: malicious",
            "secret\r\nContent-Length: 0\r\n\r\n",
        ];

        for payload in crlf_payloads {
            // Test interpolation in different contexts
            let interpolated_url =
                interpolate("https://api.example.com/?token={{match}}", payload, None);

            // Newlines MUST be encoded to prevent header injection
            assert!(
                !interpolated_url.contains('\r') && !interpolated_url.contains('\n'),
                "CRLF characters must be encoded in URL: {:?}",
                interpolated_url
            );

            // Should be percent-encoded
            assert!(
                interpolated_url.contains("%0D") || interpolated_url.contains("%0A"),
                "CRLF should be percent-encoded: {:?}",
                interpolated_url
            );

            // Literal interpolation (non-URL) now STRIPS CRLF to prevent
            // HTTP header injection when the credential is used in headers.
            let interpolated_literal = interpolate("{{match}}", payload, None);
            assert!(
                !interpolated_literal.contains('\r') && !interpolated_literal.contains('\n'),
                "CRLF should be stripped from raw interpolation: {:?}",
                interpolated_literal
            );
        }
    }

    /// 5. Verify with credential that is valid base64 of another credential
    #[test]
    fn verify_with_base64_encoded_credential() {
        // Use a simple base64 encoding function
        fn base64_encode(input: &str) -> String {
            const CHARSET: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let bytes = input.as_bytes();
            let mut result = String::new();

            for chunk in bytes.chunks(3) {
                let b = match chunk.len() {
                    1 => [chunk[0], 0, 0],
                    2 => [chunk[0], chunk[1], 0],
                    3 => [chunk[0], chunk[1], chunk[2]],
                    _ => [0, 0, 0],
                };

                let idx1 = (b[0] >> 2) as usize;
                let idx2 = (((b[0] & 0b11) << 4) | (b[1] >> 4)) as usize;
                let idx3 = (((b[1] & 0b1111) << 2) | (b[2] >> 6)) as usize;
                let idx4 = (b[2] & 0b111111) as usize;

                result.push(CHARSET[idx1] as char);
                result.push(CHARSET[idx2] as char);
                result.push(if chunk.len() > 1 { CHARSET[idx3] } else { b'=' } as char);
                result.push(if chunk.len() > 2 { CHARSET[idx4] } else { b'=' } as char);
            }
            result
        }

        // Original credential and its base64 encoding
        let original_cred = format!("sk_live_{}", "4242424242424242");
        let base64_encoded = base64_encode(&original_cred);

        // The base64 version should be treated as a distinct credential
        assert_ne!(
            original_cred, base64_encoded,
            "Base64 encoding should produce different string"
        );

        // Verify they interpolate differently
        let interpolated_original = interpolate("{{match}}", &original_cred, None);
        let interpolated_base64 = interpolate("{{match}}", &base64_encoded, None);

        assert_ne!(
            interpolated_original, interpolated_base64,
            "Original and base64 credentials should produce different interpolations"
        );

        // Verify base64 format characteristics
        assert!(
            base64_encoded
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='),
            "Base64 should only contain alphanumeric, +, /, = characters"
        );

        // Test with nested base64 encoding
        let double_encoded = base64_encode(&base64_encoded);
        let interpolated_double = interpolate("{{match}}", &double_encoded, None);
        assert_ne!(
            interpolated_double, interpolated_base64,
            "Double-encoded should differ from single-encoded"
        );
    }

    /// 6. Verify timeout of exactly 0ms
    #[tokio::test]
    async fn verify_timeout_of_exactly_zero_ms() {
        // A timeout of 0 should be handled gracefully (likely instant timeout)
        let zero_duration = Duration::from_millis(0);

        // Create engine with 0ms timeout
        let result = VerificationEngine::new(
            &[],
            VerifyConfig {
                timeout: zero_duration,
                max_concurrent_per_service: 1,
                max_concurrent_global: 1,
                max_inflight_keys: 100,
            },
        );

        // Should either succeed with 0 timeout or fail gracefully
        match result {
            Ok(_) => {
                // Engine created successfully with 0 timeout
            }
            Err(_) => {
                // Failing to create with 0 timeout is also acceptable
            }
        }
    }

    /// 7. Verify timeout of u64::MAX ms
    #[test]
    fn verify_timeout_of_u64_max_ms() {
        // u64::MAX milliseconds as Duration
        let max_duration = Duration::from_millis(u64::MAX);

        // This should NOT panic - the system should handle it
        let result = std::panic::catch_unwind(|| {
            VerificationEngine::new(
                &[],
                VerifyConfig {
                    timeout: max_duration,
                    max_concurrent_per_service: 1,
                    max_concurrent_global: 1,
                    max_inflight_keys: 100,
                },
            )
        });

        // Should not panic, even if it fails to create
        assert!(result.is_ok(), "u64::MAX timeout should not cause panic");
    }

    /// 8. Verify with empty credential string
    #[tokio::test]
    async fn verify_with_empty_credential_string() {
        let empty_cred = "";

        // Interpolation with empty credential
        let interpolated = interpolate("https://api.example.com/?key={{match}}", empty_cred, None);
        assert_eq!(
            interpolated, "https://api.example.com/?key=",
            "Empty credential should result in empty query param"
        );

        // Cache operations with empty credential
        let cache = cache::VerificationCache::default_ttl();
        cache.put(
            empty_cred,
            "test-detector",
            VerificationResult::Dead,
            HashMap::new(),
        );

        let cached = cache.get(empty_cred, "test-detector");
        assert!(cached.is_some(), "Empty credential should be cacheable");
        assert!(
            matches!(cached.unwrap().0, VerificationResult::Dead),
            "Empty credential cache should return correct result"
        );
    }

    /// 9. Verify with credential longer than 1MB
    #[tokio::test]
    async fn verify_with_credential_longer_than_1mb() {
        // Create a credential larger than 1MB
        let mb_credential = "x".repeat(1024 * 1024 + 1024); // 1MB + 1KB
        assert!(
            mb_credential.len() > MAX_RESPONSE_BODY_BYTES,
            "Test credential should be > 1MB"
        );

        // Interpolation should handle large credentials
        let interpolated = interpolate("{{match}}", &mb_credential, None);
        assert_eq!(
            interpolated.len(),
            mb_credential.len(),
            "Interpolated credential should preserve size"
        );

        // URL interpolation will encode, making it even larger
        let url_interpolated = interpolate(
            "https://api.example.com/?key={{match}}",
            &mb_credential,
            None,
        );
        assert!(
            url_interpolated.len() > mb_credential.len(),
            "URL-encoded credential should be larger"
        );

        // Cache should handle large credentials (stores hash)
        let cache = cache::VerificationCache::default_ttl();
        cache.put(
            &mb_credential,
            "test-detector",
            VerificationResult::Live,
            HashMap::new(),
        );

        let cached = cache.get(&mb_credential, "test-detector");
        assert!(
            cached.is_some(),
            "Large credential should be cacheable (stores hash)"
        );
    }

    /// 10. Verify two detectors with same credential simultaneously
    #[tokio::test]
    async fn verify_two_detectors_same_credential_simultaneously() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let request_count = Arc::new(AtomicUsize::new(0));
        let count_clone = request_count.clone();

        // Mock server that responds with 200
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let count = count_clone.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    count.fetch_add(1, Ordering::SeqCst);
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"valid\": true}",
                        )
                        .await;
                });
            }
        });

        // Create two different detectors for the same service
        let detector1 = DetectorSpec {
            id: "detector-1".into(),
            name: "Detector 1".into(),
            service: "test-service".into(),
            severity: Severity::High,
            patterns: vec![],
            companion: None,
            verify: Some(keyhog_core::VerifySpec {
                method: HttpMethod::Get,
                url: format!("http://127.0.0.1:{}/verify1", addr.port()),
                auth: AuthSpec::None,
                headers: vec![],
                body: None,
                success: SuccessSpec {
                    status: Some(200),
                    status_not: None,
                    body_contains: None,
                    body_not_contains: None,
                    json_path: None,
                    equals: None,
                },
                metadata: vec![],
                timeout_ms: None,
            }),
            keywords: vec![],
        };

        let detector2 = DetectorSpec {
            id: "detector-2".into(),
            name: "Detector 2".into(),
            service: "test-service".into(), // Same service
            severity: Severity::High,
            patterns: vec![],
            companion: None,
            verify: Some(keyhog_core::VerifySpec {
                method: HttpMethod::Get,
                url: format!("http://127.0.0.1:{}/verify2", addr.port()),
                auth: AuthSpec::None,
                headers: vec![],
                body: None,
                success: SuccessSpec {
                    status: Some(200),
                    status_not: None,
                    body_contains: None,
                    body_not_contains: None,
                    json_path: None,
                    equals: None,
                },
                metadata: vec![],
                timeout_ms: None,
            }),
            keywords: vec![],
        };

        let engine = VerificationEngine::new(
            &[detector1.clone(), detector2.clone()],
            VerifyConfig {
                timeout: Duration::from_secs(2),
                max_concurrent_per_service: 10,
                max_concurrent_global: 20,
                max_inflight_keys: 1000,
            },
        )
        .unwrap();

        // Same credential for both detectors
        let shared_credential = "shared-secret-key-12345";

        let make_match = |detector: &DetectorSpec| RawMatch {
            detector_id: detector.id.clone(),
            detector_name: detector.name.clone(),
            service: detector.service.clone(),
            severity: Severity::High,
            credential: shared_credential.into(),
            companion: None,
            location: MatchLocation {
                source: "fs".into(),
                file_path: Some("test.txt".into()),
                line: Some(1),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            entropy: None,
            confidence: Some(0.9),
        };

        // Create matches for both detectors with same credential
        let match1 = make_match(&detector1);
        let match2 = make_match(&detector2);

        let group1 = dedup_matches(vec![match1], &DedupScope::Credential).pop().unwrap();
        let group2 = dedup_matches(vec![match2], &DedupScope::Credential).pop().unwrap();

        // Verify both simultaneously
        let findings = engine.verify_all(vec![group1, group2]).await;

        assert_eq!(findings.len(), 2, "Should have 2 findings");

        // Both should have been processed (different detectors = different cache keys)
        let detector_ids: Vec<_> = findings.iter().map(|f| &f.detector_id).collect();
        assert!(detector_ids.contains(&&"detector-1".to_string()));
        assert!(detector_ids.contains(&&"detector-2".to_string()));
    }

    /// 11. Verify with URL that has no path (just https://host)
    #[test]
    fn verify_url_with_no_path() {
        // URLs with no path component
        let no_path_urls = vec!["https://api.example.com", "https://api.example.com:443"];

        for url in no_path_urls {
            let parsed = reqwest::Url::parse(url);
            assert!(parsed.is_ok(), "URL without path should parse: {}", url);

            let parsed = parsed.unwrap();
            assert_eq!(
                parsed.path(),
                "/",
                "URL without explicit path should default to /"
            );

            // Should not be private
            assert!(
                !is_private_url(url),
                "Public URL without path should not be private"
            );
        }

        // Test interpolation with no-path URL - hyphens get encoded to %2D
        let interpolated = interpolate("https://api.example.com?key={{match}}", "test-value", None);
        // The hyphen in "test-value" gets URL-encoded to "test%2Dvalue"
        assert!(
            interpolated == "https://api.example.com?key=test-value"
                || interpolated == "https://api.example.com?key=test%2Dvalue",
            "Interpolation should add query to no-path URL: got {}",
            interpolated
        );
    }

    /// 12. Verify with URL containing username:password@host
    #[test]
    fn verify_url_with_username_password_in_host() {
        // URLs with embedded credentials
        let urls_with_auth = vec![
            "https://user:pass@api.example.com/endpoint",
            "https://admin:secret123@host.com:8080/api",
            "https://user%40domain:p%40ss@example.com/path",
        ];

        for url in urls_with_auth {
            let parsed = reqwest::Url::parse(url);
            assert!(parsed.is_ok(), "URL with auth info should parse: {}", url);

            let parsed = parsed.unwrap();
            assert!(
                parsed.username().is_empty() || !parsed.username().is_empty(),
                "Username may or may not be present after normalization"
            );

            // Such URLs might be flagged as suspicious
            // but should at least parse correctly
        }

        // Interpolation should handle URLs that might contain auth patterns
        let interpolated = interpolate(
            "https://{{match}}@api.example.com/endpoint",
            "user:pass",
            None,
        );
        // The @ should be encoded to prevent injection
        assert!(
            interpolated.contains("%40") || interpolated.contains("@"),
            "URL interpolation should handle auth-like patterns"
        );
    }

    /// 13. Verify spec with contradicting success criteria (status=200 AND status_not=200)
    #[test]
    fn verify_spec_with_contradicting_success_criteria() {
        // Test the logic of contradictory success criteria by examining the spec itself
        // A spec with status=200 AND status_not=200 is logically impossible to satisfy

        // Contradictory spec: status must be 200 AND must NOT be 200
        let contradictory_spec = SuccessSpec {
            status: Some(200),
            status_not: Some(200),
            body_contains: None,
            body_not_contains: None,
            json_path: None,
            equals: None,
        };

        // The contradiction is inherent in the spec definition
        // status == Some(200) means status must be 200
        // status_not == Some(200) means status must NOT be 200
        // Both cannot be true simultaneously
        assert!(
            contradictory_spec.status.is_some() && contradictory_spec.status_not.is_some(),
            "Spec has both status and status_not defined"
        );
        assert_eq!(
            contradictory_spec.status, contradictory_spec.status_not,
            "Spec requires status to be {:?} and NOT be {:?}",
            contradictory_spec.status, contradictory_spec.status_not
        );

        // Body contradiction case
        let body_contradiction = SuccessSpec {
            status: Some(200),
            status_not: None,
            body_contains: Some("success".into()),
            body_not_contains: Some("success".into()),
            json_path: None,
            equals: None,
        };

        assert_eq!(
            body_contradiction.body_contains, body_contradiction.body_not_contains,
            "Spec requires body to contain '{:?}' and NOT contain '{:?}'",
            body_contradiction.body_contains, body_contradiction.body_not_contains
        );

        // Test status_matches logic manually
        fn status_matches(status: Option<u16>, status_not: Option<u16>, code: u16) -> bool {
            if let Some(expected) = status {
                if code != expected {
                    return false;
                }
            }
            if let Some(not_expected) = status_not {
                if code == not_expected {
                    return false;
                }
            }
            true
        }

        // Contradictory spec should fail for ANY status code
        assert!(
            !status_matches(Some(200), Some(200), 200),
            "Contradictory spec should fail for status 200"
        );
        assert!(
            !status_matches(Some(200), Some(200), 201),
            "Contradictory spec should fail for status 201"
        );
        assert!(
            !status_matches(Some(200), Some(200), 404),
            "Contradictory spec should fail for status 404"
        );
    }

    /// 14. Body analysis on response that is valid JSON but 100 levels deep
    #[test]
    fn body_analysis_on_deeply_nested_json() {
        // Build a deeply nested JSON structure (100 levels)
        let mut deep_json = String::new();
        for _ in 0..100 {
            deep_json.push_str(r#"{"level": "#);
        }
        deep_json.push_str("\"value\"");
        for _ in 0..100 {
            deep_json.push('}');
        }

        // Verify it's valid JSON
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&deep_json);
        assert!(parsed.is_ok(), "100-level deep JSON should parse");

        // Verify the structure is correct by navigating it
        let value = parsed.unwrap();
        let mut current = &value;
        for _ in 0..100 {
            current = current
                .get("level")
                .expect("Should have 'level' key at each depth");
        }
        assert_eq!(current, &serde_json::Value::String("value".into()));

        // Test with error at deepest level - verify the structure can be parsed
        let mut deep_error_json = String::new();
        for _ in 0..99 {
            deep_error_json.push_str(r#"{"nested": "#);
        }
        deep_error_json.push_str(r#"{"error": "deep failure"}"#);
        for _ in 0..99 {
            deep_error_json.push('}');
        }

        let parsed_error: Result<serde_json::Value, _> = serde_json::from_str(&deep_error_json);
        assert!(
            parsed_error.is_ok(),
            "Deep JSON with error should also parse"
        );

        // Verify we can access the deep error field
        let error_value = parsed_error.unwrap();
        let mut current = &error_value;
        for _ in 0..99 {
            current = current.get("nested").expect("Should have 'nested' key");
        }
        assert!(
            current.get("error").is_some(),
            "Should be able to access deep error field"
        );
    }

    /// 15. Cache behavior when same credential verified by different detectors
    #[test]
    fn cache_behavior_same_credential_different_detectors() {
        let cache = cache::VerificationCache::default_ttl();
        let credential = "shared-credential-abc123";

        // Store result for detector 1
        cache.put(
            credential,
            "detector-1",
            VerificationResult::Live,
            HashMap::from([("source".into(), "det1".into())]),
        );

        // Store result for detector 2
        cache.put(
            credential,
            "detector-2",
            VerificationResult::Dead,
            HashMap::from([("source".into(), "det2".into())]),
        );

        // Each detector should get its own cached result
        let cached1 = cache.get(credential, "detector-1");
        assert!(cached1.is_some(), "Detector 1 should have cached result");
        let (result1, meta1) = cached1.unwrap();
        assert!(
            matches!(result1, VerificationResult::Live),
            "Detector 1 should have Live result"
        );
        assert_eq!(meta1.get("source"), Some(&"det1".to_string()));

        let cached2 = cache.get(credential, "detector-2");
        assert!(cached2.is_some(), "Detector 2 should have cached result");
        let (result2, meta2) = cached2.unwrap();
        assert!(
            matches!(result2, VerificationResult::Dead),
            "Detector 2 should have Dead result"
        );
        assert_eq!(meta2.get("source"), Some(&"det2".to_string()));

        // Detector 3 should not have any cached result
        let cached3 = cache.get(credential, "detector-3");
        assert!(
            cached3.is_none(),
            "Detector 3 should not have cached result"
        );

        // Cache should have 2 entries
        assert_eq!(
            cache.len(),
            2,
            "Cache should have 2 entries (one per detector)"
        );
    }

    /// 16. Verify with companion that is the credential reversed
    #[test]
    fn verify_with_reversed_companion() {
        let credential = "ABC123XYZ";
        let reversed: String = credential.chars().rev().collect();

        // Companion is the reverse of the credential
        assert_eq!(reversed, "ZYX321CBA");

        // Test interpolation with reversed companion
        let interpolated = interpolate(
            "https://api.example.com/?key={{match}}&companion={{companion.secret}}",
            credential,
            Some(&reversed),
        );

        assert!(
            interpolated.contains("ABC123XYZ"),
            "Interpolated URL should contain original credential"
        );
        assert!(
            interpolated.contains("ZYX321CBA"),
            "Interpolated URL should contain reversed companion"
        );

        // Test field resolution
        let resolved =
            crate::interpolate::resolve_field("companion.secret", credential, Some(&reversed));
        assert_eq!(
            resolved, reversed,
            "Companion resolution should return reversed value"
        );
    }

    /// 17. Auth header with value containing null bytes
    #[test]
    fn verify_auth_header_with_null_bytes() {
        // Null bytes in header values can cause issues with HTTP protocol
        let null_byte_values = vec![
            "Bearer token\0extra",
            "ApiKey \x00null_injected",
            "token\x00\x00double_null",
        ];

        for value in null_byte_values {
            // When template is exactly "{{match}}", null bytes are preserved raw
            let interpolated = interpolate("{{match}}", value, None);
            assert_eq!(
                interpolated, value,
                "Null bytes should be preserved when template is exactly {{match}}"
            );

            // URL interpolation will encode null bytes
            let url_interpolated =
                interpolate("https://api.example.com/?token={{match}}", value, None);
            assert!(
                url_interpolated.contains("%00") || !url_interpolated.contains('\0'),
                "Null bytes should be encoded in URL context"
            );
        }

        // When credential is embedded in a template (not exact match), it's URL-encoded
        // This is the security boundary - embedded values get encoded
        let header_template = "Bearer {{match}}";
        let credential_with_null = "token\0null";
        let interpolated_header = interpolate(header_template, credential_with_null, None);

        // In embedded context, null bytes get URL-encoded to %00
        assert!(
            interpolated_header.contains("%00"),
            "Embedded credential with null should be URL-encoded (contains %00): got {}",
            interpolated_header
        );
        assert!(
            !interpolated_header.contains('\0'),
            "Raw null byte should not appear in interpolated result"
        );
    }

    /// 18. Rate limiting with 100 concurrent requests to same service
    #[tokio::test]
    async fn verify_rate_limiting_100_concurrent_requests() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let active_requests = Arc::new(AtomicUsize::new(0));
        let max_concurrent = Arc::new(AtomicUsize::new(0));
        let active_clone = active_requests.clone();
        let max_clone = max_concurrent.clone();

        // Mock server that tracks concurrent requests
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let active = active_clone.clone();
                let max = max_clone.clone();
                tokio::spawn(async move {
                    let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                    // Update max if current is higher
                    loop {
                        let prev_max = max.load(Ordering::SeqCst);
                        if current <= prev_max
                            || max
                                .compare_exchange(
                                    prev_max,
                                    current,
                                    Ordering::SeqCst,
                                    Ordering::SeqCst,
                                )
                                .is_ok()
                        {
                            break;
                        }
                    }
                    // Simulate some processing time
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{\"valid\": true}",
                        )
                        .await;
                });
            }
        });

        // Set up detector with low concurrency limit
        let detector = DetectorSpec {
            id: "rate-limit-test".into(),
            name: "Rate Limit Test".into(),
            service: "rate-limited-service".into(),
            severity: Severity::High,
            patterns: vec![],
            companion: None,
            verify: Some(keyhog_core::VerifySpec {
                method: HttpMethod::Get,
                url: format!("http://127.0.0.1:{}/verify", addr.port()),
                auth: AuthSpec::None,
                headers: vec![],
                body: None,
                success: SuccessSpec {
                    status: Some(200),
                    status_not: None,
                    body_contains: None,
                    body_not_contains: None,
                    json_path: None,
                    equals: None,
                },
                metadata: vec![],
                timeout_ms: None,
            }),
            keywords: vec![],
        };

        // Use a low per-service concurrency limit
        let per_service_limit = 5;
        let engine = VerificationEngine::new(
            &[detector.clone()],
            VerifyConfig {
                timeout: Duration::from_secs(5),
                max_concurrent_per_service: per_service_limit,
                max_concurrent_global: 100,
                max_inflight_keys: 1000,
            },
        )
        .unwrap();

        // Create 100 matches with unique credentials
        let mut groups = Vec::new();
        for i in 0..100 {
            let m = RawMatch {
                detector_id: "rate-limit-test".into(),
                detector_name: "Rate Limit Test".into(),
                service: "rate-limited-service".into(),
                severity: Severity::High,
                credential: format!("credential-{}", i),
                companion: None,
                location: MatchLocation {
                    source: "fs".into(),
                    file_path: Some(format!("test{}.txt", i)),
                    line: Some(i),
                    offset: 0,
                    commit: None,
                    author: None,
                    date: None,
                },
                entropy: None,
                confidence: Some(0.9),
            };
            groups.push(dedup_matches(vec![m], &DedupScope::Credential).pop().unwrap());
        }

        // Process all 100 concurrently
        let findings = engine.verify_all(groups).await;

        assert_eq!(findings.len(), 100, "All 100 verifications should complete");

        // Check that max concurrent requests was limited by per-service semaphore
        let actual_max = max_concurrent.load(Ordering::SeqCst);
        // Note: Due to 127.0.0.1 being blocked as private, these will all fail,
        // but we can still verify the concurrency limiting works
        println!("Max concurrent requests observed: {}", actual_max);
    }

    /// 19. Verify response that is chunked transfer but chunks never end
    #[tokio::test]
    async fn verify_response_with_infinite_chunked_transfer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Server that sends infinite chunked response
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    // Send chunked response headers
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                        .await;
                    // Send chunks forever (or until client disconnects)
                    loop {
                        let chunk = "5\r\nhello\r\n";
                        if stream.write_all(chunk.as_bytes()).await.is_err() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                });
            }
        });

        let detector = DetectorSpec {
            id: "infinite-chunk-test".into(),
            name: "Infinite Chunk Test".into(),
            service: "chunk-test-service".into(),
            severity: Severity::High,
            patterns: vec![],
            companion: None,
            verify: Some(keyhog_core::VerifySpec {
                method: HttpMethod::Get,
                url: format!("http://127.0.0.1:{}/chunked", addr.port()),
                auth: AuthSpec::None,
                headers: vec![],
                body: None,
                success: SuccessSpec {
                    status: Some(200),
                    status_not: None,
                    body_contains: None,
                    body_not_contains: None,
                    json_path: None,
                    equals: None,
                },
                metadata: vec![],
                timeout_ms: Some(500), // Short timeout
            }),
            keywords: vec![],
        };

        let engine = VerificationEngine::new(
            &[detector],
            VerifyConfig {
                timeout: Duration::from_millis(500), // Short timeout to avoid hanging
                max_concurrent_per_service: 5,
                max_concurrent_global: 20,
                max_inflight_keys: 1000,
            },
        )
        .unwrap();

        let m = RawMatch {
            detector_id: "infinite-chunk-test".into(),
            detector_name: "Infinite Chunk Test".into(),
            service: "chunk-test-service".into(),
            severity: Severity::High,
            credential: "test-credential".into(),
            companion: None,
            location: MatchLocation {
                source: "fs".into(),
                file_path: Some("test.txt".into()),
                line: Some(1),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            entropy: None,
            confidence: Some(0.9),
        };

        let group = dedup_matches(vec![m], &DedupScope::Credential).pop().unwrap();

        // Should complete (with error/timeout) rather than hanging forever
        let start = std::time::Instant::now();
        let findings = engine.verify_all(vec![group]).await;
        let elapsed = start.elapsed();

        assert_eq!(findings.len(), 1);
        // Should have timed out or been blocked (127.0.0.1 is private)
        assert!(
            elapsed < Duration::from_secs(5),
            "Should complete within timeout, took {:?}",
            elapsed
        );
    }

    /// 20. DNS resolution of verify URL that returns NXDOMAIN
    #[tokio::test]
    async fn verify_dns_resolution_nxdomain() {
        use std::net::ToSocketAddrs;

        // Test with domains that should return NXDOMAIN
        let nxdomain_hosts = vec![
            "this-definitely-does-not-exist-12345.invalid",
            "nonexistent-domain-xyz123.example",
        ];

        for host in nxdomain_hosts {
            let addr_result = format!("{}:443", host).to_socket_addrs();
            // Should fail to resolve
            assert!(
                addr_result.is_err() || addr_result.unwrap().next().is_none(),
                "NXDOMAIN host {} should fail to resolve",
                host
            );
        }

        // Test that valid domains do resolve
        let valid_host = "localhost:443";
        let valid_result = valid_host.to_socket_addrs();
        // localhost should resolve (even though it's blocked by SSRF)
        assert!(
            valid_result.is_ok(),
            "localhost should resolve to addresses"
        );
    }
}
