//! S3 bucket source: lists text-like objects with ListObjectsV2 and downloads
//! each candidate object for scanning. Large or non-text objects are skipped.

use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime};

use hmac::{Hmac, Mac};
use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use quick_xml::Reader;
use quick_xml::de::{Deserializer, PredefinedEntityResolver};
use quick_xml::events::Event;
use reqwest::blocking::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};

const DEFAULT_S3_HOST_SUFFIX: &str = "s3.amazonaws.com";
const S3_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_OBJECTS: usize = 100_000;
const MAX_S3_OBJECT_BYTES: u64 = 10 * 1024 * 1024;
const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Scan text objects in an S3 bucket via the ListObjectsV2 REST API.
pub struct S3Source {
    bucket: String,
    prefix: Option<String>,
    endpoint: Option<String>,
    max_objects: usize,
}

impl S3Source {
    /// Create a source that lists and downloads text objects from `bucket`.
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            prefix: None,
            endpoint: None,
            max_objects: DEFAULT_MAX_OBJECTS,
        }
    }

    /// Limit scanning to objects whose keys start with `prefix`.
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// Override the S3 endpoint, for example for MinIO or other S3-compatible APIs.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Limit the number of objects listed from the bucket before stopping.
    pub fn with_max_objects(mut self, max_objects: usize) -> Self {
        self.max_objects = max_objects;
        self
    }
}

impl Source for S3Source {
    fn name(&self) -> &str {
        "s3"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        match collect_s3_chunks(
            &self.bucket,
            self.prefix.as_deref(),
            self.endpoint.as_deref(),
            self.max_objects,
        ) {
            Ok(chunks) => Box::new(chunks.into_iter().map(Ok)),
            Err(error) => Box::new(std::iter::once(Err(error))),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListBucketResult {
    #[serde(default)]
    contents: Vec<ListObject>,
    #[serde(default)]
    is_truncated: bool,
    #[serde(default)]
    next_continuation_token: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ListObject {
    key: String,
    #[serde(default)]
    size: u64,
}

fn collect_s3_chunks(
    bucket: &str,
    prefix: Option<&str>,
    endpoint: Option<&str>,
    max_objects: usize,
) -> Result<Vec<Chunk>, SourceError> {
    let bucket = validate_bucket_name(bucket)?;
    let client = Client::builder()
        .timeout(S3_REQUEST_TIMEOUT)
        .build()
        .map_err(|e| SourceError::Other(format!("failed to build S3 client: {e}")))?;
    let base_url = build_base_url(&bucket, endpoint)?;
    let aws_auth = AwsSigV4Config::from_env(&base_url);
    let mut continuation_token = None::<String>;
    let mut chunks = Vec::new();
    let mut listed_objects = 0usize;

    loop {
        if listed_objects >= max_objects {
            break;
        }

        let mut request = client.get(&base_url).query(&[("list-type", "2")]);
        if let Some(prefix) = prefix {
            request = request.query(&[("prefix", prefix)]);
        }
        if let Some(token) = continuation_token.as_deref() {
            request = request.query(&[("continuation-token", token)]);
        }
        if let Some(auth) = aws_auth.as_ref() {
            request = auth.sign(request, &base_url)?;
        }

        let response = request
            .send()
            .map_err(|e| SourceError::Other(format!("failed to list S3 objects: {e}")))?;

        if !response.status().is_success() {
            return Err(SourceError::Other(format!(
                "failed to list S3 objects: bucket request returned {}",
                response.status()
            )));
        }

        let body = response
            .text()
            .map_err(|e| SourceError::Other(format!("failed to read S3 listing: {e}")))?;
        let listing = parse_s3_listing(&body)?;
        let remaining = max_objects.saturating_sub(listed_objects);
        let reached_limit = listing.contents.len() > remaining;

        for object in listing.contents.into_iter().take(remaining) {
            listed_objects += 1;
            if object.size == 0 || !is_probably_text(&object.key) {
                continue;
            }

            if let Some(chunk) = fetch_object_chunk(
                &client,
                &base_url,
                &bucket,
                &object.key,
                object.size,
                aws_auth.as_ref(),
            )? {
                chunks.push(chunk);
            }
        }

        if reached_limit || !listing.is_truncated {
            break;
        }
        continuation_token = listing.next_continuation_token;
        if continuation_token.is_none() {
            break;
        }
    }

    Ok(chunks)
}

fn fetch_object_chunk(
    client: &Client,
    base_url: &str,
    bucket: &str,
    key: &str,
    object_size: u64,
    aws_auth: Option<&AwsSigV4Config>,
) -> Result<Option<Chunk>, SourceError> {
    if object_size > MAX_S3_OBJECT_BYTES {
        tracing::debug!(
            "failed to read S3 object: {}/{} exceeds {} byte limit with {} bytes",
            bucket,
            key,
            MAX_S3_OBJECT_BYTES,
            object_size
        );
        return Ok(None);
    }

    let encoded_key = encode_s3_key_path(key);
    let url = format!("{}/{}", base_url.trim_end_matches('/'), encoded_key);
    let request = client.get(&url);
    let request = if let Some(auth) = aws_auth {
        auth.sign(request, &url)?
    } else {
        request
    };
    let response = request
        .send()
        .map_err(|e| SourceError::Other(format!("failed to download S3 object: {key}: {e}")))?;

    if !response.status().is_success() {
        return Ok(None);
    }

    if let Some(content_length) = response.content_length()
        && content_length > MAX_S3_OBJECT_BYTES
    {
        tracing::debug!(
            "failed to read S3 object: {}/{} content-length {} exceeds {} byte limit",
            bucket,
            key,
            content_length,
            MAX_S3_OBJECT_BYTES
        );
        return Ok(None);
    }

    // Skip objects that declare a binary content type — they won't contain text secrets.
    if let Some(ct) = response.headers().get("content-type").and_then(|v| v.to_str().ok()) {
        let ct_lower = ct.to_ascii_lowercase();
        if ct_lower.starts_with("image/")
            || ct_lower.starts_with("audio/")
            || ct_lower.starts_with("video/")
            || ct_lower == "application/octet-stream"
            || ct_lower == "application/zip"
            || ct_lower == "application/gzip"
        {
            tracing::debug!("skipping S3 object {key}: binary content-type {ct}");
            return Ok(None);
        }
    }

    // Read the response body with a hard size cap. The blocking client
    // lacks byte-stream support, so we use `copy()` into a size-limited
    // buffer to abort before the full response is buffered into memory.
    let mut body = Vec::new();
    let mut reader = response
        .take(MAX_S3_OBJECT_BYTES + 1);
    std::io::Read::read_to_end(&mut reader, &mut body)
        .map_err(|e| SourceError::Other(format!("failed to read S3 object body: {key}: {e}")))?;
    if body.len() as u64 > MAX_S3_OBJECT_BYTES {
        tracing::debug!(
            "failed to read S3 object: {}/{} downloaded size exceeds {} byte limit",
            bucket,
            key,
            MAX_S3_OBJECT_BYTES
        );
        return Ok(None);
    }
    let object_text = match String::from_utf8(body) {
        Ok(text) => text,
        Err(_) => return Ok(None),
    };

    Ok(Some(Chunk {
        data: object_text,
        metadata: ChunkMetadata {
            source_type: "s3".into(),
            path: Some(format!("{bucket}/{key}")),
            commit: None,
            author: None,
            date: None,
        },
    }))
}

#[derive(Clone)]
struct AwsSigV4Config {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    region: String,
}

impl AwsSigV4Config {
    fn from_env(base_url: &str) -> Option<Self> {
        let access_key_id = std::env::var("AWS_ACCESS_KEY_ID").ok()?;
        let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY").ok()?;
        let region = std::env::var("AWS_REGION")
            .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
            .ok()
            .or_else(|| infer_s3_region(base_url))
            .unwrap_or_else(|| "us-east-1".into());
        Some(Self {
            access_key_id,
            secret_access_key,
            session_token: std::env::var("AWS_SESSION_TOKEN").ok(),
            region,
        })
    }

    fn sign(
        &self,
        request: reqwest::blocking::RequestBuilder,
        url: &str,
    ) -> Result<reqwest::blocking::RequestBuilder, SourceError> {
        let now = chrono::DateTime::<chrono::Utc>::from(SystemTime::now());
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| SourceError::Other(format!("invalid S3 URL for signing: {e}")))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| SourceError::Other("missing host in S3 URL".into()))?;
        let canonical_uri = if parsed.path().is_empty() {
            "/"
        } else {
            parsed.path()
        };
        let canonical_query = canonical_query_string(&parsed);

        let mut canonical_headers = format!(
            "host:{host}\nx-amz-content-sha256:{EMPTY_PAYLOAD_SHA256}\nx-amz-date:{amz_date}\n"
        );
        let mut signed_headers = "host;x-amz-content-sha256;x-amz-date".to_string();
        if let Some(token) = &self.session_token {
            canonical_headers.push_str(&format!("x-amz-security-token:{token}\n"));
            signed_headers.push_str(";x-amz-security-token");
        }

        let canonical_request = format!(
            "GET\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{EMPTY_PAYLOAD_SHA256}"
        );
        let credential_scope = format!("{date_stamp}/{}/s3/aws4_request", self.region);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{:x}",
            Sha256::digest(canonical_request.as_bytes())
        );
        let signature = hex::encode(signing_key(
            &self.secret_access_key,
            &date_stamp,
            &self.region,
            "s3",
            &string_to_sign,
        )?);
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={signature}",
            self.access_key_id, credential_scope, signed_headers
        );

        let mut request = request
            .header("x-amz-date", amz_date)
            .header("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256)
            .header("Authorization", authorization);
        if let Some(token) = &self.session_token {
            request = request.header("x-amz-security-token", token);
        }
        Ok(request)
    }
}

fn infer_s3_region(base_url: &str) -> Option<String> {
    let host = reqwest::Url::parse(base_url).ok()?.host_str()?.to_string();
    let parts: Vec<&str> = host.split('.').collect();
    let s3_idx = parts.iter().position(|part| *part == "s3")?;
    let region = parts.get(s3_idx + 1)?;
    if region.starts_with("amazonaws") {
        None
    } else {
        Some((*region).to_string())
    }
}

fn canonical_query_string(url: &reqwest::Url) -> String {
    let mut pairs = url
        .query_pairs()
        .map(|(key, value)| (aws_uri_encode(&key), aws_uri_encode(&value)))
        .collect::<Vec<_>>();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn aws_uri_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn signing_key(
    secret: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
    string_to_sign: &str,
) -> Result<Vec<u8>, SourceError> {
    let date_key = hmac_sha256(format!("AWS4{secret}").as_bytes(), date_stamp.as_bytes())?;
    let region_key = hmac_sha256(&date_key, region.as_bytes())?;
    let service_key = hmac_sha256(&region_key, service.as_bytes())?;
    let signing_key = hmac_sha256(&service_key, b"aws4_request")?;
    hmac_sha256(&signing_key, string_to_sign.as_bytes())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, SourceError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|e| SourceError::Other(format!("failed to initialize S3 signer: {e}")))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn build_base_url(bucket: &str, endpoint: Option<&str>) -> Result<String, SourceError> {
    match endpoint {
        Some(endpoint) => {
            let endpoint = validate_endpoint(endpoint)?;
            Ok(format!(
                "{}/{}",
                endpoint.trim_end_matches('/'),
                urlencoding::encode(bucket)
            ))
        }
        None => Ok(format!("https://{bucket}.{DEFAULT_S3_HOST_SUFFIX}")),
    }
}

fn validate_bucket_name(bucket: &str) -> Result<String, SourceError> {
    let bucket = bucket.trim();
    if bucket.len() < 3 || bucket.len() > 63 {
        return Err(SourceError::Other("invalid S3 bucket name length".into()));
    }
    if bucket.starts_with('.')
        || bucket.ends_with('.')
        || bucket.starts_with('-')
        || bucket.ends_with('-')
        || bucket.contains("..")
        || bucket.contains('/')
        || bucket.chars().any(char::is_control)
    {
        return Err(SourceError::Other(format!("invalid S3 bucket '{bucket}'")));
    }
    if !bucket
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '-'))
    {
        return Err(SourceError::Other(format!("invalid S3 bucket '{bucket}'")));
    }
    Ok(bucket.to_string())
}

fn validate_endpoint(endpoint: &str) -> Result<String, SourceError> {
    let endpoint = endpoint.trim();
    let parsed = reqwest::Url::parse(endpoint)
        .map_err(|e| SourceError::Other(format!("invalid S3 endpoint: {e}")))?;

    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(SourceError::Other("invalid S3 endpoint".into()));
    }

    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

fn encode_s3_key_path(key: &str) -> String {
    let mut encoded = String::with_capacity(key.len());
    let mut segment = String::new();
    for ch in key.chars() {
        if ch == '/' {
            encoded.push_str(&urlencoding::encode(&segment));
            encoded.push('/');
            segment.clear();
        } else {
            segment.push(ch);
        }
    }
    encoded.push_str(&urlencoding::encode(&segment));
    encoded
}

fn parse_s3_listing(body: &str) -> Result<ListBucketResult, SourceError> {
    if contains_forbidden_xml_markup(body) {
        return Err(SourceError::Other(
            "S3 XML response contains unsupported DTD/entity declarations".into(),
        ));
    }

    let mut reader = Reader::from_str(body);
    loop {
        match reader.read_event() {
            Ok(Event::DocType(_)) => {
                return Err(SourceError::Other(
                    "S3 XML response contains unsupported DOCTYPE declarations".into(),
                ));
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(err) => {
                return Err(SourceError::Other(format!(
                    "failed to validate S3 ListObjectsV2 XML: {err}"
                )));
            }
        }
    }

    let mut deserializer = Deserializer::from_str_with_resolver(body, PredefinedEntityResolver);
    ListBucketResult::deserialize(&mut deserializer)
        .map_err(|e| SourceError::Other(format!("failed to parse S3 ListObjectsV2 XML: {e}")))
}

fn contains_forbidden_xml_markup(body: &str) -> bool {
    let upper = body.to_ascii_uppercase();
    // SAFETY: S3 ListObjectsV2 responses do not require DTDs or custom entity
    // declarations, so rejecting those markers at the raw-body boundary keeps
    // parser behavior simple and avoids later entity-expansion surprises.
    upper.contains("<!DOCTYPE") || upper.contains("<!ENTITY")
}

fn is_probably_text(key: &str) -> bool {
    let ext = Path::new(key)
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());

    !matches!(
        ext.as_deref(),
        Some(
            "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "webp"
                | "zip"
                | "gz"
                | "tgz"
                | "tar"
                | "7z"
                | "pdf"
                | "woff"
                | "woff2"
                | "mp3"
                | "mp4"
                | "mov"
                | "dll"
                | "so"
                | "dylib"
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_source_defaults_to_max_objects_limit() {
        let source = S3Source::new("bucket");
        assert_eq!(source.max_objects, DEFAULT_MAX_OBJECTS);
    }

    #[test]
    fn s3_source_allows_custom_max_objects_limit() {
        let source = S3Source::new("bucket").with_max_objects(42);
        assert_eq!(source.max_objects, 42);
    }

    #[test]
    fn default_base_url_uses_virtual_host_style() {
        assert_eq!(
            build_base_url("acme-secrets", None).unwrap(),
            "https://acme-secrets.s3.amazonaws.com"
        );
    }

    #[test]
    fn custom_endpoint_uses_path_style() {
        assert_eq!(
            build_base_url("acme-secrets", Some("https://minio.internal")).unwrap(),
            "https://minio.internal/acme-secrets"
        );
    }

    #[test]
    fn rejects_invalid_custom_endpoint() {
        assert!(build_base_url("acme-secrets", Some("https://user:pass@minio.internal")).is_err());
        assert!(build_base_url("acme-secrets", Some("ftp://minio.internal")).is_err());
    }

    #[test]
    fn rejects_invalid_bucket_names() {
        assert!(validate_bucket_name("../escape").is_err());
        assert!(validate_bucket_name("UPPERCASE").is_err());
        assert!(validate_bucket_name("ok-bucket").is_ok());
    }

    #[test]
    fn s3_key_encoding_preserves_path_separators() {
        assert_eq!(
            encode_s3_key_path("folder/my file.txt"),
            "folder/my%20file.txt"
        );
    }

    #[test]
    fn oversized_s3_objects_are_skipped_before_download() {
        let client = Client::builder().build().unwrap();
        let fetched_chunk = fetch_object_chunk(
            &client,
            "https://example.invalid/bucket",
            "bucket",
            "huge.txt",
            MAX_S3_OBJECT_BYTES + 1,
            None,
        )
        .unwrap();
        assert!(fetched_chunk.is_none());
    }

    #[test]
    fn canonical_query_string_sorts_and_encodes_values() {
        let url = reqwest::Url::parse("https://bucket.s3.amazonaws.com/?b=two words&a=1").unwrap();
        assert_eq!(canonical_query_string(&url), "a=1&b=two%20words");
    }

    #[test]
    fn rejects_s3_xml_with_doctype() {
        let err = parse_s3_listing(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE ListBucketResult [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<ListBucketResult></ListBucketResult>"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("DOCTYPE"));
    }

    #[test]
    fn rejects_s3_xml_with_entity_declaration_marker() {
        let err = parse_s3_listing(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <!ENTITY xxe "boom">
</ListBucketResult>"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("DTD/entity"));
    }
}
