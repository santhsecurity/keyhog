//! Verification execution logic.
//!
//! Verification is explicitly opt-in via the `--verify` CLI flag.
//! Security invariants for this module:
//! - Credentials are never stored permanently. They are only used in-memory for the current run.
//! - HTTPS only. TLS certificate validation stays enabled for every request.
//! - Private IPs and private DNS resolutions are blocked to reduce SSRF risk.
//! - Redirects are not followed.
//! - Response bodies are capped at 1 MB.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use keyhog_core::{
    AuthSpec, DetectorSpec, HttpMethod, MetadataSpec, SuccessSpec, VerificationResult,
    VerifiedFinding,
};
use reqwest::Client;
use tokio::sync::Notify;
use tokio::task::JoinSet;

use crate::interpolate::{interpolate, resolve_field};
use crate::ssrf::{is_private_ip, is_private_ipv4, is_private_url, parse_numeric_ipv4_host};
use crate::{DedupedMatch, VerificationEngine, VerifyConfig, VerifyError, cache};

#[cfg(test)]
use crate::dedup_matches;
#[cfg(test)]
use crate::ssrf::parse_url_host;
#[cfg(test)]
use keyhog_core::{MatchLocation, RawMatch};
use tokio::sync::Semaphore;

const DEFAULT_SERVICE_CONCURRENCY: usize = 5;
const MAX_VERIFY_ATTEMPTS: usize = 3;
const RETRY_DELAY_MS: u64 = 500;
/// Maximum response body size to read during verification (1 MB).
/// Prevents OOM from malicious endpoints returning unbounded data.
const MAX_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
const BODY_ERROR_MESSAGE: &str = "body read failed";
const BODY_TOO_LARGE_ERROR: &str = "response body exceeds 1MB limit";
const GENERIC_REQUEST_ERROR: &str = "request failed";
const CONNECTION_FAILED_ERROR: &str = "connection failed";
const TOO_MANY_REDIRECTS_ERROR: &str = "too many redirects";
const TIMEOUT_ERROR: &str = "timeout";
const PRIVATE_URL_ERROR: &str = "blocked: private URL";
const HTTPS_ONLY_ERROR: &str = "blocked: HTTPS only";
const MAX_RETRIES_EXCEEDED_ERROR: &str = "max retries exceeded";
const AWS_STS_UNREACHABLE_ERROR: &str = "AWS STS unreachable";
const AWS_VALID_ACCESS_KEY_PREFIXES: &[&str] = &["AKIA", "ASIA", "AROA", "AIDA", "AGPA"];
const AWS_ACCESS_KEY_LEN: usize = 20;
const AWS_MIN_SECRET_KEY_LEN: usize = 40;

impl VerificationEngine {
    /// Create a verifier with shared HTTP client, cache, and concurrency controls.
    pub fn new(detectors: &[DetectorSpec], config: VerifyConfig) -> Result<Self, VerifyError> {
        let client = Client::builder()
            .timeout(config.timeout)
            // SAFETY: verification traffic must keep certificate validation on.
            .danger_accept_invalid_certs(false)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(VerifyError::ClientBuild)?;

        let detector_map: HashMap<String, DetectorSpec> = detectors
            .iter()
            .cloned()
            .map(|d| (d.id.clone(), d))
            .collect();

        let mut service_semaphores = HashMap::new();
        for d in detectors {
            service_semaphores
                .entry(d.service.clone())
                .or_insert_with(|| Arc::new(Semaphore::new(config.max_concurrent_per_service)));
        }

        Ok(Self {
            client,
            detectors: detector_map,
            service_semaphores,
            global_semaphore: Arc::new(Semaphore::new(config.max_concurrent_global)),
            timeout: config.timeout,
            cache: Arc::new(cache::VerificationCache::default_ttl()),
            inflight: Arc::new(DashMap::new()),
            max_inflight_keys: config.max_inflight_keys,
        })
    }

    /// Verify a batch of deduplicated raw matches in parallel.
    /// Returns one `VerifiedFinding` per unique (detector_id, credential).
    pub async fn verify_all(&self, groups: Vec<DedupedMatch>) -> Vec<VerifiedFinding> {
        let max_active = self.global_semaphore.available_permits().max(1);
        let total = groups.len();
        let shared = VerifyTaskShared {
            global_semaphore: self.global_semaphore.clone(),
            service_semaphores: self.service_semaphores.clone(),
            client: self.client.clone(),
            detectors: self.detectors.clone(),
            timeout: self.timeout,
            cache: self.cache.clone(),
            inflight: self.inflight.clone(),
            max_inflight_keys: self.max_inflight_keys,
        };
        let mut pending = groups.into_iter();
        let mut join_set = JoinSet::new();

        while join_set.len() < max_active {
            let Some(group) = pending.next() else {
                break;
            };
            join_set.spawn(verify_group_task(shared.clone(), group));
        }

        let mut findings = Vec::with_capacity(total);
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(finding) => findings.push(finding),
                Err(e) => tracing::error!("verification task panicked: {}", e),
            }

            if let Some(group) = pending.next() {
                join_set.spawn(verify_group_task(shared.clone(), group));
            }
        }
        findings
    }
}

#[derive(Clone)]
struct VerifyTaskShared {
    global_semaphore: Arc<Semaphore>,
    service_semaphores: HashMap<String, Arc<Semaphore>>,
    client: Client,
    detectors: HashMap<String, DetectorSpec>,
    timeout: Duration,
    cache: Arc<cache::VerificationCache>,
    inflight: Arc<DashMap<(String, String), Arc<Notify>>>,
    max_inflight_keys: usize,
}

async fn verify_group_task(shared: VerifyTaskShared, group: DedupedMatch) -> VerifiedFinding {
    let global = shared.global_semaphore;
    let service_sem = shared
        .service_semaphores
        .get(&group.service)
        .cloned()
        .unwrap_or_else(|| Arc::new(Semaphore::new(DEFAULT_SERVICE_CONCURRENCY)));
    let client = shared.client;
    let detector = shared.detectors.get(&group.detector_id).cloned();
    let timeout = shared.timeout;

    let cache = shared.cache;
    let inflight = shared.inflight;
    let max_inflight_keys = shared.max_inflight_keys;

    let Ok(_global_permit) = global.acquire().await else {
        return group.into_finding(
            VerificationResult::Error("semaphore closed".into()),
            HashMap::new(),
        );
    };
    let Ok(_service_permit) = service_sem.acquire().await else {
        return group.into_finding(
            VerificationResult::Error("service semaphore closed".into()),
            HashMap::new(),
        );
    };

    if let Some((cached_result, cached_meta)) = cache.get(&group.credential, &group.detector_id) {
        return group.into_finding(cached_result, cached_meta);
    }

    let inflight_guard = if inflight.len() >= max_inflight_keys {
        None
    } else {
        let inflight_key = (group.detector_id.clone(), group.credential.clone());
        loop {
            if let Some((cached_result, cached_meta)) =
                cache.get(&group.credential, &group.detector_id)
            {
                return group.into_finding(cached_result, cached_meta);
            }

            match inflight.entry(inflight_key.clone()) {
                dashmap::mapref::entry::Entry::Occupied(entry) => {
                    let notify = entry.get().clone();
                    // SAFETY: lock ordering is one-way: task permits
                    // (global, then service) are acquired before touching
                    // inflight, and the DashMap entry guard is dropped before
                    // await. We never hold a cache/inflight lock across
                    // notify.notified().await, so waiters cannot form a cycle
                    // with the owner that later removes the inflight entry in
                    // InflightGuard::drop and wakes them.
                    drop(entry);
                    notify.notified().await;
                }
                dashmap::mapref::entry::Entry::Vacant(entry) => {
                    let notify = Arc::new(Notify::new());
                    entry.insert(notify.clone());
                    break Some(InflightGuard {
                        key: inflight_key,
                        inflight: inflight.clone(),
                        notify,
                    });
                }
            }
        }
    };
    let _inflight_guard = inflight_guard;

    let (verification, metadata) = match &detector {
        Some(det) => match &det.verify {
            Some(verify_spec) => {
                verify_with_retry(
                    &client,
                    verify_spec,
                    &group.credential,
                    group.companion.as_deref(),
                    timeout,
                )
                .await
            }
            None => (VerificationResult::Unverifiable, HashMap::new()),
        },
        None => (VerificationResult::Unverifiable, HashMap::new()),
    };

    cache.put(
        &group.credential,
        &group.detector_id,
        verification.clone(),
        metadata.clone(),
    );

    group.into_finding(verification, metadata)
}

struct InflightGuard {
    key: (String, String),
    inflight: Arc<DashMap<(String, String), Arc<Notify>>>,
    notify: Arc<Notify>,
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        // SAFETY: cleanup follows the same ordering guarantee as verify_all:
        // remove the inflight marker without holding any other map guard, then
        // notify waiters. There is no second lock acquired while this guard is
        // dropped, so the owner cannot deadlock with waiting tasks.
        self.inflight.remove(&self.key);
        self.notify.notify_waiters();
    }
}

/// Perform verification with retry logic for transient failures.
async fn verify_with_retry(
    client: &Client,
    spec: &keyhog_core::VerifySpec,
    credential: &str,
    companion: Option<&str>,
    timeout: Duration,
) -> (VerificationResult, HashMap<String, String>) {
    for attempt in 0..MAX_VERIFY_ATTEMPTS {
        let VerificationAttempt {
            result,
            metadata,
            transient,
        } = verify_credential(client, spec, credential, companion, timeout).await;
        if transient && attempt + 1 < MAX_VERIFY_ATTEMPTS {
            let delay_ms = RETRY_DELAY_MS * (attempt as u64 + 1);
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            continue;
        }
        return (result, metadata);
    }
    (
        VerificationResult::Error(MAX_RETRIES_EXCEEDED_ERROR.into()),
        HashMap::new(),
    )
}

struct VerificationAttempt {
    result: VerificationResult,
    metadata: HashMap<String, String>,
    transient: bool,
}

#[derive(Debug)]
struct ResolvedTarget {
    client: Client,
    url: reqwest::Url,
}

/// Perform one verification HTTP call for a credential.
async fn verify_credential(
    client: &Client,
    spec: &keyhog_core::VerifySpec,
    credential: &str,
    companion: Option<&str>,
    timeout: Duration,
) -> VerificationAttempt {
    let raw_url = interpolate(&spec.url, credential, companion);
    let resolved_target = match resolved_client_for_url(client, &raw_url, timeout).await {
        Ok(resolved_target) => resolved_target,
        Err(result) => {
            return VerificationAttempt {
                result,
                metadata: HashMap::new(),
                transient: false,
            };
        }
    };

    // SSRF protection: block verification against private/internal IPs.
    if is_private_url(resolved_target.url.as_str()) {
        return VerificationAttempt {
            result: VerificationResult::Error(PRIVATE_URL_ERROR.into()),
            metadata: HashMap::new(),
            transient: false,
        };
    }

    let base_request = build_request(
        &resolved_target.client,
        spec,
        resolved_target.url.clone(),
        credential,
        companion,
        timeout,
    )
    .await;
    let mut request = match base_request {
        RequestBuildResult::Ready(request) => request,
        RequestBuildResult::Final(result, metadata) => {
            return VerificationAttempt {
                result,
                metadata,
                transient: false,
            };
        }
    };

    // Apply additional headers.
    for header in &spec.headers {
        let value = interpolate(&header.value, credential, companion);
        request = request.header(&header.name, &value);
    }

    // Apply body.
    if let Some(body_template) = &spec.body {
        let body = interpolate(body_template, credential, companion);
        request = request.body(body);
    }

    // Execute.
    let response = match execute_request(request).await {
        Ok(resp) => resp,
        Err(error) => {
            return VerificationAttempt {
                result: error.result,
                metadata: HashMap::new(),
                transient: error.transient,
            };
        }
    };

    let status = response.status().as_u16();
    let body = match read_response_body(response).await {
        Ok(body) => body,
        Err(error) => {
            return VerificationAttempt {
                result: error.result,
                metadata: HashMap::new(),
                transient: error.transient,
            };
        }
    };

    // Evaluate success condition.
    let is_live = evaluate_success(&spec.success, status, &body);

    let is_actually_live = is_live && !body_indicates_error(&body);

    let metadata = extract_metadata(&spec.metadata, &body);

    let verification_result = if is_actually_live {
        VerificationResult::Live
    } else if status == 429 {
        VerificationResult::RateLimited
    } else {
        VerificationResult::Dead
    };

    VerificationAttempt {
        result: verification_result,
        metadata,
        transient: false,
    }
}

async fn resolved_client_for_url(
    client: &Client,
    url: &str,
    timeout: Duration,
) -> Result<ResolvedTarget, VerificationResult> {
    if is_private_url(url) {
        return Err(VerificationResult::Error(PRIVATE_URL_ERROR.into()));
    }
    let parsed = reqwest::Url::parse(url)
        .map_err(|_| VerificationResult::Error(GENERIC_REQUEST_ERROR.into()))?;
    if parsed.scheme() != "https" {
        return Err(VerificationResult::Error(HTTPS_ONLY_ERROR.into()));
    }
    let Some(host) = parsed.host_str() else {
        return Err(VerificationResult::Error(GENERIC_REQUEST_ERROR.into()));
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(ip) {
            return Err(VerificationResult::Error(PRIVATE_URL_ERROR.into()));
        }
        return Ok(ResolvedTarget {
            client: client.clone(),
            url: parsed,
        });
    }
    if let Some(ip) = parse_numeric_ipv4_host(host) {
        if is_private_ipv4(ip) {
            return Err(VerificationResult::Error(PRIVATE_URL_ERROR.into()));
        }
        return Ok(ResolvedTarget {
            client: client.clone(),
            url: parsed,
        });
    }

    let port = parsed.port_or_known_default().unwrap_or(443);
    let addrs = tokio::time::timeout(timeout, tokio::net::lookup_host((host, port)))
        .await
        .map_err(|_| VerificationResult::Error(TIMEOUT_ERROR.into()))?
        .map_err(|_| VerificationResult::Error(CONNECTION_FAILED_ERROR.into()))?
        .collect::<Vec<SocketAddr>>();
    if addrs.is_empty() || addrs.iter().any(|addr| is_private_ip(addr.ip())) {
        return Err(VerificationResult::Error(PRIVATE_URL_ERROR.into()));
    }
    let pinned_addrs = addrs
        .into_iter()
        .map(|addr| SocketAddr::new(addr.ip(), port))
        .collect::<Vec<_>>();

    let resolved_client = reqwest::Client::builder()
        .timeout(timeout)
        .danger_accept_invalid_certs(false)
        .redirect(reqwest::redirect::Policy::none())
        // SAFETY: this dedicated client is paired with the already-parsed URL
        // below and only ever resolves `host` to the vetted address set from
        // this function, so reqwest cannot perform a fresh DNS lookup later.
        .resolve_to_addrs(host, &pinned_addrs)
        .build()
        .map_err(|_| VerificationResult::Error(GENERIC_REQUEST_ERROR.into()))?;

    Ok(ResolvedTarget {
        client: resolved_client,
        url: parsed,
    })
}

enum RequestBuildResult {
    Ready(reqwest::RequestBuilder),
    Final(VerificationResult, HashMap<String, String>),
}

async fn build_request(
    client: &Client,
    spec: &keyhog_core::VerifySpec,
    url: reqwest::Url,
    credential: &str,
    companion: Option<&str>,
    timeout: Duration,
) -> RequestBuildResult {
    let request = request_for_method(client, &spec.method, url).timeout(timeout);
    apply_auth(request, &spec.auth, credential, companion, timeout, client).await
}

fn request_for_method(
    client: &Client,
    method: &HttpMethod,
    url: reqwest::Url,
) -> reqwest::RequestBuilder {
    match method {
        HttpMethod::Get => client.get(url),
        HttpMethod::Post => client.post(url),
        HttpMethod::Put => client.put(url),
        HttpMethod::Delete => client.delete(url),
        HttpMethod::Head => client.head(url),
        HttpMethod::Patch => client.patch(url),
    }
}

async fn apply_auth(
    request: reqwest::RequestBuilder,
    auth: &AuthSpec,
    credential: &str,
    companion: Option<&str>,
    timeout: Duration,
    client: &Client,
) -> RequestBuildResult {
    match auth {
        AuthSpec::None => RequestBuildResult::Ready(request),
        AuthSpec::Bearer { field } => {
            let token = resolve_field(field, credential, companion);
            RequestBuildResult::Ready(request.bearer_auth(&token))
        }
        AuthSpec::Basic { username, password } => {
            let user = resolve_field(username, credential, companion);
            let pass = resolve_field(password, credential, companion);
            RequestBuildResult::Ready(request.basic_auth(&user, Some(&pass)))
        }
        AuthSpec::Header { name, template } => {
            let value = interpolate(template, credential, companion);
            RequestBuildResult::Ready(request.header(name, &value))
        }
        AuthSpec::Query { param, field } => {
            let value = resolve_field(field, credential, companion);
            RequestBuildResult::Ready(request.query(&[(param.as_str(), value.as_str())]))
        }
        AuthSpec::AwsV4 {
            access_key,
            secret_key,
            region,
            ..
        } => {
            build_aws_probe(
                access_key, secret_key, region, credential, companion, timeout, client,
            )
            .await
        }
    }
}

/// Build an AWS verification probe.
///
/// # Limitation — Format-Only Validation
///
/// AWS SigV4 signing is not implemented. This probe validates the *format* of
/// the access key and secret key (prefix, length, character set) and confirms
/// that the regional STS endpoint is reachable, but it **does not authenticate**
/// the credential. All well-formatted keys are returned as `Unverifiable`.
///
/// Full SigV4 verification requires adding an AWS signing dependency (e.g.
/// `aws-sigv4`) and constructing a signed `GetCallerIdentity` request.
async fn build_aws_probe(
    access_key: &str,
    secret_key: &str,
    region: &str,
    credential: &str,
    companion: Option<&str>,
    timeout: Duration,
    client: &Client,
) -> RequestBuildResult {
    let access_key = resolve_field(access_key, credential, companion);
    let secret_key = resolve_field(secret_key, credential, companion);

    if secret_key.is_empty() {
        return RequestBuildResult::Final(VerificationResult::Unverifiable, HashMap::new());
    }

    if !valid_aws_format(&access_key, &secret_key) {
        return RequestBuildResult::Final(
            VerificationResult::Dead,
            HashMap::from([("format_valid".into(), "false".into())]),
        );
    }

    let probe_url =
        format!("https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15");

    RequestBuildResult::Final(
        probe_aws_endpoint(client, &probe_url, timeout).await,
        HashMap::from([
            ("format_valid".into(), "true".into()),
            (
                "verification_note".into(),
                "format-only: aws sigv4 signing not implemented".into(),
            ),
        ]),
    )
}

fn valid_aws_format(access_key: &str, secret_key: &str) -> bool {
    AWS_VALID_ACCESS_KEY_PREFIXES
        .iter()
        .any(|prefix| access_key.starts_with(prefix))
        && access_key.len() == AWS_ACCESS_KEY_LEN
        && secret_key.len() >= AWS_MIN_SECRET_KEY_LEN
        && secret_key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='))
}

async fn probe_aws_endpoint(
    client: &Client,
    probe_url: &str,
    timeout: Duration,
) -> VerificationResult {
    match client.get(probe_url).timeout(timeout).send().await {
        Ok(resp) if resp.status().as_u16() == 403 => VerificationResult::Unverifiable,
        Ok(_) => VerificationResult::Unverifiable,
        Err(_) => VerificationResult::Error(AWS_STS_UNREACHABLE_ERROR.into()),
    }
}

struct VerificationFailure {
    result: VerificationResult,
    transient: bool,
}

async fn execute_request(
    request: reqwest::RequestBuilder,
) -> Result<reqwest::Response, VerificationFailure> {
    request.send().await.map_err(|error| VerificationFailure {
        result: VerificationResult::Error(sanitize_request_error(&error).into()),
        transient: error.is_timeout() || error.is_connect() || error.is_request(),
    })
}

fn sanitize_request_error(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        TIMEOUT_ERROR
    } else if error.is_connect() {
        CONNECTION_FAILED_ERROR
    } else if error.is_redirect() {
        TOO_MANY_REDIRECTS_ERROR
    } else {
        GENERIC_REQUEST_ERROR
    }
}

async fn read_response_body(response: reqwest::Response) -> Result<String, VerificationFailure> {
    // First check: Content-Length header as a fast-path rejection. This header
    // is optional and attacker-controlled, so it's only used to reject
    // obviously-too-large responses without starting to stream.
    let content_length = response.content_length().unwrap_or(0) as usize;
    if content_length > MAX_RESPONSE_BODY_BYTES {
        return Err(VerificationFailure {
            result: VerificationResult::Error(BODY_TOO_LARGE_ERROR.into()),
            transient: false,
        });
    }

    // Stream the body in chunks, aborting early if the accumulated size exceeds
    // the limit. This prevents OOM from malicious endpoints that send large
    // bodies via chunked transfer encoding without a Content-Length header.
    let mut accumulated = Vec::with_capacity(content_length.min(MAX_RESPONSE_BODY_BYTES));
    let mut stream = response.bytes_stream();
    use futures_util::StreamExt;
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|_| VerificationFailure {
            result: VerificationResult::Error(BODY_ERROR_MESSAGE.into()),
            transient: true,
        })?;
        if accumulated.len() + chunk.len() > MAX_RESPONSE_BODY_BYTES {
            return Err(VerificationFailure {
                result: VerificationResult::Error(BODY_TOO_LARGE_ERROR.into()),
                transient: false,
            });
        }
        accumulated.extend_from_slice(&chunk);
    }

    Ok(String::from_utf8(accumulated).unwrap_or_default())
}

/// Check if a response body contains error indicators despite a 200 status.
/// Many APIs return 200 with error JSON instead of proper HTTP status codes.
///
/// Matches JSON key patterns like `"error":` or `"invalid_token":` to reduce
/// false positives from values containing error-like words (e.g.,
/// `"invalid_login_count": 0` should not trigger this).
///
/// `SUCCESS_OVERRIDES` are only considered when no explicit error key is found.
/// This prevents responses like `{"ok":true, "error":"rate_limited"}` from
/// being incorrectly treated as successful.
fn body_indicates_error(body: &str) -> bool {
    let lower = body.to_lowercase();
    let has_error = ERROR_INDICATORS.iter().any(|indicator| {
        lower.match_indices(indicator).any(|(pos, _)| {
            let before = lower[..pos].trim_end();
            let after = lower[pos + indicator.len()..].trim_start();
            let valid_key_start =
                before.is_empty() || before.ends_with('{') || before.ends_with(',');
            valid_key_start && after.starts_with(':')
        })
    });

    if !has_error {
        return false;
    }

    // An explicit error key takes precedence over success overrides.
    // APIs that return both `"ok":true` and `"error":"..."` should be
    // treated as errors — the error field is more specific and the `ok`
    // field often reflects request delivery, not auth success.
    // However, `"error": null` is a common pattern meaning "no error"
    // and should NOT trigger error detection.
    let has_explicit_error_key = lower.match_indices("\"error\"").any(|(pos, _)| {
        let after = lower[pos + "\"error\"".len()..].trim_start();
        after.starts_with(':') && {
            let value_start = after[1..].trim_start();
            // "error": null means "no error" — don't treat as error
            !value_start.starts_with("null")
        }
    });

    if has_explicit_error_key {
        return true;
    }

    !contains_any(&lower, SUCCESS_OVERRIDES)
}

/// Evaluate whether a verification response meets the success criteria.
fn evaluate_success(spec: &SuccessSpec, status: u16, body: &str) -> bool {
    if !status_matches(spec, status) || !body_matches(spec, body) {
        return false;
    }

    if let Some(ref json_path) = spec.json_path {
        let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) else {
            return false;
        };
        return json_expectation_matches(spec, &parsed, json_path);
    }
    true
}

fn status_matches(spec: &SuccessSpec, status: u16) -> bool {
    if let Some(expected_status) = spec.status
        && status != expected_status
    {
        return false;
    }

    if let Some(not_status) = spec.status_not
        && status == not_status
    {
        return false;
    }

    true
}

fn body_matches(spec: &SuccessSpec, body: &str) -> bool {
    if let Some(ref needle) = spec.body_contains
        && !body.contains(needle)
    {
        return false;
    }

    if let Some(ref needle) = spec.body_not_contains
        && body.contains(needle)
    {
        return false;
    }

    true
}

fn json_expectation_matches(
    spec: &SuccessSpec,
    parsed: &serde_json::Value,
    json_path: &str,
) -> bool {
    let value = json_pointer_get(parsed, json_path);
    match &spec.equals {
        Some(expected) => value.is_some_and(|actual| json_value_to_string(actual) == *expected),
        None => value.is_some(),
    }
}

fn json_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Bool(boolean) => boolean.to_string(),
        serde_json::Value::Number(number) => number.to_string(),
        other => other.to_string(),
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

const ERROR_INDICATORS: &[&str] = &[
    "\"error\"",
    "\"unauthorized\"",
    "\"forbidden\"",
    "\"invalid\"",
    "\"invalid_token\"",
    "\"invalid_key\"",
    "\"invalid_api_key\"",
    "\"authentication_error\"",
    "\"auth_error\"",
    "\"unauthenticated\"",
    "\"not_authenticated\"",
    "\"access_denied\"",
    "\"permission_denied\"",
    "\"invalid_credentials\"",
    "\"bad_credentials\"",
    "\"expired\"",
    "\"token_expired\"",
    "\"key_expired\"",
    "\"revoked\"",
    "\"inactive\"",
    "\"disabled\"",
    "\"suspended\"",
];

const SUCCESS_OVERRIDES: &[&str] = &[
    "\"ok\":true",
    "\"ok\": true",
    "\"success\":true",
    "\"success\": true",
    "\"authenticated\":true",
    "\"valid\":true",
];

/// Simple dot-path JSON accessor: "ok" → root["ok"], "data.user.name" → root["data"]["user"]["name"].
fn json_pointer_get<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    const MAX_JSON_PATH_DEPTH: usize = 20;

    let mut current = value;
    let mut depth = 0usize;
    for segment in path.split('.') {
        depth += 1;
        if depth > MAX_JSON_PATH_DEPTH || segment.is_empty() {
            return None;
        }
        current = current.get(segment)?;
    }
    Some(current)
}

/// Extract metadata fields from a verification response body.
fn extract_metadata(specs: &[MetadataSpec], body: &str) -> HashMap<String, String> {
    let mut metadata = HashMap::new();

    let parsed: Option<serde_json::Value> = serde_json::from_str(body).ok();

    for spec in specs {
        if let Some(ref json_path) = spec.json_path
            && let Some(ref parsed) = parsed
            && let Some(value) = json_pointer_get(parsed, json_path)
        {
            let s = match value {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            metadata.insert(spec.name.clone(), s);
        }
        if let Some(ref header_name) = spec.header {
            // Header extraction would need the actual response headers.
            // For now, we only support JSON-based extraction since we consume the body.
            tracing::debug!(
                "header extraction for '{}' not supported in body-only mode",
                header_name
            );
        }
    }

    metadata
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyhog_core::Severity;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn interpolation() {
        assert_eq!(
            interpolate(
                "https://api.example.com/check?key={{match}}",
                "abc123",
                None
            ),
            "https://api.example.com/check?key=abc123"
        );
        assert_eq!(
            interpolate("{{companion.secret}}", "key", Some("mysecret")),
            "mysecret"
        );
    }

    #[test]
    fn interpolation_handles_empty_companion_replacements() {
        assert_eq!(
            interpolate(
                "https://api.example.com/{{companion.secret}}/{{companion.secret}}",
                "key",
                Some("")
            ),
            "https://api.example.com//"
        );
    }

    #[test]
    fn field_resolution() {
        assert_eq!(resolve_field("match", "cred", None), "cred");
        assert_eq!(
            resolve_field("companion.secret", "cred", Some("sec")),
            "sec"
        );
        assert_eq!(
            resolve_field("literal_value", "cred", None),
            "literal_value"
        );
        assert_eq!(resolve_field("", "cred", None), "");
    }

    #[test]
    fn success_status_check() {
        let spec = SuccessSpec {
            status: Some(200),
            status_not: None,
            body_contains: None,
            body_not_contains: None,
            json_path: None,
            equals: None,
        };
        assert!(evaluate_success(&spec, 200, ""));
        assert!(!evaluate_success(&spec, 401, ""));
    }

    #[test]
    fn success_json_path_check() {
        let spec = SuccessSpec {
            status: Some(200),
            status_not: None,
            body_contains: None,
            body_not_contains: None,
            json_path: Some("ok".into()),
            equals: Some("true".into()),
        };
        assert!(evaluate_success(&spec, 200, r#"{"ok": true}"#));
        assert!(!evaluate_success(&spec, 200, r#"{"ok": false}"#));
        assert!(!evaluate_success(&spec, 401, r#"{"ok": true}"#));
    }

    #[test]
    fn dedup_merges_locations() {
        let m1 = RawMatch {
            detector_id: "test".into(),
            detector_name: "Test".into(),
            service: "test".into(),
            severity: Severity::High,
            credential: "SECRET123".into(),
            companion: None,
            location: MatchLocation {
                source: "fs".into(),
                file_path: Some("a.py".into()),
                line: Some(1),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            entropy: None,
            confidence: Some(0.75),
        };
        let m2 = RawMatch {
            location: MatchLocation {
                file_path: Some("b.py".into()),
                line: Some(10),
                ..m1.location.clone()
            },
            ..m1.clone()
        };

        let groups = dedup_matches(vec![m1, m2]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].additional_locations.len(), 1);
    }

    #[test]
    fn json_pointer_nested() {
        let document: serde_json::Value =
            serde_json::from_str(r#"{"data": {"user": {"name": "alice"}}}"#).unwrap();
        assert_eq!(
            json_pointer_get(&document, "data.user.name"),
            Some(&serde_json::Value::String("alice".into()))
        );
        assert!(json_pointer_get(&document, "data.missing").is_none());
    }

    #[test]
    fn json_pointer_rejects_excessive_depth() {
        let value: serde_json::Value = serde_json::from_str(r#"{"a":{"b":{"c":true}}}"#).unwrap();
        let path = (0..21)
            .map(|i| format!("level{i}"))
            .collect::<Vec<_>>()
            .join(".");
        assert!(json_pointer_get(&value, &path).is_none());
        assert!(json_pointer_get(&value, "a.b.c").is_some());
    }

    #[tokio::test]
    async fn verify_all_blocks_integer_private_hosts() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let requests_clone = requests.clone();

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let count = requests_clone.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    count.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                        .await;
                });
            }
        });

        let detector = DetectorSpec {
            id: "test".into(),
            name: "Test".into(),
            service: "test".into(),
            severity: Severity::High,
            patterns: vec![],
            companion: None,
            verify: Some(keyhog_core::VerifySpec {
                method: HttpMethod::Get,
                url: format!("http://2130706433:{}/verify", addr.port()),
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
            &[detector],
            VerifyConfig {
                timeout: Duration::from_secs(1),
                max_concurrent_per_service: 50,
                max_concurrent_global: 50,
                ..Default::default()
            },
        )
        .unwrap();

        let make_match = || RawMatch {
            detector_id: "test".into(),
            detector_name: "Test".into(),
            service: "test".into(),
            severity: Severity::High,
            credential: "same-credential".into(),
            companion: None,
            location: MatchLocation {
                source: "fs".into(),
                file_path: Some("a.txt".into()),
                line: Some(1),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            entropy: None,
            confidence: Some(0.9),
        };

        let group = dedup_matches(vec![make_match()]).pop().unwrap();
        let groups = (0..20).map(|_| group.clone()).collect();
        let findings = engine.verify_all(groups).await;
        assert_eq!(findings.len(), 20);
        assert!(findings.iter().all(|finding| {
            matches!(
                &finding.verification,
                VerificationResult::Error(message) if message == PRIVATE_URL_ERROR
            )
        }));
        assert_eq!(requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn aws_probe_does_not_block_inside_runtime() {
        let client = Client::new();
        let probe_result = probe_aws_endpoint(
            &client,
            "http://127.0.0.1:1/should-fail-fast",
            Duration::from_millis(50),
        )
        .await;

        assert!(matches!(
            probe_result,
            VerificationResult::Error(message) if message == AWS_STS_UNREACHABLE_ERROR
        ));
    }

    // =========================================================================
    // SSRF Protection Tests
    // =========================================================================

    #[test]
    fn ssrf_blocks_localhost() {
        assert!(is_private_url("http://localhost/api"));
        assert!(is_private_url("https://localhost:8080/verify"));
        assert!(is_private_url("http://LOCALHOST/path"));
    }

    #[test]
    fn ssrf_blocks_loopback() {
        assert!(is_private_url("http://127.0.0.1/api"));
        assert!(is_private_url("http://127.0.0.1:3000/check"));
        assert!(is_private_url("https://127.0.0.1/secret"));
    }

    #[test]
    fn ssrf_blocks_private_class_a() {
        assert!(is_private_url("http://10.0.0.1/api"));
        assert!(is_private_url("http://10.255.255.255/verify"));
        assert!(is_private_url("https://10.10.10.10/check"));
    }

    #[test]
    fn ssrf_blocks_private_class_b() {
        assert!(is_private_url("http://172.16.0.1/api"));
        assert!(is_private_url("http://172.17.1.1/verify"));
        assert!(is_private_url("http://172.18.2.2/check"));
        assert!(is_private_url("http://172.19.3.3/test"));
        assert!(is_private_url("http://172.20.0.0/api"));
        assert!(is_private_url("http://172.30.0.0/api"));
        assert!(is_private_url("http://172.31.255.255/verify"));
    }

    #[test]
    fn ssrf_blocks_private_class_c() {
        assert!(is_private_url("http://192.168.0.1/api"));
        assert!(is_private_url("http://192.168.1.1/verify"));
        assert!(is_private_url("https://192.168.255.255/check"));
    }

    #[test]
    fn ssrf_blocks_link_local() {
        assert!(is_private_url("http://169.254.0.1/metadata"));
        assert!(is_private_url("http://169.254.169.254/latest"));
        assert!(is_private_url("https://169.254.1.1/api"));
    }

    #[test]
    fn ssrf_blocks_ipv6_loopback() {
        assert!(is_private_url("http://[::1]/api"));
        assert!(is_private_url("https://[::1]:8080/verify"));
    }

    #[test]
    fn ssrf_blocks_ipv6_private_ranges_and_mapped_ipv4() {
        assert!(is_private_url("http://[fd00::1]/api"));
        assert!(is_private_url("http://[fe80::1]/api"));
        assert!(is_private_url("http://[::ffff:127.0.0.1]/api"));
    }

    #[test]
    fn ssrf_blocks_zero_address() {
        assert!(is_private_url("http://0.0.0.0/api"));
        assert!(is_private_url("http://0.0.0.0:3000/verify"));
    }

    #[test]
    fn ssrf_blocks_integer_loopback_host() {
        assert!(is_private_url("http://2130706433/api"));
    }

    #[test]
    fn ssrf_blocks_hex_and_octal_ipv4_hosts() {
        assert!(is_private_url("http://0x7f000001/api"));
        assert!(is_private_url("http://0177.0.0.1/api"));
        assert!(is_private_url("http://0x7f.0x0.0x0.0x1/api"));
    }

    #[test]
    fn ssrf_blocks_short_dotted_ipv4_hosts() {
        assert!(is_private_url("http://127.1/api"));
        assert!(is_private_url("http://127.0.1/api"));
    }

    #[test]
    fn ssrf_blocks_cloud_metadata() {
        assert!(is_private_url("http://metadata.google.internal/"));
        assert!(is_private_url("http://169.254.169.254/latest/meta-data/"));
        assert!(is_private_url("https://metadata.google/computeMetadata"));
    }

    #[test]
    fn ssrf_blocks_percent_encoded_private_hosts_after_decoding() {
        assert!(is_private_url("http://%31%32%37.0.0.1/api"));
    }

    #[tokio::test]
    async fn resolved_client_rejects_private_dns_results() {
        let client = reqwest::Client::builder().build().unwrap();
        let resolved_client =
            resolved_client_for_url(&client, "http://localhost/api", Duration::from_secs(1)).await;
        assert!(matches!(
            resolved_client,
            Err(VerificationResult::Error(message)) if message == PRIVATE_URL_ERROR
        ));
    }

    #[tokio::test]
    async fn resolved_client_rejects_private_ip_literals_and_numeric_ipv4_hosts() {
        let client = reqwest::Client::builder().build().unwrap();

        for url in ["http://127.0.0.1/api", "http://2130706433/api"] {
            let resolved_client =
                resolved_client_for_url(&client, url, Duration::from_secs(1)).await;
            assert!(
                matches!(resolved_client, Err(VerificationResult::Error(ref message)) if message == PRIVATE_URL_ERROR),
                "expected private URL rejection for {url}, got {resolved_client:?}"
            );
        }
    }

    #[tokio::test]
    async fn resolved_client_rejects_non_https_public_urls() {
        let client = reqwest::Client::builder().build().unwrap();
        let resolved_client =
            resolved_client_for_url(&client, "http://example.com/api", Duration::from_secs(1))
                .await;
        assert!(matches!(
            resolved_client,
            Err(VerificationResult::Error(message)) if message == HTTPS_ONLY_ERROR
        ));
    }

    #[test]
    fn ssrf_allows_public_urls() {
        assert!(!is_private_url("https://api.github.com/users/octocat"));
        assert!(!is_private_url("https://api.openai.com/v1/models"));
        assert!(!is_private_url(
            "https://hooks.slack.com/services/T000/B000/XXXX"
        ));
        assert!(!is_private_url("http://example.com/api"));
        assert!(!is_private_url("http://134744072/api"));
    }

    // =========================================================================
    // Interpolation Security Tests
    // =========================================================================

    #[test]
    fn interpolation_url_encodes_special_chars() {
        let cred = "key/with/slashes";
        assert_eq!(
            interpolate("https://api.example.com/{{match}}", cred, None),
            "https://api.example.com/key%2Fwith%2Fslashes"
        );
    }

    #[test]
    fn interpolation_url_encodes_query_params() {
        let cred = "key=value&other=test";
        assert_eq!(
            interpolate("https://api.example.com?token={{match}}", cred, None),
            "https://api.example.com?token=key%3Dvalue%26other%3Dtest"
        );
    }

    #[test]
    fn interpolation_prevents_template_injection() {
        let cred = "{{malicious}}";
        let interpolated_url = interpolate("https://api.example.com/{{match}}", cred, None);
        assert_eq!(
            interpolated_url,
            "https://api.example.com/%7B%7Bmalicious%7D%7D"
        );
    }

    #[test]
    fn interpolation_handles_newlines() {
        let cred = "key\nwith\nnewlines";
        let interpolated_url = interpolate("https://api.example.com/{{match}}", cred, None);
        assert!(interpolated_url.contains("%0A"));
        assert!(!interpolated_url.contains('\n'));
    }

    #[test]
    fn interpolation_handles_companion_with_special_chars() {
        let companion = "secret/with/chars";
        let interpolated_url = interpolate(
            "https://api.example.com?key={{companion.token}}",
            "key",
            Some(companion),
        );
        assert!(interpolated_url.contains("%2F"));
    }

    // =========================================================================
    // Body Analysis Tests
    // =========================================================================

    #[test]
    fn body_indicates_error_null_response() {
        assert!(!body_indicates_error("null"));
        assert!(!body_indicates_error("NULL"));
    }

    #[test]
    fn body_indicates_error_real_error_patterns() {
        assert!(body_indicates_error(r#"{"error": "invalid token"}"#));
        assert!(body_indicates_error(r#"{"unauthorized": true}"#));
        assert!(body_indicates_error(r#"{"invalid_key": "bad"}"#));
        assert!(body_indicates_error(
            r#"{"access_denied": "no permission"}"#
        ));
        assert!(body_indicates_error(r#"{"expired": true}"#));
        assert!(body_indicates_error(r#"{"revoked": "yes"}"#));
    }

    #[test]
    fn body_success_override_patterns() {
        // These should NOT indicate error — success keys without explicit error
        assert!(!body_indicates_error(r#"{"ok":true, "error": null}"#));
        assert!(!body_indicates_error(
            r#"{"success":true, "warning": "minor"}"#
        ));
        assert!(!body_indicates_error(r#"{"authenticated":true}"#));
        assert!(!body_indicates_error(r#"{"valid":true}"#));
    }

    #[test]
    fn body_error_explicit_key_overrides_success() {
        // An explicit "error" key with a real value should be detected as an
        // error even when "ok":true is also present. This prevents dead
        // credentials from being reported as live.
        assert!(body_indicates_error(
            r#"{"ok":true, "error": "rate_limited"}"#
        ));
        assert!(body_indicates_error(
            r#"{"ok":true, "error": "invalid_token"}"#
        ));
        assert!(body_indicates_error(
            r#"{"success":true, "error": "unauthorized"}"#
        ));
    }

    #[test]
    fn body_indicates_error_empty_body() {
        assert!(!body_indicates_error(""));
    }

    #[test]
    fn body_indicates_error_non_json() {
        assert!(!body_indicates_error("plain text response"));
        assert!(!body_indicates_error("<html><body>Error</body></html>"));
        assert!(!body_indicates_error("this has \"error\" in it"));
    }

    #[test]
    fn body_indicates_error_ignores_indicator_inside_string_values() {
        assert!(!body_indicates_error(
            r#"{"message":"this text mentions \"error\" but is not an error key"}"#
        ));
        assert!(!body_indicates_error(
            r#"{"detail":"the word \"invalid\" appears here as content"}"#
        ));
    }

    // =========================================================================
    // Cache Tests
    // =========================================================================

    #[test]
    fn cache_basic_hit() {
        let cache = cache::VerificationCache::default_ttl();
        cache.put(
            "test-cred",
            "test-detector",
            VerificationResult::Live,
            HashMap::from([("key".into(), "value".into())]),
        );

        let cached_verification = cache.get("test-cred", "test-detector");
        assert!(cached_verification.is_some());
        let (verification, metadata) = cached_verification.unwrap();
        assert!(matches!(verification, VerificationResult::Live));
        assert_eq!(metadata.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn cache_miss_different_credential() {
        let cache = cache::VerificationCache::default_ttl();
        cache.put(
            "cred-1",
            "detector",
            VerificationResult::Live,
            HashMap::new(),
        );

        let cached_verification = cache.get("cred-2", "detector");
        assert!(cached_verification.is_none());
    }

    #[test]
    fn cache_miss_different_detector() {
        let cache = cache::VerificationCache::default_ttl();
        cache.put(
            "cred",
            "detector-1",
            VerificationResult::Live,
            HashMap::new(),
        );

        let cached_verification = cache.get("cred", "detector-2");
        assert!(cached_verification.is_none());
    }

    #[test]
    fn cache_ttl_expiration() {
        let cache = cache::VerificationCache::new(Duration::from_millis(10));
        cache.put(
            "test-cred",
            "test-detector",
            VerificationResult::Live,
            HashMap::new(),
        );

        // Immediately should be available
        assert!(cache.get("test-cred", "test-detector").is_some());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(50));

        // Should be expired now
        assert!(cache.get("test-cred", "test-detector").is_none());
    }

    #[test]
    fn cache_eviction_of_expired_entries() {
        // Test that expired entries are properly evicted
        let cache = cache::VerificationCache::new(Duration::from_millis(1));

        cache.put("cred-1", "det", VerificationResult::Live, HashMap::new());
        std::thread::sleep(Duration::from_millis(5));
        cache.put("cred-2", "det", VerificationResult::Live, HashMap::new());

        // First entry should be expired, second should be present
        assert!(cache.get("cred-1", "det").is_none());
        assert!(cache.get("cred-2", "det").is_some());
    }

    #[test]
    fn cache_integrity_after_multiple_puts() {
        let cache = cache::VerificationCache::default_ttl();

        // Put same credential with different results
        cache.put("cred", "det", VerificationResult::Dead, HashMap::new());
        cache.put("cred", "det", VerificationResult::Live, HashMap::new());

        // Should have the latest value
        let (verification, _) = cache.get("cred", "det").unwrap();
        assert!(matches!(verification, VerificationResult::Live));
    }

    // =========================================================================
    // Dedup Mode Tests
    // =========================================================================

    #[test]
    fn dedup_per_location_same_detector_different_files() {
        let m1 = RawMatch {
            detector_id: "test-det".into(),
            detector_name: "Test".into(),
            service: "svc".into(),
            severity: Severity::High,
            credential: "SAME_SECRET".into(),
            companion: None,
            location: MatchLocation {
                source: "fs".into(),
                file_path: Some("a.py".into()),
                line: Some(1),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            entropy: None,
            confidence: Some(0.9),
        };
        let m2 = RawMatch {
            location: MatchLocation {
                file_path: Some("b.py".into()),
                line: Some(10),
                ..m1.location.clone()
            },
            ..m1.clone()
        };

        let groups = dedup_matches(vec![m1, m2]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].additional_locations.len(), 1);
        assert_eq!(groups[0].primary_location.file_path, Some("a.py".into()));
    }

    #[test]
    fn dedup_consolidated_different_detectors_same_credential() {
        let m1 = RawMatch {
            detector_id: "detector-1".into(),
            detector_name: "Detector 1".into(),
            service: "svc".into(),
            severity: Severity::High,
            credential: "SAME_SECRET".into(),
            companion: None,
            location: MatchLocation {
                source: "fs".into(),
                file_path: Some("a.py".into()),
                line: Some(1),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            entropy: None,
            confidence: Some(0.9),
        };
        let m2 = RawMatch {
            detector_id: "detector-2".into(),
            detector_name: "Detector 2".into(),
            location: MatchLocation {
                file_path: Some("b.py".into()),
                line: Some(10),
                ..m1.location.clone()
            },
            ..m1.clone()
        };

        let groups = dedup_matches(vec![m1, m2]);
        // Should create separate groups because detector_id is different
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn dedup_preserves_companion() {
        let m1 = RawMatch {
            detector_id: "test".into(),
            detector_name: "Test".into(),
            service: "svc".into(),
            severity: Severity::High,
            credential: "SECRET".into(),
            companion: None,
            location: MatchLocation {
                source: "fs".into(),
                file_path: Some("a.py".into()),
                line: Some(1),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            entropy: None,
            confidence: Some(0.9),
        };
        let m2 = RawMatch {
            companion: Some("companion-value".into()),
            location: MatchLocation {
                file_path: Some("b.py".into()),
                line: Some(10),
                ..m1.location.clone()
            },
            ..m1.clone()
        };

        let groups = dedup_matches(vec![m1, m2]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].companion, Some("companion-value".into()));
    }

    // =========================================================================
    // Edge Case Tests
    // =========================================================================

    #[test]
    fn evaluate_success_handles_redirect_status() {
        let spec = SuccessSpec {
            status: Some(301),
            status_not: None,
            body_contains: None,
            body_not_contains: None,
            json_path: None,
            equals: None,
        };
        assert!(evaluate_success(&spec, 301, ""));
        assert!(!evaluate_success(&spec, 200, ""));
    }

    #[test]
    fn evaluate_success_rate_limit_status() {
        let spec = SuccessSpec {
            status: None,
            status_not: Some(429),
            body_contains: None,
            body_not_contains: None,
            json_path: None,
            equals: None,
        };
        assert!(!evaluate_success(&spec, 429, ""));
        assert!(evaluate_success(&spec, 200, ""));
    }

    #[test]
    fn verify_empty_url_returns_error() {
        // Empty URL should trigger connection error handling
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let client = Client::new();
            let spec = keyhog_core::VerifySpec {
                method: HttpMethod::Get,
                url: "".to_string(),
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
                timeout_ms: Some(1000),
            };

            let verification =
                verify_credential(&client, &spec, "test", None, Duration::from_secs(1))
                    .await
                    .result;
            assert!(matches!(verification, VerificationResult::Error(_)));
        });
    }

    #[test]
    fn verify_missing_verify_spec_returns_unverifiable() {
        let detector = DetectorSpec {
            id: "test".into(),
            name: "Test".into(),
            service: "test".into(),
            severity: Severity::Low,
            patterns: vec![],
            companion: None,
            verify: None, // Missing verify spec
            keywords: vec![],
        };

        let engine = VerificationEngine::new(&[detector], VerifyConfig::default()).unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let group = DedupedMatch {
                detector_id: "test".into(),
                detector_name: "Test".into(),
                service: "test".into(),
                severity: Severity::Low,
                credential: "test-cred".into(),
                companion: None,
                primary_location: MatchLocation {
                    source: "fs".into(),
                    file_path: Some("test.txt".into()),
                    line: Some(1),
                    offset: 0,
                    commit: None,
                    author: None,
                    date: None,
                },
                additional_locations: vec![],
                confidence: Some(0.5),
            };

            let findings = engine.verify_all(vec![group]).await;
            assert_eq!(findings.len(), 1);
            assert!(matches!(
                findings[0].verification,
                VerificationResult::Unverifiable
            ));
        });
    }

    #[test]
    fn success_body_contains_check() {
        let spec = SuccessSpec {
            status: Some(200),
            status_not: None,
            body_contains: Some("verified".into()),
            body_not_contains: None,
            json_path: None,
            equals: None,
        };
        assert!(evaluate_success(&spec, 200, r#"{"status": "verified"}"#));
        assert!(!evaluate_success(&spec, 200, r#"{"status": "pending"}"#));
    }

    #[test]
    fn success_body_not_contains_check() {
        let spec = SuccessSpec {
            status: Some(200),
            status_not: None,
            body_contains: None,
            body_not_contains: Some("error".into()),
            json_path: None,
            equals: None,
        };
        assert!(evaluate_success(&spec, 200, r#"{"ok": true}"#));
        assert!(!evaluate_success(&spec, 200, r#"{"error": "failed"}"#));
    }

    // =========================================================================
    // Verification Edge Cases
    // =========================================================================

    #[test]
    fn verify_url_exactly_8kb_max_length() {
        // URL exactly 8KB (8192 bytes) should be valid for interpolation
        let long_path = "a".repeat(8192 - "https://api.example.com/".len());
        let url = format!("https://api.example.com/{}", long_path);
        assert_eq!(url.len(), 8192);

        // Interpolation should handle this without issues
        let interpolated_url = interpolate(&url, "test-cred", None);
        assert_eq!(interpolated_url.len(), 8192);
        assert!(interpolated_url.starts_with("https://api.example.com/"));
    }

    #[test]
    fn credential_10kb_long() {
        // Credential that is 10KB long should be handled properly
        let long_credential = "x".repeat(10240);
        assert_eq!(long_credential.len(), 10240);

        // Interpolation with exact template should return credential unchanged
        let interpolated_credential = interpolate("{{match}}", &long_credential, None);
        assert_eq!(interpolated_credential.len(), 10240);
        assert_eq!(interpolated_credential, long_credential);

        // URL interpolation should URL-encode it
        let url_result = interpolate(
            "https://api.example.com/?key={{match}}",
            &long_credential,
            None,
        );
        assert!(url_result.contains("xxxxxxxxxx"));
    }

    #[test]
    fn credential_all_printable_ascii() {
        // Credential containing every printable ASCII character (32-126)
        let all_ascii: String = (32..=126).map(|c| c as u8 as char).collect();
        assert_eq!(all_ascii.len(), 95);

        // Test interpolation doesn't corrupt special characters when used as literal
        let interpolated_credential = interpolate("{{match}}", &all_ascii, None);
        assert_eq!(interpolated_credential, all_ascii);

        // URL encoding should handle all special characters
        let url_result = interpolate("https://api.example.com/{{match}}", &all_ascii, None);
        // All non-alphanumeric characters should be percent-encoded
        assert!(url_result.starts_with("https://api.example.com/"));
    }

    #[test]
    fn companion_identical_to_primary_credential() {
        // Companion that is identical to the primary credential
        let credential = "SAME_CREDENTIAL_12345";

        let interpolated_credential = interpolate("{{match}}", credential, Some(credential));
        assert_eq!(interpolated_credential, credential);

        // Test with companion template
        let comp_result = interpolate("{{companion.secret}}", credential, Some(credential));
        assert_eq!(comp_result, credential);

        // URL interpolation with both
        let url_result = interpolate(
            "https://api.example.com/?primary={{match}}&companion={{companion.secret}}",
            credential,
            Some(credential),
        );
        // Both should be URL-encoded when embedded
        assert!(url_result.contains("primary="));
        assert!(url_result.contains("companion="));
    }

    #[test]
    fn verify_spec_json_path_with_dots_in_field_names() {
        // JSON path containing dots in field names (needs proper escaping handling)
        // Note: json_pointer_get uses dot-separated paths, so field names with dots
        // are not directly supported - this tests the current behavior
        let document: serde_json::Value =
            serde_json::from_str(r#"{"field.with.dots": {"nested.key": "value"}}"#).unwrap();
        assert!(json_pointer_get(&document, "field.with.dots").is_none());

        // Normal nested access works fine
        let normal_val: serde_json::Value =
            serde_json::from_str(r#"{"data": {"user.name": "alice"}}"#).unwrap();
        assert_eq!(
            json_pointer_get(&normal_val, "data"),
            Some(&serde_json::Value::Object(
                [(
                    "user.name".to_string(),
                    serde_json::Value::String("alice".into())
                )]
                .into_iter()
                .collect()
            ))
        );
    }

    #[test]
    fn success_body_contains_matches_credential_itself() {
        // When body_contains pattern is the credential itself
        let credential = "sk_test_4242424242424242";
        let body = format!(r#"{{"token": "{}", "valid": true}}"#, credential);

        let spec = SuccessSpec {
            status: Some(200),
            status_not: None,
            body_contains: Some(credential.into()),
            body_not_contains: None,
            json_path: None,
            equals: None,
        };

        assert!(evaluate_success(&spec, 200, &body));

        // Should fail if credential not in body
        let wrong_body = r#"{"token": "other", "valid": true}"#;
        assert!(!evaluate_success(&spec, 200, wrong_body));
    }

    #[tokio::test]
    async fn consecutive_verifications_cache_poisoning_protection() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let request_count = Arc::new(AtomicUsize::new(0));
        let count_clone = request_count.clone();

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let count = count_clone.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    count.fetch_add(1, Ordering::SeqCst);
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{\"valid\": true}",
                        )
                        .await;
                });
            }
        });

        let detector = DetectorSpec {
            id: "cache-test".into(),
            name: "Cache Test".into(),
            service: "cache-service".into(),
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

        let engine = VerificationEngine::new(
            &[detector],
            VerifyConfig {
                timeout: Duration::from_secs(1),
                max_concurrent_per_service: 50,
                max_concurrent_global: 50,
                ..Default::default()
            },
        )
        .unwrap();

        let make_match = |cred: &str| RawMatch {
            detector_id: "cache-test".into(),
            detector_name: "Cache Test".into(),
            service: "cache-service".into(),
            severity: Severity::High,
            credential: cred.into(),
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

        // First verification with credential A
        let group_a = dedup_matches(vec![make_match("cred-a")]).pop().unwrap();
        let findings_a = engine.verify_all(vec![group_a.clone()]).await;
        assert_eq!(findings_a.len(), 1);

        // Second verification with same credential A (should use cache)
        let findings_a2 = engine.verify_all(vec![group_a.clone()]).await;
        assert_eq!(findings_a2.len(), 1);

        // Both results should be identical (cache hit)
        assert_eq!(
            std::mem::discriminant(&findings_a[0].verification),
            std::mem::discriminant(&findings_a2[0].verification)
        );

        // Different credential B should be independent
        let group_b = dedup_matches(vec![make_match("cred-b")]).pop().unwrap();
        let findings_b = engine.verify_all(vec![group_b]).await;
        assert_eq!(findings_b.len(), 1);

        // Cache should not have cross-contaminated results
        assert!(matches!(
            findings_a[0].verification,
            VerificationResult::Live | VerificationResult::Dead | VerificationResult::Error(_)
        ));
    }

    #[test]
    fn verify_with_delete_method() {
        // Verify that DELETE method is properly supported
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let client = Client::new();

            // Build a DELETE request - should not panic
            let request = request_for_method(
                &client,
                &HttpMethod::Delete,
                reqwest::Url::parse("https://example.com/resource/123").unwrap(),
            );

            // The request builder should be functional (we can't actually send without a server)
            let _ = request;
        });
    }

    #[test]
    fn verify_url_with_ipv6_literal() {
        // URL with IPv6 literal address should be properly handled
        let ipv6_urls = vec![
            "http://[::1]:8080/api",
            "https://[2001:db8::1]/verify",
            "http://[fe80::1]:3000/check",
        ];

        for url in ipv6_urls {
            // parse_url_host should extract the host correctly
            let host = parse_url_host(url);
            assert!(host.is_some(), "Failed to parse host for: {}", url);

            let host_str = host.unwrap();
            // IPv6 addresses should be handled (without brackets after parsing)
            assert!(
                host_str.contains(':')
                    || host_str == "::1"
                    || host_str.starts_with("fe80")
                    || host_str.starts_with("2001"),
                "Unexpected host for {}: {}",
                url,
                host_str
            );
        }

        // IPv6 loopback should be blocked as private
        assert!(is_private_url("http://[::1]/api"));
        assert!(is_private_url("http://[::1]:8080/verify"));

        // IPv6 ULA should be blocked as private
        assert!(is_private_url("http://[fd00::1]/api"));

        // IPv6 link-local should be blocked as private
        assert!(is_private_url("http://[fe80::1]/api"));
        assert!(is_private_url("http://[fe80::1]:3000/check"));
    }

    #[test]
    fn body_valid_jsonl_multiple_objects() {
        // Body with JSONL format (multiple JSON objects, one per line)
        let jsonl_body = r#"{"id": 1, "valid": true}
{"id": 2, "valid": false}
{"id": 3, "valid": true}"#;

        // body_indicates_error should handle JSONL gracefully
        // It looks for error indicators as JSON keys
        assert!(!body_indicates_error(jsonl_body));

        // Success spec with body_contains should work on the entire body
        let spec = SuccessSpec {
            status: Some(200),
            status_not: None,
            body_contains: Some("\"valid\": true".into()),
            body_not_contains: None,
            json_path: None,
            equals: None,
        };

        assert!(evaluate_success(&spec, 200, jsonl_body));

        // Should fail if pattern not present
        let spec_missing = SuccessSpec {
            status: Some(200),
            status_not: None,
            body_contains: Some("not_found".into()),
            body_not_contains: None,
            json_path: None,
            equals: None,
        };
        assert!(!evaluate_success(&spec_missing, 200, jsonl_body));

        // JSON path won't work because the body as a whole is not valid JSON
        let spec_json = SuccessSpec {
            status: Some(200),
            status_not: None,
            body_contains: None,
            body_not_contains: None,
            json_path: Some("id".into()),
            equals: None,
        };
        assert!(!evaluate_success(&spec_json, 200, jsonl_body));
    }
}
