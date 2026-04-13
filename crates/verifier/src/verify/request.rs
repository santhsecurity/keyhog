use std::collections::HashMap;
use std::time::Duration;

use keyhog_core::{HttpMethod, VerificationResult};
use reqwest::Client;

use crate::ssrf::is_private_url;

pub(crate) const PRIVATE_URL_ERROR: &str = "blocked: private URL";
pub(crate) const HTTPS_ONLY_ERROR: &str = "blocked: HTTPS only";

pub(crate) struct ResolvedTarget {
    pub client: Client,
    pub url: reqwest::Url,
}

pub(crate) enum RequestBuildResult {
    Ready(reqwest::RequestBuilder),
    Final {
        result: VerificationResult,
        metadata: HashMap<String, String>,
        transient: bool,
    },
}

pub(crate) struct RequestError {
    pub result: VerificationResult,
    pub transient: bool,
}

pub(crate) async fn resolved_client_for_url(
    _client: &Client,
    raw_url: &str,
    _timeout: Duration,
    allow_private_ips: bool,
) -> std::result::Result<ResolvedTarget, VerificationResult> {
    let url = match reqwest::Url::parse(raw_url) {
        Ok(url) => url,
        Err(e) => return Err(VerificationResult::Error(format!("invalid URL: {}", e))),
    };

    // SSRF check MUST come before HTTPS-only check to prevent information leakage
    // about internal network topology via error message differentiation.
    if !allow_private_ips && is_private_url(url.as_str()) {
        return Err(VerificationResult::Error(PRIVATE_URL_ERROR.into()));
    }

    if url.scheme() != "https"
        && !url.as_str().contains("localhost")
        && !url.as_str().contains("127.0.0.1")
    {
        return Err(VerificationResult::Error(HTTPS_ONLY_ERROR.into()));
    }

    Ok(ResolvedTarget {
        client: _client.clone(),
        url,
    })
}

pub(crate) async fn build_request_for_step(
    client: &Client,
    method: &HttpMethod,
    auth: &keyhog_core::AuthSpec,
    url: reqwest::Url,
    credential: &str,
    companions: &HashMap<String, String>,
    timeout: Duration,
) -> RequestBuildResult {
    let request = request_for_method(client, method, url).timeout(timeout);
    crate::verify::auth::build_request_for_auth(
        request, auth, credential, companions, timeout, client,
    )
    .await
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
        HttpMethod::Patch => client.patch(url),
        HttpMethod::Head => client.head(url),
    }
}

pub(crate) async fn execute_request(
    request: reqwest::RequestBuilder,
) -> std::result::Result<reqwest::Response, RequestError> {
    request.send().await.map_err(|e| RequestError {
        result: if e.is_timeout() {
            VerificationResult::Error("timeout".into())
        } else if e.is_redirect() {
            VerificationResult::Error("too many redirects".into())
        } else if e.is_connect() {
            VerificationResult::Error("connection failed".into())
        } else {
            VerificationResult::Error("request failed".into())
        },
        transient: e.is_timeout() || e.is_connect(),
    })
}
