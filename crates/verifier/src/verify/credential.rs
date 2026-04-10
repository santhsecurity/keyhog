use std::collections::HashMap;
use std::time::Duration;

use keyhog_core::{AuthSpec, HttpMethod, VerificationResult};
use reqwest::Client;

use crate::interpolate::interpolate;
use crate::verify::multi_step::verify_multi_step;
use crate::verify::{
    RequestBuildResult, body_indicates_error, build_request_for_step, evaluate_success,
    execute_request, extract_metadata, read_response_body, resolved_client_for_url,
};

const MAX_VERIFY_ATTEMPTS: usize = 3;
const RETRY_DELAY_MS: u64 = 500;

pub(crate) struct VerificationAttempt {
    pub result: VerificationResult,
    pub metadata: HashMap<String, String>,
    pub transient: bool,
}

pub(crate) async fn verify_with_retry(
    client: &Client,
    spec: &keyhog_core::VerifySpec,
    credential: &str,
    companions: &HashMap<String, String>,
    timeout: Duration,
    allow_private_ips: bool,
) -> (VerificationResult, HashMap<String, String>) {
    let mut last_error = None;

    for attempt in 0..MAX_VERIFY_ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS * attempt as u64)).await;
        }

        let attempt_result = verify_credential(
            client,
            spec,
            credential,
            companions,
            timeout,
            allow_private_ips,
        )
        .await;

        if !attempt_result.transient {
            return (attempt_result.result, attempt_result.metadata);
        }

        last_error = Some(attempt_result.result);
    }

    (
        last_error.unwrap_or(VerificationResult::Error("max retries exceeded".into())),
        HashMap::new(),
    )
}

pub(crate) async fn verify_credential(
    client: &Client,
    spec: &keyhog_core::VerifySpec,
    credential: &str,
    companions: &HashMap<String, String>,
    timeout: Duration,
    allow_private_ips: bool,
) -> VerificationAttempt {
    if !spec.steps.is_empty() {
        return verify_multi_step(
            client,
            spec,
            credential,
            companions,
            timeout,
            allow_private_ips,
        )
        .await;
    }

    let url_template = spec.url.as_deref().unwrap_or("");
    let method = spec.method.as_ref().unwrap_or(&HttpMethod::Get);
    let auth = spec.auth.as_ref().unwrap_or(&AuthSpec::None);
    let success = spec.success.as_ref();

    // Auth methods like AwsV4 construct their own URL and make their own request.
    // Skip URL resolution for these — go directly to the auth handler.
    let is_self_constructing_auth = matches!(auth, AuthSpec::AwsV4 { .. });

    if url_template.is_empty() && !is_self_constructing_auth {
        return VerificationAttempt {
            result: VerificationResult::Unverifiable,
            metadata: HashMap::new(),
            transient: false,
        };
    }

    let timeout = verification_timeout(spec, timeout);

    // For self-constructing auth with no URL, use a placeholder URL — the auth
    // handler will construct the real request independently.
    let base_request = if is_self_constructing_auth && url_template.is_empty() {
        build_request_for_step(
            client,
            method,
            auth,
            reqwest::Url::parse("https://placeholder.invalid").unwrap(),
            credential,
            companions,
            timeout,
        )
        .await
    } else {
        let raw_url = interpolate(url_template, credential, companions);
        let resolved_target =
            match resolved_client_for_url(client, &raw_url, timeout, allow_private_ips).await {
                Ok(resolved_target) => resolved_target,
                Err(result) => {
                    return VerificationAttempt {
                        result,
                        metadata: HashMap::new(),
                        transient: false,
                    };
                }
            };

        build_request_for_step(
            &resolved_target.client,
            method,
            auth,
            resolved_target.url.clone(),
            credential,
            companions,
            timeout,
        )
        .await
    };
    let mut request = match base_request {
        RequestBuildResult::Ready(request) => request,
        RequestBuildResult::Final {
            result,
            metadata,
            transient,
        } => {
            return VerificationAttempt {
                result,
                metadata,
                transient,
            };
        }
    };

    for header in &spec.headers {
        let value = interpolate(&header.value, credential, companions);
        request = request.header(&header.name, &value);
    }

    if let Some(body_template) = &spec.body {
        let body = interpolate(body_template, credential, companions);
        request = request.body(body);
    }

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

    let is_live = if let Some(s) = success {
        evaluate_success(s, status, &body)
    } else {
        status == 200
    };

    let is_actually_live = is_live && !body_indicates_error(&body);
    let metadata = extract_metadata(&spec.metadata, &body);

    let verification_result = if is_actually_live {
        VerificationResult::Live
    } else if status == 429 || (500..=504).contains(&status) {
        if status == 429 {
            crate::rate_limit::get_rate_limiter()
                .update_limit(&spec.service, 0.5)
                .await;
        }
        VerificationResult::RateLimited
    } else {
        VerificationResult::Dead
    };

    VerificationAttempt {
        result: verification_result,
        metadata,
        transient: status == 429 || (500..=504).contains(&status),
    }
}

pub(crate) fn verification_timeout(
    spec: &keyhog_core::VerifySpec,
    default_timeout: Duration,
) -> Duration {
    spec.timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(default_timeout)
}
