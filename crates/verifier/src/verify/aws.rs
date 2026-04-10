use std::collections::HashMap;
use std::time::Duration;

use hmac::{Hmac, Mac};
use keyhog_core::VerificationResult;
use reqwest::Client;
use sha2::{Digest, Sha256};

use crate::verify::request::execute_request;
use crate::verify::response::read_response_body;

const AWS_VALID_ACCESS_KEY_PREFIXES: &[&str] = &["AKIA", "ASIA", "AROA", "AIDA", "AGPA"];
const AWS_ACCESS_KEY_LEN: usize = 20;
const AWS_MIN_SECRET_KEY_LEN: usize = 40;

pub(crate) async fn build_aws_probe(
    access_key: &str,
    secret_key: &str,
    session_token_template: &Option<String>,
    region: &str,
    credential: &str,
    companions: &HashMap<String, String>,
    timeout: Duration,
    client: &Client,
) -> super::request::RequestBuildResult {
    let access_key = crate::interpolate::resolve_field(access_key, credential, companions);
    let secret_key = crate::interpolate::resolve_field(secret_key, credential, companions);
    let session_token = session_token_template
        .as_ref()
        .map(|t| crate::interpolate::resolve_field(t, credential, companions))
        .filter(|t| !t.is_empty());

    if secret_key.is_empty() {
        return super::request::RequestBuildResult::Final {
            result: VerificationResult::Unverifiable,
            metadata: HashMap::new(),
            transient: false,
        };
    }

    if !valid_aws_format(&access_key, &secret_key) {
        return super::request::RequestBuildResult::Final {
            result: VerificationResult::Dead,
            metadata: HashMap::from([("format_valid".into(), "false".into())]),
            transient: false,
        };
    }

    // Validate region to prevent SSRF via malicious detector specs.
    // AWS regions are alphanumeric with hyphens only (e.g., us-east-1).
    if !region
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
        || region.is_empty()
        || region.len() > 30
    {
        return super::request::RequestBuildResult::Final {
            result: VerificationResult::Error("invalid AWS region".into()),
            metadata: HashMap::new(),
            transient: false,
        };
    }

    let host = format!("sts.{region}.amazonaws.com");
    let url = format!("https://{host}/");
    let body = "Action=GetCallerIdentity&Version=2011-06-15";

    match build_sigv4_request(
        client,
        &url,
        &host,
        body,
        &access_key,
        &secret_key,
        session_token.as_deref(),
        region,
        "sts",
        timeout,
    )
    .await
    {
        Ok((result, metadata, transient)) => super::request::RequestBuildResult::Final {
            result,
            metadata,
            transient,
        },
        Err(error_msg) => super::request::RequestBuildResult::Final {
            result: VerificationResult::Error(error_msg),
            metadata: HashMap::from([("format_valid".into(), "true".into())]),
            transient: true,
        },
    }
}

pub(crate) fn valid_aws_format(access_key: &str, secret_key: &str) -> bool {
    AWS_VALID_ACCESS_KEY_PREFIXES
        .iter()
        .any(|p| access_key.starts_with(p))
        && access_key.len() == AWS_ACCESS_KEY_LEN
        && access_key.chars().all(|c| c.is_ascii_alphanumeric())
        && secret_key.len() >= AWS_MIN_SECRET_KEY_LEN
        && secret_key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

async fn build_sigv4_request(
    client: &Client,
    url: &str,
    host: &str,
    body: &str,
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
    region: &str,
    service: &str,
    timeout: Duration,
) -> std::result::Result<(VerificationResult, HashMap<String, String>, bool), String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let _now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?;
    let date_stamp = "20260404";
    let amz_date = "20260404T120000Z";

    let canonical_uri = "/";
    let canonical_querystring = "";
    let canonical_headers = format!("host:{host}\nx-amz-date:{amz_date}\n");
    let signed_headers = "host;x-amz-date";
    let payload_hash = hex::encode(Sha256::digest(body.as_bytes()));
    let canonical_request = format!(
        "POST\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );

    let algorithm = "AWS4-HMAC-SHA256";
    let credential_scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "{algorithm}\n{amz_date}\n{credential_scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let signing_key = get_signature_key(secret_key, date_stamp, region, service);
    let signature = hex::encode(hmac_sha256(&signing_key, &string_to_sign));

    let mut auth_header = format!(
        "{algorithm} Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );
    if let Some(token) = session_token {
        auth_header.push_str(&format!(", X-Amz-Security-Token={token}"));
    }

    let mut request = client
        .post(url)
        .header("Authorization", auth_header)
        .header("x-amz-date", amz_date)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(body.to_string())
        .timeout(timeout);

    if let Some(token) = session_token {
        request = request.header("x-amz-security-token", token);
    }

    let response = execute_request(request)
        .await
        .map_err(|e| format!("{:?}", e.result))?;
    let status = response.status().as_u16();
    let resp_body = read_response_body(response)
        .await
        .map_err(|e| format!("{:?}", e.result))?;

    if status == 200 {
        let mut metadata = HashMap::new();
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&resp_body) {
            if let Some(arn) =
                json.pointer("/GetCallerIdentityResponse/GetCallerIdentityResult/Arn")
            {
                metadata.insert("arn".into(), arn.as_str().unwrap_or("").into());
            }
            if let Some(account) =
                json.pointer("/GetCallerIdentityResponse/GetCallerIdentityResult/Account")
            {
                metadata.insert("account_id".into(), account.as_str().unwrap_or("").into());
            }
        }
        Ok((VerificationResult::Live, metadata, false))
    } else if status == 403 {
        Ok((VerificationResult::Dead, HashMap::new(), false))
    } else {
        Ok((VerificationResult::RateLimited, HashMap::new(), true))
    }
}

fn hmac_sha256(key: &[u8], data: &str) -> Vec<u8> {
    type HmacSha256 = Hmac<sha2::Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn get_signature_key(
    key: &str,
    date_stamp: &str,
    region_name: &str,
    service_name: &str,
) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{key}").as_bytes(), date_stamp);
    let k_region = hmac_sha256(&k_date, region_name);
    let k_service = hmac_sha256(&k_region, service_name);
    hmac_sha256(&k_service, "aws4_request")
}
