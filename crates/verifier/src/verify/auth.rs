use std::collections::HashMap;
use std::time::Duration;

use keyhog_core::{AuthSpec, VerificationResult};
use reqwest::Client;

use crate::interpolate::{interpolate, resolve_field};
use crate::verify::{RequestBuildResult, build_aws_probe};

pub(crate) async fn build_request_for_auth(
    request: reqwest::RequestBuilder,
    auth: &AuthSpec,
    credential: &str,
    companions: &HashMap<String, String>,
    timeout: Duration,
    client: &Client,
) -> RequestBuildResult {
    match auth {
        AuthSpec::None => RequestBuildResult::Ready(request),
        AuthSpec::Bearer { field } => {
            let token = resolve_field(field, credential, companions);
            RequestBuildResult::Ready(request.bearer_auth(token))
        }
        AuthSpec::Basic { username, password } => {
            let u = resolve_field(username, credential, companions);
            let p = resolve_field(password, credential, companions);
            RequestBuildResult::Ready(request.basic_auth(u, Some(p)))
        }
        AuthSpec::Header { name, template } => {
            let value = interpolate(template, credential, companions);
            RequestBuildResult::Ready(request.header(name, value))
        }
        AuthSpec::Query { param, field } => {
            let value = resolve_field(field, credential, companions);
            RequestBuildResult::Ready(request.query(&[(param, value)]))
        }
        AuthSpec::AwsV4 {
            access_key,
            secret_key,
            session_token,
            region,
            ..
        } => {
            build_aws_probe(
                access_key,
                secret_key,
                session_token,
                region,
                credential,
                companions,
                timeout,
                client,
            )
            .await
        }
        AuthSpec::Script { engine, code } => {
            let variables = companions.clone();
            match codewalk::sandbox::execute_script(
                engine,
                code,
                "verification_target",
                "custom_verify",
                &variables,
                timeout,
            )
            .await
            {
                Ok(output) => {
                    if output.contains("STATUS: LIVE") {
                        RequestBuildResult::Final {
                            result: VerificationResult::Live,
                            metadata: HashMap::new(),
                            transient: false,
                        }
                    } else {
                        RequestBuildResult::Final {
                            result: VerificationResult::Dead,
                            metadata: HashMap::new(),
                            transient: false,
                        }
                    }
                }
                Err(e) => RequestBuildResult::Final {
                    result: VerificationResult::Error(e.to_string()),
                    metadata: HashMap::new(),
                    transient: true,
                },
            }
        }
    }
}
