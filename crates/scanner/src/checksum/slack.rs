use std::sync::LazyLock;

use super::{ChecksumResult, ChecksumValidator};

/// Validates Slack token structure.
///
/// Slack tokens do not expose a public checksum algorithm, but their format is
/// highly regular. This validator performs strict structural matching and
/// rejects tokens that violate known segment rules.
pub struct SlackTokenValidator;

// Compile once, reuse across all validate() calls.
static SLACK_BOT_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^xoxb-[0-9]{10,15}-[0-9]{10,15}-[a-zA-Z0-9]{15,40}$")
        .expect("hardcoded regex")
});
static SLACK_USER_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"^xoxp-[0-9]{10,15}-[0-9]{10,15}(?:-[0-9]{10,13})?-[a-zA-Z0-9]{24,40}$")
        .expect("hardcoded regex")
});

impl SlackTokenValidator {
    fn is_valid_slack_bot(credential: &str) -> bool {
        SLACK_BOT_RE.is_match(credential)
    }

    fn is_valid_slack_user(credential: &str) -> bool {
        SLACK_USER_RE.is_match(credential)
    }
}

impl ChecksumValidator for SlackTokenValidator {
    fn validator_id(&self) -> &str {
        "slack-token"
    }

    fn validate(&self, credential: &str) -> ChecksumResult {
        if credential.starts_with("xoxb-") {
            if Self::is_valid_slack_bot(credential) {
                ChecksumResult::Valid
            } else {
                ChecksumResult::Invalid
            }
        } else if credential.starts_with("xoxp-") {
            if Self::is_valid_slack_user(credential) {
                ChecksumResult::Valid
            } else {
                ChecksumResult::Invalid
            }
        } else {
            ChecksumResult::NotApplicable
        }
    }
}
