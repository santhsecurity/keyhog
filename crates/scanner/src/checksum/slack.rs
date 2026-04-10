use super::{ChecksumResult, ChecksumValidator};

/// Validates Slack token structure.
///
/// Slack tokens do not expose a public checksum algorithm, but their format is
/// highly regular. This validator performs strict structural matching and
/// rejects tokens that violate known segment rules.
pub struct SlackTokenValidator;

impl SlackTokenValidator {
    fn is_valid_slack_bot(credential: &str) -> bool {
        let re = regex::Regex::new(r"^xoxb-[0-9]{10,15}-[0-9]{10,15}-[a-zA-Z0-9]{24,34}$").expect(
            "Slack bot regex is static and must compile. Fix: correct the hard-coded pattern",
        );
        if re.is_match(credential) {
            return true;
        }
        let re2 = regex::Regex::new(r"^xoxb-[0-9]{10,15}-[0-9]{10,15}-[0-9A-Za-z]{15,40}$").expect(
            "Slack fallback regex is static and must compile. Fix: correct the hard-coded pattern",
        );
        re2.is_match(credential)
    }

    fn is_valid_slack_user(credential: &str) -> bool {
        let re = regex::Regex::new(r"^xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}$")
            .expect(
                "Slack user regex is static and must compile. Fix: correct the hard-coded pattern",
            );
        if re.is_match(credential) {
            return true;
        }
        let re2 =
            regex::Regex::new(r"^xoxp-[0-9]{10,15}-[0-9]{10,15}-[a-zA-Z0-9]{24,34}$").expect(
                "Slack user fallback regex is static and must compile. Fix: correct the hard-coded pattern",
            );
        re2.is_match(credential)
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
