use super::github::{base62_encode_u32, crc32};
use super::*;
use base64::Engine;

fn make_github_classic(entropy: &str) -> String {
    assert_eq!(entropy.len(), 30);
    let checksum = base62_encode_u32(crc32(entropy.as_bytes()), 6);
    format!("ghp_{entropy}{checksum}")
}

fn make_github_fine_grained(id: &str, entropy: &str) -> String {
    assert_eq!(id.len(), 22);
    assert_eq!(entropy.len(), 53);
    let payload = format!("{id}_{entropy}");
    let checksum = base62_encode_u32(crc32(payload.as_bytes()), 6);
    format!("github_pat_{payload}{checksum}")
}

fn make_npm(entropy: &str) -> String {
    assert_eq!(entropy.len(), 30);
    let checksum = base62_encode_u32(crc32(entropy.as_bytes()), 6);
    format!("npm_{entropy}{checksum}")
}

#[test]
fn crc32_known_values() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b""), 0x0000_0000);
    assert_eq!(crc32(b"test"), 0xD87F_7E0C);
}

#[test]
fn github_classic_valid() {
    let token = make_github_classic("zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ");
    assert_eq!(
        GithubClassicPatValidator.validate(&token),
        ChecksumResult::Valid
    );
}

#[test]
fn github_classic_all_as_valid() {
    let token = make_github_classic(&"A".repeat(30));
    assert_eq!(
        GithubClassicPatValidator.validate(&token),
        ChecksumResult::Valid
    );
}

#[test]
fn github_classic_invalid_checksum() {
    let mut token = make_github_classic(&"B".repeat(30));
    token.pop();
    token.push('x');
    assert_eq!(
        GithubClassicPatValidator.validate(&token),
        ChecksumResult::Invalid
    );
}

#[test]
fn github_classic_not_applicable_variants() {
    assert_eq!(
        GithubClassicPatValidator.validate("gho_something"),
        ChecksumResult::NotApplicable
    );
    assert_eq!(
        GithubClassicPatValidator.validate("ghp_tooshort"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn github_fine_grained_valid() {
    let token = make_github_fine_grained(&"A".repeat(22), &"B".repeat(53));
    assert_eq!(
        GithubFineGrainedPatValidator.validate(&token),
        ChecksumResult::Valid
    );
}

#[test]
fn github_fine_grained_invalid_checksum() {
    let token = "github_pat_AAAAAAAAAAAAAAAAAAAAAA_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB000000";
    assert_eq!(
        GithubFineGrainedPatValidator.validate(token),
        ChecksumResult::Invalid
    );
}

#[test]
fn github_fine_grained_not_applicable() {
    assert_eq!(
        GithubFineGrainedPatValidator.validate("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn npm_valid_and_invalid() {
    let token = make_npm("zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ");
    assert_eq!(NpmTokenValidator.validate(&token), ChecksumResult::Valid);

    let mut invalid = make_npm(&"C".repeat(30));
    invalid.pop();
    invalid.push('x');
    assert_eq!(
        NpmTokenValidator.validate(&invalid),
        ChecksumResult::Invalid
    );
    assert_eq!(
        NpmTokenValidator.validate("npm_tooshort"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn slack_valid_and_invalid_variants() {
    assert_eq!(
        SlackTokenValidator.validate("xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx"),
        ChecksumResult::Valid
    );
    assert_eq!(
        SlackTokenValidator.validate("xoxp-1234567890-1234567890-abcdefghijklmnopqrstuvwx"),
        ChecksumResult::Valid
    );
    assert_eq!(
        SlackTokenValidator
            .validate("xoxp-1234567890-1234567890-1234567890-abcdef1234567890abcdef1234567890"),
        ChecksumResult::Valid
    );
    assert_eq!(
        SlackTokenValidator.validate("xoxb-nodashes"),
        ChecksumResult::Invalid
    );
    assert_eq!(
        SlackTokenValidator.validate("not-a-slack-token"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn pypi_valid_and_invalid_variants() {
    let blob = base64::engine::general_purpose::URL_SAFE.encode(vec![0u8; 120]);
    let token = format!("pypi-{blob}");
    assert_eq!(PypiTokenValidator.validate(&token), ChecksumResult::Valid);
    assert_eq!(
        PypiTokenValidator.validate("pypi-!!!not-valid-base64!!!"),
        ChecksumResult::Invalid
    );
    assert_eq!(
        PypiTokenValidator.validate("pypi-short"),
        ChecksumResult::Invalid
    );
    assert_eq!(
        PypiTokenValidator.validate("not-pypi-token"),
        ChecksumResult::NotApplicable
    );
}

#[test]
fn registry_routes_and_rejects() {
    let github = make_github_classic(&"D".repeat(30));
    assert_eq!(validate_checksum(&github), ChecksumResult::Valid);

    let npm = make_npm(&"E".repeat(30));
    assert_eq!(validate_checksum(&npm), ChecksumResult::Valid);

    let slack = "xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx";
    assert_eq!(validate_checksum(slack), ChecksumResult::Valid);

    let blob = base64::engine::general_purpose::STANDARD.encode(vec![0u8; 120]);
    let pypi = format!("pypi-{blob}");
    assert_eq!(validate_checksum(&pypi), ChecksumResult::Valid);

    assert_eq!(
        validate_checksum("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA000000"),
        ChecksumResult::Invalid
    );
    assert_eq!(
        validate_checksum("npm_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA000000"),
        ChecksumResult::Invalid
    );
    assert_eq!(validate_checksum("xoxb-bad"), ChecksumResult::Invalid);
    assert_eq!(validate_checksum("pypi-!!!bad!!!"), ChecksumResult::Invalid);
    assert_eq!(
        validate_checksum("AKIAIOSFODNN7EXAMPLE"),
        ChecksumResult::NotApplicable
    );
}
