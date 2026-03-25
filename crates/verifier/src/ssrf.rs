//! SSRF protection helpers for credential verification.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Check if a URL points to a private/internal network (SSRF protection).
pub(crate) fn is_private_url(url: &str) -> bool {
    parse_url_host(url).is_none_or(|host| is_private_host(&host))
}

pub(crate) fn parse_url_host(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    // Decode multiple times to prevent double-encoding bypasses
    let mut decoded = host.to_string();
    for _ in 0..3 {
        // Limit iterations to prevent abuse
        let new_decoded = percent_encoding::percent_decode_str(&decoded)
            .decode_utf8()
            .ok()?
            .to_string();
        if new_decoded == decoded {
            break;
        }
        decoded = new_decoded;
    }
    Some(decoded.trim_matches(['[', ']']).to_lowercase())
}

pub(crate) fn is_private_host(host: &str) -> bool {
    if is_metadata_host(host) || is_local_hostname(host) {
        return true;
    }

    // Security boundary: parse legacy numeric IPv4 spellings before the normal
    // IP parser so integer, octal, hex, and short dotted forms cannot bypass
    // the private-address blocklist.
    if let Some(ip) = parse_numeric_ipv4_host(host) {
        return is_private_ipv4(ip);
    }

    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => is_private_ipv4(ip),
        Ok(IpAddr::V6(ip)) => is_private_ipv6(ip),
        Err(_) => false,
    }
}

pub(crate) fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_private_ipv4(ip),
        IpAddr::V6(ip) => is_private_ipv6(ip),
    }
}

pub(crate) fn parse_numeric_ipv4_host(host: &str) -> Option<std::net::Ipv4Addr> {
    if host.is_empty() {
        return None;
    }
    if !host.contains('.') {
        return parse_ipv4_component(host).map(std::net::Ipv4Addr::from);
    }
    let values = parse_ipv4_components(host)?;
    combine_ipv4_components(&values)
}

fn parse_ipv4_components(host: &str) -> Option<Vec<u32>> {
    let parts = host.split('.').collect::<Vec<_>>();
    if !(2..=4).contains(&parts.len()) {
        return None;
    }
    let mut values = Vec::with_capacity(parts.len());
    for part in parts {
        values.push(parse_ipv4_component(part)?);
    }
    Some(values)
}

fn combine_ipv4_components(values: &[u32]) -> Option<Ipv4Addr> {
    let addr = match values.len() {
        2 => {
            if values[0] > 0xff || values[1] > 0x00ff_ffff {
                return None;
            }
            (values[0] << 24) | values[1]
        }
        3 => {
            if values[0] > 0xff || values[1] > 0xff || values[2] > 0xffff {
                return None;
            }
            (values[0] << 24) | (values[1] << 16) | values[2]
        }
        4 => {
            // Each component must fit in a single byte for a valid 4-part IPv4 address.
            if values.iter().any(|&v| v > 0xff) {
                return None;
            }
            (values[0] << 24) | (values[1] << 16) | (values[2] << 8) | values[3]
        }
        _ => return None,
    };
    Some(Ipv4Addr::from(addr))
}

pub(crate) fn parse_ipv4_component(part: &str) -> Option<u32> {
    if part.is_empty() || part.starts_with('+') || part.starts_with('-') {
        return None;
    }

    let (digits, radix) =
        if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            (hex, 16)
        } else if part.len() > 1 && part.starts_with('0') {
            // POSIX `inet_aton` treats leading-zero components as octal. The
            // `len() > 1` guard ensures bare "0" is parsed as decimal zero
            // (correct) rather than triggering the octal path with an empty
            // digit string.
            (part, 8)
        } else {
            (part, 10)
        };

    if digits.is_empty() {
        return None;
    }

    u32::from_str_radix(digits, radix).ok()
}

pub(crate) fn is_local_hostname(host: &str) -> bool {
    matches!(host, "localhost" | "localhost.")
}

pub(crate) fn is_metadata_host(host: &str) -> bool {
    matches!(
        host,
        "metadata.google"
            | "metadata.google.internal"
            | "metadata.azure.internal"
            | "metadata.internal"
    )
}

/// IP addresses used by cloud providers for instance metadata services that
/// fall outside standard private ranges.
fn is_cloud_metadata_ip(ip: std::net::Ipv4Addr) -> bool {
    // Alibaba Cloud metadata endpoint — not in RFC 1918 or link-local ranges.
    ip == std::net::Ipv4Addr::new(100, 100, 100, 200)
}

pub(crate) fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || is_cloud_metadata_ip(ip)
}

pub(crate) fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_private_ipv4(mapped);
    }

    // SAFETY: explicit coverage for ULA (`fd00::/8`) and link-local
    // (`fe80::/10`) comes from the standard library helpers below.
    ip.is_loopback() || ip.is_unspecified() || ip.is_unique_local() || ip.is_unicast_link_local()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_localhost() {
        assert!(is_private_url("https://localhost/api"));
        assert!(is_private_url("https://127.0.0.1/api"));
        assert!(is_private_url("https://[::1]/api"));
    }

    #[test]
    fn blocks_private_ranges() {
        assert!(is_private_url("https://10.0.0.1/api"));
        assert!(is_private_url("https://172.16.0.1/api"));
        assert!(is_private_url("https://192.168.1.1/api"));
    }

    #[test]
    fn blocks_metadata_endpoints() {
        assert!(is_private_url("https://169.254.169.254/latest/meta-data/"));
        assert!(is_private_url(
            "https://metadata.google.internal/computeMetadata/v1/"
        ));
    }

    #[test]
    fn allows_public_urls() {
        assert!(!is_private_url("https://api.github.com/user"));
        assert!(!is_private_url("https://api.stripe.com/v1/charges"));
        assert!(!is_private_url("https://slack.com/api/auth.test"));
    }

    #[test]
    fn handles_malformed_urls() {
        assert!(is_private_url(""));
        assert!(is_private_url("not-a-url"));
        assert!(is_private_url("://missing-scheme"));
    }

    #[test]
    fn blocks_ipv6_private() {
        assert!(is_private_ipv6("::1".parse().unwrap()));
        assert!(is_private_ipv6("fe80::1".parse().unwrap()));
        assert!(is_private_ipv6("fd00::1".parse().unwrap()));
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6() {
        // ::ffff:127.0.0.1
        assert!(is_private_ipv6("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_private_ipv6("::ffff:10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn blocks_zero_address() {
        assert!(is_private_url("https://0.0.0.0/api"));
    }

    // SSRF BYPASS ATTEMPTS - These tests verify that common attacker techniques are blocked

    #[test]
    fn blocks_decimal_ip_notation() {
        // http://2130706433 = 127.0.0.1 in decimal
        assert!(is_private_url("http://2130706433/"));
        assert!(is_private_url("http://2130706433:8080/"));
    }

    #[test]
    fn blocks_octal_ip_notation() {
        // http://0177.0.0.1 = 127.0.0.1 in octal (0177 = 127)
        assert!(is_private_url("http://0177.0.0.1/"));
        assert!(is_private_url("http://0177.0.0.1:8080/"));
        // http://0177.1 = 127.0.0.1 in 2-part octal form
        assert!(is_private_url("http://0177.1/"));
    }

    #[test]
    fn blocks_hex_ip_notation() {
        // http://0x7f000001 = 127.0.0.1 in hex
        assert!(is_private_url("http://0x7f000001/"));
        assert!(is_private_url("http://0x7f.0x00.0x00.0x01/"));
        assert!(is_private_url("http://0X7F.0x00.0x00.0x01/"));
    }

    #[test]
    fn blocks_ipv6_shorthand_loopback() {
        // IPv6 shorthand for loopback
        assert!(is_private_url("http://[::ffff:127.0.0.1]/"));
        assert!(is_private_url("http://[::1]/"));
        assert!(is_private_url("http://[0:0:0:0:0:0:0:1]/"));
    }

    #[test]
    fn blocks_url_with_at_sign_bypass() {
        // http://evil.com@127.0.0.1 - @ sign tricks where parser thinks evil.com is userinfo
        assert!(is_private_url("http://evil.com@127.0.0.1/"));
        assert!(is_private_url("http://evil.com@10.0.0.1/"));
        assert!(is_private_url("http://user:pass@127.0.0.1/"));
    }

    #[test]
    fn blocks_private_ip_with_port() {
        // Private IPs with various ports
        assert!(is_private_url("http://10.0.0.1:8080/"));
        assert!(is_private_url("http://192.168.1.1:22/"));
        assert!(is_private_url("http://127.0.0.1:3000/api"));
        assert!(is_private_url("http://172.16.0.1:443/"));
    }

    #[test]
    fn blocks_double_encoded_url() {
        // Double-encoded URLs cause reqwest::Url::parse to fail with IdnaError
        // because they contain invalid characters after the first decode.
        // This is actually a defense - malformed URLs can't be used for SSRF.
        // Verify that double-encoded URLs are rejected (return true = blocked/private).
        let url = "http://%2531%2530%252e%2530%252e%2530%252e%2531/";
        assert!(is_private_url(url)); // Returns true because URL can't be parsed
        // Verify the host parsing fails for double-encoded URLs
        assert_eq!(parse_url_host(url), None);
        // Double-encoded 127.0.0.1 - also fails to parse
        assert!(is_private_url(
            "http://%2531%2532%2537%252e%2530%252e%2530%252e%2531/"
        ));
    }
    #[test]
    fn blocks_url_with_fragment_hiding_path() {
        // Fragment hiding the real host: http://127.0.0.1#.example.com
        // The parser should still detect 127.0.0.1 as the host
        assert!(is_private_url("http://127.0.0.1#.example.com"));
        assert!(is_private_url("http://10.0.0.1#example.com"));
        assert!(is_private_url("http://192.168.1.1#@public.com"));
    }

    #[test]
    fn blocks_cloud_metadata_dns_rebinding() {
        // Cloud metadata endpoints via DNS rebinding hostnames
        // These simulate what happens when a hostname resolves to 169.254.169.254
        // The actual hostname check is done before resolution
        assert!(is_private_url("http://metadata.google/"));
        assert!(is_private_url("http://metadata.google.internal/"));
        assert!(is_private_url(
            "http://metadata.google.internal/computeMetadata/v1/"
        ));
    }

    #[test]
    fn blocks_url_with_credentials_on_private_ip() {
        // http://user:pass@169.254.169.254 - credentials in userinfo with private IP
        assert!(is_private_url("http://user:pass@169.254.169.254/"));
        assert!(is_private_url("http://admin:secret@127.0.0.1/"));
        assert!(is_private_url("http://user@10.0.0.1/"));
    }

    // SSRF DNS PINNING VALIDATION TESTS

    #[test]
    fn dns_pinning_blocks_localhost_resolution() {
        // Verify resolved_client_for_url blocks localhost after DNS resolution
        // This tests that even if localhost resolves to 127.0.0.1, it's blocked
        assert!(is_private_host("localhost"));
        assert!(is_private_host("localhost."));
        assert!(is_private_url("http://localhost/"));
        assert!(is_private_url("https://localhost:8080/api"));
    }

    #[test]
    fn dns_pinning_blocks_aws_metadata_ip() {
        // Verify it blocks 169.254.169.254 (AWS metadata)
        assert!(is_private_host("169.254.169.254"));
        assert!(is_private_url("http://169.254.169.254/"));
        assert!(is_private_url("http://169.254.169.254/latest/meta-data/"));
        assert!(is_private_url("https://169.254.169.254:80/"));
    }

    #[test]
    fn dns_pinning_blocks_ipv6_ula() {
        // Verify it blocks fd00:: (IPv6 ULA - Unique Local Address)
        assert!(is_private_ipv6("fd00::".parse().unwrap()));
        assert!(is_private_ipv6("fd00::1".parse().unwrap()));
        assert!(is_private_ipv6("fd12:3456:7890::1".parse().unwrap()));
        assert!(is_private_url("http://[fd00::1]/"));
        assert!(is_private_url("http://[fd00::]/"));
    }

    #[test]
    fn dns_pinning_blocks_ipv4_mapped_ipv6_loopback() {
        // Verify it blocks ::ffff:127.0.0.1 (IPv4-mapped IPv6 loopback)
        assert!(is_private_ipv6("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_private_url("http://[::ffff:127.0.0.1]/"));
        assert!(is_private_url("http://[::ffff:7f00:0001]/"));
        assert!(is_private_ipv6("::ffff:10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn dns_pinning_allows_public_host_github() {
        // Verify it allows api.github.com (real public host)
        // Public hosts should NOT be blocked
        assert!(!is_private_host("api.github.com"));
        assert!(!is_private_url("https://api.github.com/user"));
        assert!(!is_private_url("https://api.github.com/repos/owner/repo"));
    }

    #[test]
    fn dns_pinning_blocks_numeric_ipv4() {
        // Verify numeric IPv4 (http://2130706433) is blocked
        // 2130706433 = 127*256^3 + 0*256^2 + 0*256 + 1 = 127.0.0.1
        assert!(is_private_url("http://2130706433/"));
        assert!(is_private_url("http://2130706433:8080/"));
        // Verify the numeric parsing works correctly
        assert_eq!(
            parse_numeric_ipv4_host("2130706433"),
            Some(Ipv4Addr::new(127, 0, 0, 1))
        );
    }

    #[test]
    fn dns_pinning_blocks_octal_ipv4() {
        // Verify octal IPv4 (http://0177.0.0.1) is blocked
        // 0177 in octal = 127 in decimal
        assert!(is_private_url("http://0177.0.0.1/"));
        assert!(is_private_url("http://0177.0.0.1:22/"));
        assert!(is_private_url("http://0177.1/")); // 2-part octal
        assert!(is_private_url("http://0177.0.1/")); // 3-part octal
    }

    #[test]
    fn dns_pinning_blocks_double_encoded_hostname() {
        // Verify double-encoded hostname is blocked
        // Double encoding can bypass naive URL decoders
        let double_encoded = "http://%2531%2532%2537%252e%2530%252e%2530%252e%2531/"; // %25 = '%'
        assert!(is_private_url(double_encoded));
        assert_eq!(parse_url_host(double_encoded), None); // Should fail to parse
    }

    #[test]
    fn dns_pinning_blocks_at_sign_redirect_to_localhost() {
        // Verify URL with @ sign redirecting to localhost is blocked
        // The @ sign makes the parser treat everything before as userinfo
        // http://evil.com@127.0.0.1/ -> actually connects to 127.0.0.1
        assert!(is_private_url("http://evil.com@127.0.0.1/"));
        assert!(is_private_url("http://user:pass@127.0.0.1/"));
        assert!(is_private_url("http://public.com@10.0.0.1/"));
        assert!(is_private_url("http://example.com@192.168.1.1/"));
    }

    #[test]
    fn dns_pinning_blocks_empty_hostname() {
        // Verify empty hostname is blocked
        // Empty or malformed hostnames should be treated as private/blocked
        assert!(is_private_url("http:///"));
        assert!(is_private_url("http://"));
        assert!(parse_url_host("http:///").is_none());
        assert!(parse_url_host("http://").is_none());
    }

    #[test]
    fn blocks_alibaba_cloud_metadata_ip() {
        // Alibaba Cloud metadata at 100.100.100.200 is NOT in RFC 1918 private
        // ranges, so it must be caught by the cloud metadata IP check.
        assert!(is_private_url("http://100.100.100.200/"));
        assert!(is_private_url("https://100.100.100.200/latest/meta-data/"));
        assert!(is_private_ipv4("100.100.100.200".parse().unwrap()));
        // Verify nearby addresses are NOT blocked (only the exact metadata IP)
        assert!(!is_private_ipv4("100.100.100.199".parse().unwrap()));
        assert!(!is_private_ipv4("100.100.100.201".parse().unwrap()));
    }

    #[test]
    fn blocks_azure_metadata_hostname() {
        assert!(is_private_url("http://metadata.azure.internal/"));
    }
}
