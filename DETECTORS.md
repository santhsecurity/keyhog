# KeyHog Detector Specification (TOML)

KeyHog uses a declarative TOML-based format for defining detectors. This format allows security researchers to define complex matching, context analysis, and multi-step verification without writing Rust code.

## Top-Level Schema

```toml
[detector]
id = "service-key-name"      # Unique stable identifier
name = "Human Readable Name" # Display name for reports
service = "service-id"       # Service namespace (for rate limiting)
severity = "critical"        # critical, high, medium, low, info
keywords = ["prefix_", "KEY"] # (Optional) AC literals to trigger matching

[[detector.patterns]]
regex = 'prefix_[a-zA-Z0-9]{32}'
description = "Descriptive text for this specific pattern"
group = 1 # (Optional) Regex capture group containing the actual secret

[[detector.companions]]
name = "secret_key"
regex = 'secret[=:\s]+([a-zA-Z0-9]{40})'
within_lines = 5
required = false
```

## Verification Flows

KeyHog supports three levels of verification.

### 1. Simple Single-Step
For services with a simple liveness probe.

```toml
[detector.verify]
method = "GET"
url = "https://api.service.com/v1/me"
auth = { type = "bearer", field = "match" }
success = { status = 200, body_contains = "account_id" }
```

### 2. Multi-Step (OAuth2 / CSRF)
For services that require a handshake or token exchange.

```toml
[[detector.verify.steps]]
name = "get_token"
method = "POST"
url = "https://auth.service.com/token"
body = "grant_type=client_credentials&client_id={{match}}&client_secret={{companion.secret_key}}"
success = { status = 200 }
extract = [{ name = "access_token", json_path = "access_token" }]

[[detector.verify.steps]]
name = "probe"
method = "GET"
url = "https://api.service.com/data"
auth = { type = "bearer", field = "step.get_token.access_token" }
success = { status = 200 }
```

### 3. Sandboxed Scripting
For truly complex logic (challenge-response, custom signing).

```toml
[detector.verify.auth]
type = "script"
engine = "node" # node, python, bash
code = """
const { credential, companions } = input;
// Custom logic here...
if (is_valid) console.log("STATUS: LIVE");
"""
```

## Interpolation Syntax
- `{{match}}`: The primary secret found.
- `{{companion.NAME}}`: A value from a nearby companion pattern.
- `{{step.STEP_NAME.VAR}}`: Metadata extracted from a previous verification step.
