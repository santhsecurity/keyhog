# Keyhog Production Readiness Audit

## Verdict

**Would I trust this scanner to find every leaked AWS key in a GitHub org today?**  
**No (yet).** Core architecture is strong, but there are critical detector-quality issues that can both miss real AWS leaks and produce noisy findings.

## Method

- Reviewed source under `crates/core/src/`, `crates/scanner/src/`, `crates/verifier/src/`, `crates/sources/src/`, `crates/cli/src/`.
- Reviewed detector specs under `detectors/*.toml` (AWS and high-impact providers in detail).
- CLI help evaluation is based on `clap` definitions in `crates/cli/src/main.rs` (runtime invocation was not available in this session).

## Findings (ordered by severity)

### 1) CRITICAL - Multiple AWS verifiers are nonfunctional placeholder implementations

- **Files/locations:**
  - `detectors/aws-secrets-manager-credentials.toml:25`
  - `detectors/aws-ses-smtp-credentials.toml:36`
  - `detectors/aws-cognito-client-secret.toml:20`
  - `detectors/aws-ecr-token.toml:29`
  - `detectors/aws-codecommit-credentials.toml:29`
- **Problem:** These detectors verify against `https://api.aws.amazon.com/v1/me`, which is not the documented verification flow for these credential types.
- **Impact:** Live verification status is unreliable for critical AWS findings; may mark real credentials as dead/error or silently fail expected verification semantics.
- **Fix:**
  - Replace with service-correct probes:
    - Cognito secret -> token endpoint for specific User Pool app.
    - ECR token -> `GetAuthorizationToken` flow (or remove verification if not safely feasible).
    - SES SMTP -> SMTP AUTH probe to regional endpoint.
    - CodeCommit -> git credential helper-compatible probe, or reclassify as pattern-only.
    - Secrets Manager ARN -> do **not** treat ARN as credential; convert detector type (see finding 3).
  - Add integration tests per detector proving verifier returns deterministic `Live/Invalid`.

### 2) CRITICAL - AWS session token detection gap

- **Files/locations:**
  - `detectors/aws-access-key.toml:14` (only access key IDs)
  - `detectors/aws-govcloud-access-key.toml:14` (same pattern class)
  - No detector coverage for `AWS_SESSION_TOKEN`/`aws_session_token` patterns.
- **Problem:** Temporary AWS credentials are a 3-part tuple (access key + secret + session token). Current logic primarily keys on `AKIA|ASIA` and companion secrets, but lacks dedicated session-token detection.
- **Impact:** Missed leaks when only session token or session-focused env var is committed (common in CI logs, debug dumps, and incident artifacts).
- **Fix:**
  - Add a detector for `AWS_SESSION_TOKEN` and common aliases with strong context anchors.
  - Add tuple-aware correlation in scanner/verifier (`access key + secret + session token` within bounded line/window scope).
  - Add adversarial tests: leaked token only, token+secret without access key, multiline split tuple.

### 3) HIGH - Detector named as credential scanner actually matches non-secret identifiers

- **File/location:** `detectors/aws-secrets-manager-credentials.toml:14`
- **Problem:** Pattern targets secret **ARNs** (`arn:aws:secretsmanager:...`), which are identifiers, not secret values.
- **Impact:** High false-positive and confusion risk; users get “critical secret” findings for resource identifiers.
- **Fix:**
  - Rename detector to `aws-secrets-manager-arn` with lower severity (info/low), or
  - Keep as enrichment-only signal requiring a separately matched secret value to emit high/critical finding.
  - Remove credential-style bearer verification for ARN (currently incorrect).

### 4) HIGH - Extremely broad companion regexes create false positives and verifier poisoning

- **Files/locations:**
  - `detectors/vonage-video-api.toml:24` (`[a-f0-9]{16}`)
  - `detectors/wix-api-credentials.toml:29` (generic UUID)
  - `detectors/aws-codecommit-credentials.toml:23` (`[a-zA-Z0-9/+=]{40}`)
- **Problem:** Companion capture patterns are generic enough to match hashes/UUIDs/random strings near unrelated context.
- **Impact:** Wrong companion association can produce false “credential pairs,” noisy findings, and invalid verification attempts.
- **Fix:**
  - Require strong companion anchors (key names, prefixes, delimiters).
  - Enforce quality-gate rule: companion regex must include at least one service-specific literal.
  - Add negative tests with nearby UUID/hash noise.

### 5) HIGH - Fake implementation smell: `--git` description implies history scan but behavior is blob traversal with dedup by blob ID

- **Files/locations:**
  - `crates/cli/src/main.rs:151` (`--git` help text: “Scan git repository history”)
  - `crates/sources/src/git.rs:24` and `crates/sources/src/git.rs:109`
- **Problem:** UX says “history,” but implementation traverses commit trees and dedups blobs (`seen_blobs`), which changes semantics from “every historical occurrence.”
- **Impact:** User expectation mismatch in audits/forensics; can miss path/context-level historic duplicate exposures even when blob content repeats.
- **Fix:**
  - Either rename flag/help to “scan reachable git blobs” or
  - Change implementation to emit commit-path scoped chunks when history mode is requested.
  - Keep current behavior as an explicit `--git-blobs` mode.

### 6) MEDIUM - Unbounded result accumulation before truncation

- **File/location:** `crates/cli/src/main.rs:761`-`857`
- **Problem:** `scan_parallel` collects all matches into a `Vec` and only then applies `MAX_TOTAL_FINDINGS` truncation.
- **Impact:** On pathological/high-noise input, memory can spike before cap is enforced.
- **Fix:**
  - Enforce streaming/online cap (bounded heap or per-worker bounded channel).
  - Maintain top-K by severity/confidence incrementally instead of full collect.

### 7) MEDIUM - Git history and diff sources buffer whole command output in memory

- **Files/locations:**
  - `crates/sources/src/git_history.rs:105`-`109`
  - `crates/sources/src/git_diff.rs:120`-`129`
- **Problem:** Uses `.output()` and then parses full stdout.
- **Impact:** Large repos or wide ref ranges can cause large transient allocations and long pause times.
- **Fix:**
  - Switch to streaming parse with `stdout` pipe and incremental line parser.
  - Add configurable hard cap on parsed bytes/lines with partial-scan warning.

### 8) MEDIUM - False positive pressure remains high in documentation/test content for broad detectors

- **Files/locations:**
  - `crates/scanner/src/context.rs:11`-`14` (docs/test lower confidence, not hard suppression)
  - Example broad detector families above (`vonage-video-api`, `wix-api-credentials`, `aws-codecommit-credentials`)
- **Problem:** Context handling reduces confidence but does not always suppress; broad regex families still leak into findings.
- **Impact:** CI noise, alert fatigue, and reduced trust in critical findings.
- **Fix:**
  - Add hard-suppress heuristics for doc/test contexts when detector confidence is below threshold.
  - Raise default `--min-confidence` for text output in CI presets.
  - Add “detector precision score” tests using curated benign corpora.

## Detection Gaps vs TruffleHog/Gitleaks-style coverage (specific patterns)

1. **AWS session token patterns** (critical): missing `AWS_SESSION_TOKEN`/`aws_session_token` class.
2. **Tuple correlation for temporary AWS creds**: no explicit 3-part temporary credential tuple detector path.
3. **AWS secret-only leakage handling**: no robust, standalone anchored detector strategy for leaked secret key material without access key context (current approach is mostly companion-based).
4. **Service-verifier parity gap**: several AWS detectors include verification stubs that do not match real provider auth flows, weakening “verified secret” parity expected from modern scanners.

## CLI Assessment

Based on `crates/cli/src/main.rs`:

- `keyhog` top-level UX is generally sensible (`scan`, `detectors`, custom `--version`).
- Flag docs are mostly clear; mode conflicts (`--fast` vs `--deep`) are well-defined.
- Output format wiring (`text/json/jsonl/sarif`) is correct in code path (`report_with` dispatch).
- Main issue is semantic mismatch around `--git` wording vs actual source behavior (finding 5).

## Recommended Remediation Plan (short)

1. **Blocker sprint (before production):**
   - Fix/disable nonfunctional AWS verifier endpoints.
   - Add AWS session-token detection and tuple correlation tests.
   - Tighten generic companion regexes.
2. **Performance hardening sprint:**
   - Stream git parsers.
   - Make finding cap online, not post-collection.
3. **Quality sprint:**
   - Add precision regression suite (docs/tests/lockfiles/fixtures).
   - Add detector lint requiring service-specific literals in companion regexes.

## Final Trust Call

Keyhog has strong foundations (quality gate, context analysis, bounded chunk scanning, SSRF protections), but **current detector-level issues are significant enough that I would not yet call it “legendary” for AWS leak detection in org-wide scanning**. The above blocker fixes are concrete and should materially improve both recall and trustworthiness.

