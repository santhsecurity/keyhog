//! GitHub organization source: clones and scans all repositories in a GitHub
//! organization via the GitHub API.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, AUTHORIZATION, HeaderMap, HeaderValue, USER_AGENT};
use serde::Deserialize;

use crate::FilesystemSource;

const GIT_CLONE_TIMEOUT: Duration = Duration::from_secs(300);

/// Scans all repositories in a GitHub organization by shallow-cloning them to a temp directory.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::Source;
/// use keyhog_sources::GitHubOrgSource;
///
/// let source = GitHubOrgSource::new("acme".into(), "ghp_example".into());
/// assert_eq!(source.name(), "github-org");
/// ```
pub struct GitHubOrgSource {
    org: String,
    token: String,
}

impl GitHubOrgSource {
    /// Create a source that scans all repositories in a GitHub organization.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Source;
    /// use keyhog_sources::GitHubOrgSource;
    ///
    /// let source = GitHubOrgSource::new("acme".into(), "ghp_example".into());
    /// assert_eq!(source.name(), "github-org");
    /// ```
    pub fn new(org: String, token: String) -> Self {
        Self { org, token }
    }
}

impl Source for GitHubOrgSource {
    fn name(&self) -> &str {
        "github-org"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        match collect_org_chunks(&self.org, &self.token) {
            Ok(chunks) => Box::new(chunks.into_iter().map(Ok)),
            Err(err) => Box::new(std::iter::once(Err(err))),
        }
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Debug, Deserialize)]
struct GitHubRepo {
    name: String,
    clone_url: String,
}

fn collect_org_chunks(org: &str, token: &str) -> Result<Vec<Chunk>, SourceError> {
    let client = build_client(token)?;
    let repos = list_repos(&client, org)?;
    let temp_dir = tempfile::tempdir().map_err(SourceError::Io)?;
    let mut chunks = Vec::new();

    for repo in repos {
        let clone_path = temp_dir.path().join(&repo.name);
        clone_repo(&repo, token, &clone_path)?;
        chunks.extend(scan_repo(org, &repo.name, &clone_path));
    }

    Ok(chunks)
}

fn build_client(token: &str) -> Result<Client, SourceError> {
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github+json"),
    );
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static("keyhog-github-org-scanner"),
    );
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|e| SourceError::Other(format!("invalid GitHub authorization header: {e}")))?,
    );

    Client::builder()
        .default_headers(headers)
        .build()
        .map_err(|e| SourceError::Other(format!("failed to build GitHub client: {e}")))
}

fn list_repos(client: &Client, org: &str) -> Result<Vec<GitHubRepo>, SourceError> {
    let mut repos = Vec::new();
    let mut page = 1;

    loop {
        let response = send_github_request_with_backoff(client, org, page)?;

        if !response.status().is_success() {
            return Err(SourceError::Other(format!(
                "GitHub API returned {} while listing repositories for org {org}",
                response.status()
            )));
        }

        let page_repos: Vec<GitHubRepo> = response
            .json()
            .map_err(|e| SourceError::Other(format!("failed to parse GitHub API response: {e}")))?;

        let count = page_repos.len();
        repos.extend(page_repos);

        if count < 100 {
            break;
        }

        page += 1;
    }

    Ok(repos)
}

fn send_github_request_with_backoff(
    client: &Client,
    org: &str,
    page: usize,
) -> Result<reqwest::blocking::Response, SourceError> {
    const MAX_ATTEMPTS: usize = 4;

    for attempt in 0..MAX_ATTEMPTS {
        let response = client
            .get(format!(
                "https://api.github.com/orgs/{org}/repos?per_page=100&page={page}"
            ))
            .send()
            .map_err(|e| SourceError::Other(format!("GitHub API request failed: {e}")))?;

        let status = response.status();
        let retry_after = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        let rate_limited = response
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value == "0");

        if !(status.as_u16() == 429 || (status.as_u16() == 403 && rate_limited)) {
            return Ok(response);
        }

        if attempt + 1 == MAX_ATTEMPTS {
            return Err(SourceError::Other(format!(
                "GitHub API rate limited while listing repositories for org {org}"
            )));
        }

        std::thread::sleep(std::time::Duration::from_secs(
            retry_after.unwrap_or((attempt + 1) as u64),
        ));
    }

    Err(SourceError::Other("GitHub API retry limit exceeded".into()))
}

fn clone_repo(repo: &GitHubRepo, token: &str, clone_path: &Path) -> Result<(), SourceError> {
    let clone_target = clone_path.to_str().ok_or_else(|| {
        SourceError::Other(format!("non-UTF-8 clone path for repo {}", repo.name))
    })?;
    let auth_material = GitAskpassAuth::create(token)?;

    let child = Command::new("git")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", &auth_material.askpass_path)
        .env("SSH_ASKPASS", &auth_material.askpass_path)
        .args([
            "clone",
            "--depth",
            "1",
            "--quiet",
            &repo.clone_url,
            clone_target,
        ])
        .spawn()
        .map_err(SourceError::Io)?;

    let output = wait_for_command_with_timeout(child, GIT_CLONE_TIMEOUT)
        .map_err(|err| SourceError::Git(format!("failed to clone {}: {}", repo.name, err)))?;

    if !output.status.success() {
        return Err(SourceError::Git(format!(
            "failed to clone {}: {}",
            repo.name,
            sanitize_git_error_message(&String::from_utf8_lossy(&output.stderr))
        )));
    }

    Ok(())
}

fn wait_for_command_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Result<std::process::Output, String> {
    let start = Instant::now();
    loop {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            return child.wait_with_output().map_err(|e| e.to_string());
        }

        if start.elapsed() >= timeout {
            child.kill().map_err(|e| e.to_string())?;
            let _ = child.wait();
            return Err(format!("git clone timed out after {}s", timeout.as_secs()));
        }

        thread::sleep(Duration::from_millis(100));
    }
}

#[derive(Debug)]
struct GitAskpassAuth {
    _dir: tempfile::TempDir,
    askpass_path: PathBuf,
    #[allow(dead_code)]
    token_path: PathBuf,
}

impl GitAskpassAuth {
    fn create(token: &str) -> Result<Self, SourceError> {
        validate_github_token(token)?;
        let dir = tempfile::tempdir().map_err(SourceError::Io)?;
        let token_path = dir.path().join("token");

        // Create the token file with restricted permissions.
        // On Unix, we use O_NOFOLLOW and mode 0600.
        // On Windows, we rely on tempdir creating a private directory (usually).
        {
            use std::io::Write;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);

            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }

            let mut file = options.open(&token_path).map_err(SourceError::Io)?;
            file.write_all(token.as_bytes()).map_err(SourceError::Io)?;
        }

        let askpass_path = if cfg!(unix) {
            let path = dir.path().join("askpass.sh");
            std::fs::write(
                &path,
                "#!/bin/sh\nset -eu\nTOKEN_FILE=\"$(dirname \"$0\")/token\"\ncase \"$1\" in\n*Username*) printf '%s' x-access-token ;;\n*) exec cat -- \"$TOKEN_FILE\" ;;\nesac\n",
            )
            .map_err(SourceError::Io)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                    .map_err(SourceError::Io)?;
            }
            path
        } else {
            let path = dir.path().join("askpass.bat");
            let content = format!(
                "@echo off\r\necho %1 | findstr /I \"Username\" >nul\r\nif %errorlevel% == 0 (\r\n  echo x-access-token\r\n) else (\r\n  type \"{}\"\r\n)\r\n",
                token_path.display()
            );
            std::fs::write(&path, content).map_err(SourceError::Io)?;
            path
        };

        Ok(Self {
            _dir: dir,
            askpass_path,
            token_path,
        })
    }
}

fn validate_github_token(token: &str) -> Result<(), SourceError> {
    if token.is_empty() || token.chars().any(char::is_control) {
        return Err(SourceError::Other(
            "github token contains unsafe characters".into(),
        ));
    }
    Ok(())
}

fn scan_repo(org: &str, repo_name: &str, clone_path: &Path) -> Vec<Chunk> {
    let source = FilesystemSource::new(clone_path.to_path_buf());
    let mut chunks = Vec::new();

    for chunk in source.chunks().flatten() {
        chunks.push(rewrite_chunk_path(chunk, org, repo_name, clone_path));
    }

    chunks
}

fn rewrite_chunk_path(mut chunk: Chunk, org: &str, repo_name: &str, clone_path: &Path) -> Chunk {
    let relative_path = chunk
        .metadata
        .path
        .as_ref()
        .and_then(|path| make_relative_path(path, clone_path));

    chunk.metadata = ChunkMetadata {
        source_type: "github-org".into(),
        path: relative_path.map(|relative| format!("{org}/{repo_name}/{relative}")),
        commit: None,
        author: None,
        date: None,
    };

    chunk
}

fn make_relative_path(path: &str, clone_path: &Path) -> Option<String> {
    let normalized_path = std::fs::canonicalize(path).ok()?;
    let normalized_clone_path = std::fs::canonicalize(clone_path).ok()?;
    let relative = normalized_path
        .strip_prefix(&normalized_clone_path)
        .ok()?
        .to_path_buf();
    Some(relative.to_string_lossy().into_owned())
}

fn sanitize_git_error_message(stderr: &str) -> String {
    use std::sync::OnceLock;

    static URL_CRED_RE: OnceLock<Option<Regex>> = OnceLock::new();
    static AUTH_HEADER_RE: OnceLock<Option<Regex>> = OnceLock::new();
    static TOKEN_RE: OnceLock<Option<Regex>> = OnceLock::new();

    let url_cred =
        URL_CRED_RE.get_or_init(|| Regex::new(r"([a-z][a-z0-9+\-.]*://)([^/@\s]+)@").ok());
    let auth_header = AUTH_HEADER_RE
        .get_or_init(|| Regex::new(r"(?i)(authorization:\s*(?:basic|bearer)\s+)\S+").ok());
    let token_pat = TOKEN_RE.get_or_init(|| {
        // Tighten common token patterns to avoid over-redaction of short strings.
        Regex::new(r"(?:ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}|xoxb-[A-Za-z0-9-]{24,}|xoxp-[A-Za-z0-9-]{24,}|sk-proj-[A-Za-z0-9_-]{24,}|sk_live_[A-Za-z0-9]{24,}|sk_test_[A-Za-z0-9]{24,}|AKIA[0-9A-Z]{16})").ok()
    });

    let mut result = stderr.to_string();
    if let Some(re) = url_cred {
        result = re.replace_all(&result, "${1}<redacted>@").into_owned();
    }
    if let Some(re) = auth_header {
        result = re.replace_all(&result, "${1}<redacted>").into_owned();
    }
    if let Some(re) = token_pat {
        result = re.replace_all(&result, "<redacted-token>").into_owned();
    }
    result.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_relative_path_strips_clone_prefix() {
        let temp_dir = tempfile::tempdir().unwrap();
        let clone_path = temp_dir.path().join("widgets");
        let file_path = clone_path.join("src").join("main.rs");
        std::fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        std::fs::write(&file_path, "fn main() {}\n").unwrap();

        let relative = make_relative_path(file_path.to_str().unwrap(), &clone_path);
        assert_eq!(relative.as_deref(), Some("src/main.rs"));
    }

    #[test]
    fn make_relative_path_rejects_paths_outside_clone_root() {
        let temp_dir = tempfile::tempdir().unwrap();
        let clone_path = temp_dir.path().join("widgets");
        let inside_path = clone_path.join("src").join("main.rs");
        let outside_path = temp_dir.path().join("elsewhere.rs");
        std::fs::create_dir_all(inside_path.parent().unwrap()).unwrap();
        std::fs::write(&inside_path, "fn main() {}\n").unwrap();
        std::fs::write(&outside_path, "fn elsewhere() {}\n").unwrap();

        assert_eq!(
            make_relative_path(outside_path.to_str().unwrap(), &clone_path),
            None
        );
    }

    #[test]
    fn rewrite_chunk_path_rewrites_metadata() {
        let temp_dir = tempfile::tempdir().unwrap();
        let clone_root = temp_dir.path().join("widgets");
        let file_path = clone_root.join("src").join("main.rs");
        std::fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        std::fs::write(&file_path, "secret").unwrap();

        let chunk = Chunk {
            data: "secret".into(),
            metadata: ChunkMetadata {
                source_type: "filesystem".into(),
                path: Some(file_path.to_string_lossy().into_owned()),
                commit: Some("abc".into()),
                author: Some("dev".into()),
                date: None,
            },
        };

        let rewritten = rewrite_chunk_path(chunk, "acme", "widgets", &clone_root);

        assert_eq!(rewritten.metadata.source_type, "github-org");
        assert_eq!(
            rewritten.metadata.path.as_deref(),
            Some("acme/widgets/src/main.rs")
        );
        assert_eq!(rewritten.metadata.commit, None);
        assert_eq!(rewritten.metadata.author, None);
    }

    #[test]
    fn sanitize_git_error_message_redacts_credentials() {
        let message = "fatal: could not read https://user:token@example.com/repo.git\nAuthorization: Bearer secret-token";
        let sanitized = sanitize_git_error_message(message);
        assert!(!sanitized.contains("token@example.com"));
        assert!(!sanitized.contains("secret-token"));
        assert!(sanitized.contains("<redacted>@"));
        assert!(sanitized.contains("Bearer <redacted>"));
    }

    #[test]
    fn git_askpass_uses_token_file() {
        let auth = GitAskpassAuth::create("ghp_secret").unwrap();
        let script = std::fs::read_to_string(&auth.askpass_path).unwrap();
        assert!(script.contains("TOKEN_FILE"));
        assert!(script.contains("exec cat -- \"$TOKEN_FILE\""));
        assert_eq!(
            std::fs::read_to_string(&auth.token_path).unwrap(),
            "ghp_secret"
        );
    }

    #[test]
    fn git_askpass_rejects_control_chars_in_token() {
        let error = GitAskpassAuth::create("ghp_bad\nsecret").unwrap_err();
        assert!(error.to_string().contains("unsafe"));
    }
}
