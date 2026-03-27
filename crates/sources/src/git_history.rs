//! Git history source: scans all commits in a repository's history for secrets
//! that may have been committed and later removed.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Scans git history commit-by-commit using patch output and extracts added lines.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::Source;
/// use keyhog_sources::GitHistorySource;
/// use std::path::PathBuf;
///
/// let source = GitHistorySource::new(PathBuf::from(".")).with_max_commits(25);
/// assert_eq!(source.name(), "git-history");
/// ```
pub struct GitHistorySource {
    repo_path: PathBuf,
    max_commits: Option<usize>,
}

impl GitHistorySource {
    /// Create a source that scans commit history patches for added lines.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Source;
    /// use keyhog_sources::GitHistorySource;
    /// use std::path::PathBuf;
    ///
    /// let source = GitHistorySource::new(PathBuf::from("."));
    /// assert_eq!(source.name(), "git-history");
    /// ```
    pub fn new(repo_path: PathBuf) -> Self {
        Self {
            repo_path,
            max_commits: None,
        }
    }

    /// Limit how many commits are traversed from `HEAD`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Source;
    /// use keyhog_sources::GitHistorySource;
    /// use std::path::PathBuf;
    ///
    /// let source = GitHistorySource::new(PathBuf::from(".")).with_max_commits(2);
    /// assert_eq!(source.name(), "git-history");
    /// ```
    pub fn with_max_commits(mut self, n: usize) -> Self {
        self.max_commits = Some(n);
        self
    }
}

impl Source for GitHistorySource {
    fn name(&self) -> &str {
        "git-history"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        match collect_git_history_chunks(&self.repo_path, self.max_commits) {
            Ok(chunks) => Box::new(chunks.into_iter().map(Ok)),
            Err(error) => Box::new(std::iter::once(Err(error))),
        }
    }
}

struct AddedHistoryHunk {
    commit: String,
    author: String,
    date: String,
    path: String,
    content: String,
}

fn collect_git_history_chunks(
    repo_path: &Path,
    max_commits: Option<usize>,
) -> Result<Vec<Chunk>, SourceError> {
    let repo_arg = validate_repo_path(repo_path)?;
    let mut command = Command::new("git");
    command.args([
        "-C",
        &repo_arg,
        "log",
        "--date=iso-strict",
        "--format=commit %H%nAuthor: %an <%ae>%nDate: %aI",
        "-p",
    ]);

    if let Some(limit) = max_commits {
        command.args(["--max-count", &limit.to_string()]);
    }

    command.arg("--end-of-options");

    let output = command.output().map_err(SourceError::Io)?;
    ensure_git_success("git log failed", &output)?;

    let log_output = String::from_utf8_lossy(&output.stdout);
    let hunks = parse_git_log_for_added_lines(&log_output);

    Ok(hunks
        .into_iter()
        .filter(|hunk| !hunk.content.trim().is_empty())
        .map(|hunk| Chunk {
            data: hunk.content,
            metadata: ChunkMetadata {
                source_type: "git-history".into(),
                path: Some(hunk.path),
                commit: Some(hunk.commit),
                author: Some(hunk.author),
                date: Some(hunk.date),
            },
        })
        .collect())
}

fn ensure_git_success(operation: &str, output: &std::process::Output) -> Result<(), SourceError> {
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let reason = if stderr.contains("not a git repository") {
        "not a git repository"
    } else if stderr.contains("does not have any commits yet") {
        "repository has no commits"
    } else {
        operation
    };
    Err(SourceError::Git(format!("{reason}: {}", stderr.trim())))
}

fn parse_git_log_for_added_lines(log_output: &str) -> Vec<AddedHistoryHunk> {
    let mut hunks = Vec::new();
    let mut current_commit: Option<String> = None;
    let mut current_author: Option<String> = None;
    let mut current_date: Option<String> = None;
    let mut current_path: Option<String> = None;
    let mut current_content = String::new();
    let mut in_hunk = false;

    for line in log_output.lines() {
        if let Some(commit) = line.strip_prefix("commit ") {
            flush_history_hunk(
                &mut hunks,
                &current_commit,
                &current_author,
                &current_date,
                &current_path,
                &mut current_content,
            );
            current_commit = Some(commit.trim().to_string());
            current_author = None;
            current_date = None;
            current_path = None;
            in_hunk = false;
            continue;
        }

        if let Some(author) = line.strip_prefix("Author: ") {
            current_author = Some(author.trim().to_string());
            continue;
        }

        if let Some(date) = line.strip_prefix("Date: ") {
            current_date = Some(date.trim().to_string());
            continue;
        }

        if line.starts_with("diff --git ") {
            flush_history_hunk(
                &mut hunks,
                &current_commit,
                &current_author,
                &current_date,
                &current_path,
                &mut current_content,
            );
            current_path = extract_new_path(line);
            in_hunk = false;
            continue;
        }

        if line.starts_with("new file mode")
            || line.starts_with("index ")
            || line.starts_with("--- ")
        {
            continue;
        }

        if let Some(path_part) = line.strip_prefix("+++ b/") {
            current_path = sanitize_path(path_part);
            continue;
        }

        if line.starts_with("@@") && line.contains("@@") {
            in_hunk = true;
            continue;
        }

        if (in_hunk || line.starts_with('+')) && line.starts_with('+') && !line.starts_with("+++") {
            current_content.push_str(&line[1..]);
            current_content.push('\n');
        }
    }

    flush_history_hunk(
        &mut hunks,
        &current_commit,
        &current_author,
        &current_date,
        &current_path,
        &mut current_content,
    );

    hunks
}

fn validate_repo_path(repo_path: &Path) -> Result<String, SourceError> {
    let path = repo_path.to_str().unwrap_or(".");
    // Security boundary: `git -C` still parses its path operand, so option-like
    // values such as `-c` must be rejected even though `Command` bypasses the
    // shell.
    if path.starts_with('-') || path.chars().any(char::is_control) {
        return Err(SourceError::Other(
            "repository path contains unsafe characters".into(),
        ));
    }

    Ok(path.to_string())
}

fn flush_history_hunk(
    hunks: &mut Vec<AddedHistoryHunk>,
    current_commit: &Option<String>,
    current_author: &Option<String>,
    current_date: &Option<String>,
    current_path: &Option<String>,
    current_content: &mut String,
) {
    if let (Some(commit), Some(author), Some(date), Some(path)) =
        (current_commit, current_author, current_date, current_path)
        && !current_content.trim().is_empty()
    {
        hunks.push(AddedHistoryHunk {
            commit: commit.clone(),
            author: author.clone(),
            date: date.clone(),
            path: path.clone(),
            content: current_content.trim().to_string(),
        });
    }

    current_content.clear();
}

fn extract_new_path(line: &str) -> Option<String> {
    line.find(" b/")
        .and_then(|index| sanitize_path(&line[index + 3..]))
}

fn sanitize_path(path: &str) -> Option<String> {
    let path = path.trim().replace('\\', "/");
    if path.is_empty() || path == "/dev/null" {
        return None;
    }

    let candidate = Path::new(&path);
    if candidate.is_absolute() || path.chars().any(char::is_control) {
        return None;
    }

    let mut normalized = Vec::new();
    for component in candidate.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(part) => {
                normalized.push(part.to_string_lossy().into_owned());
            }
            std::path::Component::ParentDir => {
                normalized.pop()?;
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return None;
            }
        }
    }

    if normalized.is_empty() {
        None
    } else {
        Some(normalized.join("/"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn create_test_repo() -> (tempfile::TempDir, PathBuf) {
        let temp_dir = tempfile::tempdir().unwrap();
        let repo_path = temp_dir.path().to_path_buf();

        let output = Command::new("git")
            .args(["init", "-b", "main"])
            .current_dir(&repo_path)
            .output()
            .expect("failed to execute git init");
        assert!(output.status.success(), "git init failed: {:?}", output);

        Command::new("git")
            .args(["config", "user.email", "test@example.com"])
            .current_dir(&repo_path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Test User"])
            .current_dir(&repo_path)
            .output()
            .unwrap();

        (temp_dir, repo_path)
    }

    fn commit_file(repo_path: &PathBuf, filename: &str, content: &str, message: &str) {
        let file_path = repo_path.join(filename);
        fs::write(&file_path, content).unwrap();

        Command::new("git")
            .args(["add", filename])
            .current_dir(repo_path)
            .output()
            .unwrap();

        let output = Command::new("git")
            .args(["commit", "-m", message])
            .current_dir(repo_path)
            .output()
            .expect("failed to commit");
        assert!(output.status.success(), "git commit failed: {:?}", output);
    }

    #[test]
    fn test_git_history_source_name() {
        let source = GitHistorySource::new(PathBuf::from("."));
        assert_eq!(source.name(), "git-history");
    }

    #[test]
    fn test_git_history_source_collects_added_files_commit_by_commit() {
        let (_temp_dir, repo_path) = create_test_repo();

        commit_file(&repo_path, "first.txt", "api_key = sk-first", "Add first");
        commit_file(&repo_path, "second.txt", "token = sk-second", "Add second");

        let chunks: Vec<_> = GitHistorySource::new(repo_path)
            .chunks()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(chunks.len(), 2);
        assert!(
            chunks
                .iter()
                .any(|chunk| chunk.metadata.path.as_deref() == Some("first.txt"))
        );
        assert!(
            chunks
                .iter()
                .any(|chunk| chunk.metadata.path.as_deref() == Some("second.txt"))
        );
        assert!(chunks.iter().all(|chunk| chunk.metadata.commit.is_some()));
        assert!(chunks.iter().all(|chunk| chunk.metadata.author.is_some()));
        assert!(chunks.iter().all(|chunk| chunk.metadata.date.is_some()));
    }

    #[test]
    fn test_git_history_source_honors_max_commits() {
        let (_temp_dir, repo_path) = create_test_repo();

        commit_file(&repo_path, "first.txt", "api_key = sk-first", "Add first");
        commit_file(&repo_path, "second.txt", "token = sk-second", "Add second");

        let chunks: Vec<_> = GitHistorySource::new(repo_path)
            .with_max_commits(1)
            .chunks()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].metadata.path.as_deref(), Some("second.txt"));
    }

    #[test]
    fn test_parse_git_log_for_added_lines_keeps_commit_metadata() {
        let log = r#"commit abc123
Author: Test User <test@example.com>
Date: 2026-03-20T12:00:00-07:00

    Add secret

diff --git a/secret.txt b/secret.txt
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/secret.txt
@@ -0,0 +1,2 @@
+api_key = sk-test123
+another = value
"#;

        let hunks = parse_git_log_for_added_lines(log);
        assert_eq!(hunks.len(), 1);
        assert_eq!(hunks[0].commit, "abc123");
        assert_eq!(hunks[0].author, "Test User <test@example.com>");
        assert_eq!(hunks[0].date, "2026-03-20T12:00:00-07:00");
        assert_eq!(hunks[0].path, "secret.txt");
        assert_eq!(hunks[0].content, "api_key = sk-test123\nanother = value");
    }

    #[test]
    fn rejects_option_like_repo_paths() {
        let error = validate_repo_path(Path::new("-c")).unwrap_err();
        assert!(error.to_string().contains("unsafe"));
    }

    #[test]
    fn sanitize_path_rejects_traversal_and_control_chars() {
        assert!(sanitize_path("../secret.txt").is_none());
        assert!(sanitize_path("/etc/passwd").is_none());
        assert!(sanitize_path("evil\npath").is_none());
        assert_eq!(sanitize_path("src/main.rs").as_deref(), Some("src/main.rs"));
    }

    macro_rules! valid_sanitize_case {
        ($name:ident, $input:expr, $expected:expr) => {
            #[test]
            fn $name() {
                assert_eq!(sanitize_path($input).as_deref(), Some($expected));
            }
        };
    }

    macro_rules! invalid_sanitize_case {
        ($name:ident, $input:expr) => {
            #[test]
            fn $name() {
                assert!(sanitize_path($input).is_none());
            }
        };
    }

    valid_sanitize_case!(sanitize_keeps_simple_file, "config.env", "config.env");
    valid_sanitize_case!(
        sanitize_keeps_nested_file,
        "src/config.env",
        "src/config.env"
    );
    valid_sanitize_case!(
        sanitize_normalizes_curdir_prefix,
        "./src/config.env",
        "src/config.env"
    );
    valid_sanitize_case!(
        sanitize_normalizes_curdir_in_middle,
        "src/./config.env",
        "src/config.env"
    );
    valid_sanitize_case!(
        sanitize_keeps_spaces_in_name,
        "docs/My Secrets.txt",
        "docs/My Secrets.txt"
    );
    valid_sanitize_case!(
        sanitize_keeps_unicode_name,
        "配置/密钥.env",
        "配置/密钥.env"
    );
    valid_sanitize_case!(
        sanitize_keeps_dash_and_underscore,
        "a-b_c/file.name",
        "a-b_c/file.name"
    );
    valid_sanitize_case!(
        sanitize_collapses_parent_after_normal_segment,
        "src/dir/../config.env",
        "src/config.env"
    );
    valid_sanitize_case!(
        sanitize_keeps_windowsish_component_text,
        "C:project/file.txt",
        "C:project/file.txt"
    );

    invalid_sanitize_case!(sanitize_rejects_absolute_unix_path, "/var/tmp/secret");
    invalid_sanitize_case!(sanitize_rejects_double_parent_escape, "../../secret");
    invalid_sanitize_case!(sanitize_rejects_single_parent_escape, "../secret");
    invalid_sanitize_case!(
        sanitize_rejects_parent_escape_after_normalization,
        "dir/../../config.env"
    );
    invalid_sanitize_case!(sanitize_rejects_dev_null, "/dev/null");
    invalid_sanitize_case!(sanitize_rejects_newline, "a\nb");
    invalid_sanitize_case!(sanitize_rejects_carriage_return, "a\rb");
    invalid_sanitize_case!(sanitize_rejects_tab, "a\tb");
    invalid_sanitize_case!(sanitize_rejects_empty_path, "");
    invalid_sanitize_case!(sanitize_rejects_rooted_with_curdir, "/./secret");
    invalid_sanitize_case!(sanitize_rejects_windows_parent_escape, "..\\secret");

    #[test]
    fn parse_git_log_handles_renames_with_added_lines() {
        let log = r#"commit def456
Author: Test User <test@example.com>
Date: 2026-03-21T12:00:00-07:00

    Rename and update secret

diff --git a/old.env b/new.env
similarity index 80%
rename from old.env
rename to new.env
--- a/old.env
+++ b/new.env
@@ -1 +1,2 @@
-token = old
+token = new
+api_key = sk-legendary
"#;

        let hunks = parse_git_log_for_added_lines(log);
        assert_eq!(hunks.len(), 1);
        assert_eq!(hunks[0].path, "new.env");
        assert!(hunks[0].content.contains("api_key = sk-legendary"));
    }

    #[test]
    fn parse_git_log_rejects_malicious_new_paths() {
        let log = r#"commit badc0de
Author: Test User <test@example.com>
Date: 2026-03-21T12:00:00-07:00

    Malicious patch

diff --git a/safe.txt b/../../etc/passwd
--- a/safe.txt
+++ b/../../etc/passwd
@@ -0,0 +1 @@
+api_key = should-not-scan
"#;

        let hunks = parse_git_log_for_added_lines(log);
        assert!(hunks.is_empty());
    }
}
