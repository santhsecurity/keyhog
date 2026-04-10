//! Git diff source: scans only added/modified lines from `git diff`, ideal for
//! CI/CD pre-commit hooks that should only flag new secrets.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use std::io::BufRead;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

/// Scans only the ADDED lines between two git refs.
/// Uses `git diff` unified diff output and extracts lines starting with '+'.
/// Useful for CI/CD pre-commit hooks and PR checks.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::Source;
/// use keyhog_sources::GitDiffSource;
/// use std::path::PathBuf;
///
/// let source = GitDiffSource::new(PathBuf::from("."), "main").with_head_ref("HEAD");
/// assert_eq!(source.name(), "git-diff");
/// ```
pub struct GitDiffSource {
    repo_path: PathBuf,
    base_ref: String,
    head_ref: Option<String>,
}

impl GitDiffSource {
    /// Create a new diff source comparing `base_ref` to HEAD.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Source;
    /// use keyhog_sources::GitDiffSource;
    /// use std::path::PathBuf;
    ///
    /// let source = GitDiffSource::new(PathBuf::from("."), "origin/main");
    /// assert_eq!(source.name(), "git-diff");
    /// ```
    pub fn new(repo_path: PathBuf, base_ref: impl Into<String>) -> Self {
        Self {
            repo_path,
            base_ref: base_ref.into(),
            head_ref: None,
        }
    }

    /// Set a specific head ref to compare against (defaults to HEAD).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Source;
    /// use keyhog_sources::GitDiffSource;
    /// use std::path::PathBuf;
    ///
    /// let source = GitDiffSource::new(PathBuf::from("."), "main").with_head_ref("feature");
    /// assert_eq!(source.name(), "git-diff");
    /// ```
    pub fn with_head_ref(mut self, head_ref: impl Into<String>) -> Self {
        self.head_ref = Some(head_ref.into());
        self
    }
}

impl Source for GitDiffSource {
    fn name(&self) -> &str {
        "git-diff"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        match stream_added_lines(&self.repo_path, &self.base_ref, self.head_ref.as_deref()) {
            Ok(iter) => Box::new(iter),
            Err(e) => Box::new(std::iter::once(Err(e))),
        }
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Stream only ADDED lines from git diff output.
fn stream_added_lines(
    repo_path: &Path,
    base_ref: &str,
    head_ref: Option<&str>,
) -> Result<impl Iterator<Item = Result<Chunk, SourceError>>, SourceError> {
    let base_ref = super::validate_ref_name(base_ref)?;
    let head_ref = super::validate_ref_name(head_ref.unwrap_or("HEAD"))?;
    let repo_root = super::canonical_repo_root(repo_path)?;
    let repo_arg = super::validate_repo_path(&repo_root)?;

    // Verify the refs exist first
    super::verify_ref(&repo_arg, &base_ref)?;
    super::verify_ref(&repo_arg, &head_ref)?;
    let base_commit = super::get_commit_hash(&repo_arg, &base_ref)?;
    let head_commit = super::get_commit_hash(&repo_arg, &head_ref)?;

    // Run git diff to get unified diff output
    let mut command = Command::new("git");
    command.args([
        "-C",
        &repo_arg,
        "diff",
        "-U0",
        "--end-of-options",
        &base_commit,
        &head_commit,
    ]);

    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let mut child = command.spawn().map_err(SourceError::Io)?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SourceError::Io(std::io::Error::other("missing stdout")))?;
    let mut reader = std::io::BufReader::new(stdout).lines();

    // Get commit info for metadata
    let author = super::get_commit_author(&repo_arg, &head_commit)?;
    let date = super::get_commit_date(&repo_arg, &head_commit)?;

    let mut current_path: Option<String> = None;
    let mut current_content = String::new();
    let mut in_hunk = false;
    let mut done = false;

    Ok(std::iter::from_fn(move || {
        if done {
            return None;
        }

        loop {
            let line = match reader.next() {
                Some(Ok(l)) => l,
                Some(Err(e)) => {
                    done = true;
                    return Some(Err(SourceError::Io(e)));
                }
                None => {
                    done = true;
                    if let Some(ref path) = current_path
                        && !current_content.trim().is_empty()
                    {
                        return Some(Ok(Chunk {
                            data: current_content.trim().to_string(),
                            metadata: ChunkMetadata {
                                source_type: "git-diff".into(),
                                path: Some(path.clone()),
                                commit: Some(head_commit.clone()),
                                author: Some(author.clone()),
                                date: Some(date.clone()),
                            },
                        }));
                    }
                    return None;
                }
            };

            if line.starts_with("diff --git ") {
                let prev_path = current_path.take();
                let prev_content = std::mem::take(&mut current_content);

                in_hunk = false;

                if let Some(path) = prev_path
                    && !prev_content.trim().is_empty()
                {
                    return Some(Ok(Chunk {
                        data: prev_content.trim().to_string(),
                        metadata: ChunkMetadata {
                            source_type: "git-diff".into(),
                            path: Some(path),
                            commit: Some(head_commit.clone()),
                            author: Some(author.clone()),
                            date: Some(date.clone()),
                        },
                    }));
                }
                continue;
            }

            if line.starts_with("deleted file mode") {
                current_path = None;
                continue;
            }

            if line.starts_with("new file mode")
                || line.starts_with("index ")
                || line.starts_with("--- ")
            {
                continue;
            }

            if let Some(path_part) = line.strip_prefix("+++ b/") {
                current_path = Some(path_part.trim().to_string());
                continue;
            }

            if line.starts_with("@@") && line.contains("@@") {
                in_hunk = true;
                continue;
            }

            if in_hunk && line.starts_with('+') && !line.starts_with("+++") {
                current_content.push_str(&line[1..]);
                current_content.push('\n');
            }

            if current_content.len() > 10 * 1024 * 1024
                && let Some(ref path) = current_path
                && !current_content.trim().is_empty()
            {
                let chunk_content = current_content.trim().to_string();
                current_content = String::new();
                return Some(Ok(Chunk {
                    data: chunk_content,
                    metadata: ChunkMetadata {
                        source_type: "git-diff".into(),
                        path: Some(path.clone()),
                        commit: Some(head_commit.clone()),
                        author: Some(author.clone()),
                        date: Some(date.clone()),
                    },
                }));
            }
        }
    }))
}

#[cfg(test)]
struct AddedHunk {
    path: String,
    content: String,
}

#[cfg(test)]
fn parse_diff_for_added_lines(diff: &str, repo_root: &Path) -> Result<Vec<AddedHunk>, SourceError> {
    let mut hunks = Vec::new();
    let mut current_path: Option<String> = None;
    let mut current_content = String::new();
    let mut in_hunk = false;

    for line in diff.lines() {
        if line.starts_with("diff --git ") {
            if let Some(path) = current_path.take() {
                if !current_content.trim().is_empty() {
                    hunks.push(AddedHunk {
                        path,
                        content: current_content.trim().to_string(),
                    });
                }
            }
            current_content.clear();
            in_hunk = false;
            continue;
        }

        if line.starts_with("deleted file mode") {
            current_path = None;
            continue;
        }

        if let Some(path_part) = line.strip_prefix("+++ b/") {
            current_path = sanitize_diff_path(path_part, repo_root);
            continue;
        }

        if line.starts_with("@@") && line.contains("@@") {
            in_hunk = true;
            continue;
        }

        if in_hunk && line.starts_with('+') && !line.starts_with("+++") {
            current_content.push_str(&line[1..]);
            current_content.push('\n');
        }
    }

    if let Some(path) = current_path {
        if !current_content.trim().is_empty() {
            hunks.push(AddedHunk {
                path,
                content: current_content.trim().to_string(),
            });
        }
    }

    Ok(hunks)
}

#[allow(dead_code)]
fn sanitize_diff_path(path: &str, repo_root: &Path) -> Option<String> {
    let path = path.trim();
    if path == "/dev/null" || path.is_empty() {
        return None;
    }

    let candidate = Path::new(path);
    if candidate.is_absolute() || path.chars().any(char::is_control) {
        return None;
    }

    let mut normalized = PathBuf::new();
    for component in candidate.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }

    if normalized.as_os_str().is_empty() {
        return None;
    }

    // Security boundary: check if any component of the path is a symlink that
    // escapes the repository root. This prevents scanning arbitrary files
    // via malicious diff headers.
    let mut current = repo_root.to_path_buf();
    for component in normalized.components() {
        if let Component::Normal(part) = component {
            current.push(part);
            if let Ok(metadata) = std::fs::symlink_metadata(&current)
                && metadata.is_symlink()
                && let Ok(link_target) = std::fs::read_link(&current)
            {
                let absolute_target = if link_target.is_absolute() {
                    link_target
                } else {
                    current.parent().unwrap_or(repo_root).join(link_target)
                };

                if let Ok(canonical_target) = absolute_target.canonicalize()
                    && let Ok(canonical_root) = repo_root.canonicalize()
                    && !canonical_target.starts_with(canonical_root)
                {
                    return None;
                }
            }
        }
    }

    Some(normalized.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn create_test_repo() -> (tempfile::TempDir, PathBuf) {
        let temp_dir = tempfile::tempdir().unwrap();
        let repo_path = temp_dir.path().to_path_buf();

        // Initialize git repo with initial branch name "main"
        let output = Command::new("git")
            .args(["init", "-b", "main"])
            .current_dir(&repo_path)
            .output()
            .expect("failed to execute git init");
        assert!(output.status.success(), "git init failed: {:?}", output);

        // Configure git user for commits
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
    fn test_git_diff_source_new() {
        let source = GitDiffSource::new(PathBuf::from("."), "main");
        assert_eq!(source.name(), "git-diff");
    }

    #[test]
    fn test_git_diff_source_with_head() {
        let source = GitDiffSource::new(PathBuf::from("."), "main").with_head_ref("feature");
        assert_eq!(source.name(), "git-diff");
    }

    #[test]
    fn rejects_unsafe_git_refs() {
        assert!(super::super::validate_ref_name("--upload-pack=sh").is_err());
        assert!(super::super::validate_ref_name("main..feature").is_err());
        assert!(super::super::validate_ref_name("feature branch").is_err());
        assert_eq!(super::super::validate_ref_name("HEAD~1").unwrap(), "HEAD~1");
        assert_eq!(
            super::super::validate_ref_name("refs/heads/main").unwrap(),
            "refs/heads/main"
        );
    }

    #[test]
    fn rejects_option_like_repo_paths() {
        let error = super::super::validate_repo_path(Path::new("-c")).unwrap_err();
        assert!(error.to_string().contains("unsafe"));
    }

    #[test]
    fn test_git_diff_finds_added_lines_in_new_file() {
        let (_temp_dir, repo_path) = create_test_repo();

        // Create initial commit on main branch
        commit_file(
            &repo_path,
            "initial.txt",
            "initial content",
            "Initial commit",
        );

        // Create a feature branch and add a file
        Command::new("git")
            .args(["checkout", "-b", "feature"])
            .current_dir(&repo_path)
            .output()
            .unwrap();

        commit_file(
            &repo_path,
            "secret.txt",
            "api_key = sk-test12345",
            "Add secret",
        );

        // Now diff between main and feature should show the added lines
        let source = GitDiffSource::new(repo_path.clone(), "main").with_head_ref("feature");
        let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

        assert_eq!(chunks.len(), 1, "Should find one chunk with added lines");
        assert_eq!(chunks[0].metadata.path, Some("secret.txt".to_string()));
        // Should only contain the ADDED line, not the full file content
        assert!(chunks[0].data.contains("sk-test12345"));
        assert_eq!(chunks[0].metadata.source_type, "git-diff");
        assert!(chunks[0].metadata.commit.is_some());
    }

    #[test]
    fn test_git_diff_finds_only_added_lines_not_deleted() {
        let (_temp_dir, repo_path) = create_test_repo();

        // Create initial commit with a file
        commit_file(
            &repo_path,
            "config.txt",
            "old_secret_key = sk-old\nother = value",
            "Initial commit",
        );

        // Create a branch and modify the file
        Command::new("git")
            .args(["checkout", "-b", "feature"])
            .current_dir(&repo_path)
            .output()
            .unwrap();

        // Replace the old secret with a new one
        commit_file(
            &repo_path,
            "config.txt",
            "new_secret_key = sk-new\nother = value",
            "Update config",
        );

        // Diff should show only the ADDED lines (new_secret_key), not deleted lines
        let source = GitDiffSource::new(repo_path.clone(), "main").with_head_ref("feature");
        let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

        assert_eq!(chunks.len(), 1, "Should find one chunk");
        assert_eq!(chunks[0].metadata.path, Some("config.txt".to_string()));
        // Should contain the NEW secret
        assert!(chunks[0].data.contains("sk-new"));
        // Should NOT contain the OLD (deleted) secret
        assert!(!chunks[0].data.contains("sk-old"));
    }

    #[test]
    fn test_git_diff_skips_deleted_files() {
        let (_temp_dir, repo_path) = create_test_repo();

        // Create initial commit with files
        commit_file(&repo_path, "keep.txt", "keep this", "Initial commit");
        commit_file(
            &repo_path,
            "delete.txt",
            "delete this",
            "Add file to delete",
        );

        // Create a branch and delete the file
        Command::new("git")
            .args(["checkout", "-b", "feature"])
            .current_dir(&repo_path)
            .output()
            .unwrap();

        fs::remove_file(repo_path.join("delete.txt")).unwrap();
        Command::new("git")
            .args(["rm", "delete.txt"])
            .current_dir(&repo_path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "Delete file"])
            .current_dir(&repo_path)
            .output()
            .unwrap();

        // Diff should NOT show deleted files - only added/modified content
        let source = GitDiffSource::new(repo_path.clone(), "main").with_head_ref("feature");
        let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

        // Deleted file should yield no chunks (no added lines)
        assert!(
            chunks.is_empty(),
            "Should not find chunks for deleted files"
        );
    }

    #[test]
    fn test_git_diff_defaults_to_head() {
        let (_temp_dir, repo_path) = create_test_repo();

        // Create initial commit
        commit_file(&repo_path, "file.txt", "content", "Initial commit");

        // Create a branch and add a file
        Command::new("git")
            .args(["checkout", "-b", "feature"])
            .current_dir(&repo_path)
            .output()
            .unwrap();

        commit_file(&repo_path, "new.txt", "new content", "Add file");

        // Don't specify head_ref - should default to HEAD (which points to feature)
        let source = GitDiffSource::new(repo_path.clone(), "main");
        let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].metadata.path, Some("new.txt".to_string()));
        assert!(chunks[0].data.contains("new content"));
    }

    #[test]
    fn test_git_diff_with_tilde_ref() {
        let (_temp_dir, repo_path) = create_test_repo();

        // Create multiple commits
        commit_file(&repo_path, "file1.txt", "content1", "First commit");
        commit_file(&repo_path, "file2.txt", "content2", "Second commit");
        commit_file(&repo_path, "file3.txt", "content3", "Third commit");

        // Diff HEAD~2..HEAD should show changes from last 2 commits
        let source = GitDiffSource::new(repo_path.clone(), "HEAD~2");
        let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

        assert_eq!(chunks.len(), 2, "Should find chunks from last 2 commits");
        let paths: Vec<_> = chunks.iter().map(|c| c.metadata.path.clone()).collect();
        assert!(paths.contains(&Some("file2.txt".to_string())));
        assert!(paths.contains(&Some("file3.txt".to_string())));
    }

    #[test]
    fn test_git_diff_nonexistent_ref() {
        let (_temp_dir, repo_path) = create_test_repo();

        commit_file(&repo_path, "file.txt", "content", "Initial commit");

        // Try to diff against non-existent ref
        let source = GitDiffSource::new(repo_path.clone(), "nonexistent-branch");
        let chunk_collection: Result<Vec<_>, _> = source.chunks().collect();

        assert!(
            chunk_collection.is_err(),
            "Should fail with non-existent ref"
        );
    }

    #[test]
    fn test_git_diff_multiple_added_files() {
        let (_temp_dir, repo_path) = create_test_repo();

        commit_file(&repo_path, "initial.txt", "initial", "Initial commit");

        Command::new("git")
            .args(["checkout", "-b", "feature"])
            .current_dir(&repo_path)
            .output()
            .unwrap();

        // Add multiple files in a single commit
        commit_file(&repo_path, "file1.txt", "secret1", "Add file1");
        commit_file(&repo_path, "file2.txt", "secret2", "Add file2");
        commit_file(&repo_path, "file3.txt", "secret3", "Add file3");

        let source = GitDiffSource::new(repo_path.clone(), "main");
        let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

        assert_eq!(chunks.len(), 3);
        let paths: Vec<_> = chunks
            .iter()
            .map(|c| c.metadata.path.clone().unwrap())
            .collect();
        assert!(paths.contains(&"file1.txt".to_string()));
        assert!(paths.contains(&"file2.txt".to_string()));
        assert!(paths.contains(&"file3.txt".to_string()));
    }

    #[test]
    fn test_git_diff_empty_repo() {
        let temp_dir = tempfile::tempdir().unwrap();
        let repo_path = temp_dir.path().to_path_buf();

        // Initialize repo but don't make any commits
        Command::new("git")
            .args(["init"])
            .current_dir(&repo_path)
            .output()
            .unwrap();
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

        let source = GitDiffSource::new(repo_path.clone(), "HEAD");
        let chunk_collection: Result<Vec<_>, _> = source.chunks().collect();

        assert!(chunk_collection.is_err(), "Should fail for empty repo");
    }

    #[test]
    fn test_parse_diff_simple_addition() {
        let repo_root = Path::new("/tmp");
        let diff = r#"diff --git a/test.txt b/test.txt
new file mode 100644
index 0000000..e69de29
--- /dev/null
+++ b/test.txt
@@ -0,0 +1,3 @@
+line1
+line2
+line3
"#;

        let hunks = parse_diff_for_added_lines(diff, repo_root).unwrap();
        assert_eq!(hunks.len(), 1);
        assert_eq!(hunks[0].path, "test.txt");
        assert_eq!(hunks[0].content, "line1\nline2\nline3");
    }

    #[test]
    fn test_parse_diff_with_deletions() {
        let repo_root = Path::new("/tmp");
        let diff = r#"diff --git a/test.txt b/test.txt
index abc1234..def5678 100644
--- a/test.txt
+++ b/test.txt
@@ -1,3 +1,3 @@
-old_line1
-old_line2
+new_line1
+new_line2
 unchanged
"#;

        let hunks = parse_diff_for_added_lines(diff, repo_root).unwrap();
        assert_eq!(hunks.len(), 1);
        assert_eq!(hunks[0].path, "test.txt");
        // Should only contain added lines
        assert!(hunks[0].content.contains("new_line1"));
        assert!(hunks[0].content.contains("new_line2"));
        assert!(!hunks[0].content.contains("old_line1"));
        assert!(!hunks[0].content.contains("old_line2"));
        assert!(!hunks[0].content.contains("unchanged"));
    }

    #[test]
    fn test_parse_diff_multiple_files() {
        let repo_root = Path::new("/tmp");
        let diff = r#"diff --git a/file1.txt b/file1.txt
new file mode 100644
index 0000000..e69de29
--- /dev/null
+++ b/file1.txt
@@ -0,0 +1,1 @@
+content1

diff --git a/file2.txt b/file2.txt
new file mode 100644
index 0000000..e69de29
--- /dev/null
+++ b/file2.txt
@@ -0,0 +1,1 @@
+content2
"#;

        let hunks = parse_diff_for_added_lines(diff, repo_root).unwrap();
        assert_eq!(hunks.len(), 2);

        let paths: Vec<_> = hunks.iter().map(|h| &h.path).collect();
        assert!(paths.contains(&&"file1.txt".to_string()));
        assert!(paths.contains(&&"file2.txt".to_string()));
    }

    #[test]
    fn test_parse_diff_deleted_file() {
        let repo_root = Path::new("/tmp");
        let diff = r#"diff --git a/deleted.txt b/deleted.txt
deleted file mode 100644
index e69de29..0000000
--- a/deleted.txt
+++ /dev/null
@@ -1,3 +0,0 @@
-line1
-line2
-line3
"#;

        let hunks = parse_diff_for_added_lines(diff, repo_root).unwrap();
        // Deleted file should yield no hunks (no added lines)
        assert!(hunks.is_empty());
    }

    #[test]
    fn test_parse_diff_uses_canonical_header_path() {
        let repo_root = Path::new("/tmp");
        let diff = r#"diff --git a/dir b/file.txt b/dir b/file.txt
index abc1234..def5678 100644
--- a/dir b/file.txt
+++ b/dir b/file.txt
@@ -1 +1 @@
+secret
"#;

        let hunks = parse_diff_for_added_lines(diff, repo_root).unwrap();
        assert_eq!(hunks.len(), 1);
        assert_eq!(hunks[0].path, "dir b/file.txt");
    }

    #[test]
    fn test_parse_diff_rejects_path_traversal_header() {
        let repo_root = Path::new("/tmp");
        let diff = r#"diff --git a/safe.txt b/../../etc/passwd
index abc1234..def5678 100644
--- a/safe.txt
+++ b/../../etc/passwd
@@ -1 +1 @@
+secret
"#;

        let hunks = parse_diff_for_added_lines(diff, repo_root).unwrap();
        assert!(hunks.is_empty());
    }

    #[test]
    #[allow(dead_code)]
    fn sanitize_diff_path_allows_missing_nested_file_inside_repo() {
        let temp_dir = tempfile::tempdir().unwrap();
        let repo_root = temp_dir.path();

        let sanitized = sanitize_diff_path("new/dir/file.txt", repo_root);
        assert_eq!(sanitized.as_deref(), Some("new/dir/file.txt"));
    }

    #[test]
    #[allow(dead_code)]
    fn sanitize_diff_path_normalizes_curdir_segments() {
        let temp_dir = tempfile::tempdir().unwrap();
        let repo_root = temp_dir.path();

        let sanitized = sanitize_diff_path("./src/./main.rs", repo_root);
        assert_eq!(sanitized.as_deref(), Some("src/main.rs"));
    }

    #[cfg(unix)]
    #[test]
    #[allow(dead_code)]
    fn sanitize_diff_path_rejects_missing_file_through_escape_symlink() {
        let temp_dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), temp_dir.path().join("escape")).unwrap();

        let sanitized = sanitize_diff_path("escape/new-secret.txt", temp_dir.path());
        assert!(sanitized.is_none());
    }
}
