//! Git diff source: scans only added/modified lines from `git diff`, ideal for
//! CI/CD pre-commit hooks that should only flag new secrets.

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use unicode_normalization::UnicodeNormalization;

const DEFAULT_GIT_DIR: &str = ".";

/// Scans only the ADDED lines between two git refs.
/// Uses `git diff` unified diff output and extracts lines starting with '+'.
/// Useful for CI/CD pre-commit hooks and PR checks.
pub struct GitDiffSource {
    repo_path: PathBuf,
    base_ref: String,
    head_ref: Option<String>,
}

impl GitDiffSource {
    /// Create a new diff source comparing `base_ref` to HEAD.
    pub fn new(repo_path: PathBuf, base_ref: impl Into<String>) -> Self {
        Self {
            repo_path,
            base_ref: base_ref.into(),
            head_ref: None,
        }
    }

    /// Set a specific head ref to compare against (defaults to HEAD).
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
        let chunk_collection =
            collect_added_lines(&self.repo_path, &self.base_ref, self.head_ref.as_deref());
        match chunk_collection {
            Ok(chunks) => Box::new(chunks.into_iter().map(Ok)),
            Err(e) => Box::new(std::iter::once(Err(e))),
        }
    }
}

/// Represents a hunk of added lines in a diff.
struct AddedHunk {
    path: String,
    content: String,
}

/// Collect only ADDED lines from git diff output.
/// Parses unified diff format and extracts lines starting with '+' (but not '+++').
fn collect_added_lines(
    repo_path: &Path,
    base_ref: &str,
    head_ref: Option<&str>,
) -> Result<Vec<Chunk>, SourceError> {
    let base_ref = validate_ref_name(base_ref)?;
    let head_ref = validate_ref_name(head_ref.unwrap_or("HEAD"))?;
    let repo_root = canonical_repo_root(repo_path)?;
    let repo_arg = validate_repo_path(&repo_root)?;

    // Verify the refs exist first
    verify_ref(&repo_arg, &base_ref)?;
    verify_ref(&repo_arg, &head_ref)?;
    let base_commit = get_commit_hash(&repo_arg, &base_ref)?;
    let head_commit = get_commit_hash(&repo_arg, &head_ref)?;

    // Run git diff to get unified diff output
    let output = Command::new("git")
        .args(["-C", &repo_arg, "diff", "-U0", "--end-of-options", &base_commit, &head_commit])
        .output()
        .map_err(SourceError::Io)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SourceError::Git(format!("git diff failed: {}", stderr)));
    }

    let diff_output = String::from_utf8_lossy(&output.stdout);

    // Get commit info for metadata
    let author = get_commit_author(&repo_arg, &head_commit)?;
    let date = get_commit_date(&repo_arg, &head_commit)?;

    // Parse the diff and extract added lines grouped by file
    let hunks = parse_diff_for_added_lines(&diff_output, &repo_root)?;

    // Convert hunks to chunks
    let mut chunks = Vec::new();
    for hunk in hunks {
        // Skip empty hunks
        if hunk.content.trim().is_empty() {
            continue;
        }

        chunks.push(Chunk {
            data: hunk.content,
            metadata: ChunkMetadata {
                source_type: "git-diff".into(),
                path: Some(hunk.path),
                commit: Some(head_commit.clone()),
                author: Some(author.clone()),
                date: Some(date.clone()),
            },
        });
    }

    Ok(chunks)
}

/// Parse unified diff output and extract only added lines.
/// Returns hunks grouped by file path.
fn parse_diff_for_added_lines(
    diff_output: &str,
    repo_root: &Path,
) -> Result<Vec<AddedHunk>, SourceError> {
    let mut hunks: Vec<AddedHunk> = Vec::new();
    let mut current_path: Option<String> = None;
    let mut current_content = String::new();
    let mut in_hunk = false;

    for line in diff_output.lines() {
        // Check for diff --git line to identify the file
        // Format: diff --git a/<old_path> b/<new_path>
        if line.starts_with("diff --git ") {
            // Save previous hunk if we have content
            if let Some(ref path) = current_path
                && !current_content.trim().is_empty()
            {
                hunks.push(AddedHunk {
                    path: path.clone(),
                    content: current_content.trim().to_string(),
                });
            }

            current_content = String::new();
            in_hunk = false;
            current_path = None;
            continue;
        }

        // Skip deleted files (check for special case where file is deleted)
        // Deleted files have "deleted file mode" in the diff
        if line.starts_with("deleted file mode") {
            // This file was deleted, skip it by marking path as None
            current_path = None;
            continue;
        }

        // Skip new file mode indicator
        if line.starts_with("new file mode") {
            continue;
        }

        // Skip index line
        if line.starts_with("index ") {
            continue;
        }

        // Skip old file path lines (--- a/...)
        // Note: For new files, this is "--- /dev/null"
        if line.starts_with("--- ") {
            continue;
        }

        // Parse new file path (+++ b/...)
        // This confirms the file path for new/modified files
        if line.starts_with("+++ ") {
            // Extract path from "+++ b/path" or "+++ /dev/null" (for deleted)
            if let Some(path_part) = line.strip_prefix("+++ b/") {
                current_path = sanitize_diff_path(path_part, repo_root);
            }
            continue;
        }

        // Hunk header: @@ -old_start,old_len +new_start,new_len @@
        if line.starts_with("@@") && line.contains("@@") {
            in_hunk = true;
            continue;
        }

        // Process diff content lines
        if (in_hunk || line.starts_with('+')) && !line.starts_with("+++")
            || (in_hunk && line.starts_with('-') && !line.starts_with("---"))
        {
            // Added lines start with '+' but not '+++' (which is the file header)
            if line.starts_with('+') && !line.starts_with("+++") {
                // This is an added line - strip the leading '+' and add to content
                let content = &line[1..]; // Remove leading '+'
                current_content.push_str(content);
                current_content.push('\n');
            }
            // Skip deleted lines (start with '-' but not '---')
            // and context lines (start with ' ')
        }
    }

    // Don't forget the last hunk
    if let Some(ref path) = current_path
        && !current_content.trim().is_empty()
    {
        hunks.push(AddedHunk {
            path: path.clone(),
            content: current_content.trim().to_string(),
        });
    }

    Ok(hunks)
}

fn validate_repo_path(repo_path: &Path) -> Result<String, SourceError> {
    let path = repo_path.to_str().unwrap_or(DEFAULT_GIT_DIR);
    // Security boundary: `Command` avoids shell injection, but git still parses
    // `-C <path>` itself. Reject control chars and option-like paths so user
    // input cannot be reinterpreted as an extra git flag.
    if path.starts_with('-') || path.chars().any(char::is_control) {
        return Err(SourceError::Other(
            "repository path contains unsafe characters".into(),
        ));
    }
    Ok(path.to_string())
}

fn canonical_repo_root(repo_path: &Path) -> Result<PathBuf, SourceError> {
    std::fs::canonicalize(repo_path).map_err(SourceError::Io)
}

fn sanitize_diff_path(path: &str, repo_root: &Path) -> Option<String> {
    let path = path.trim().nfc().collect::<String>();
    if path == "/dev/null" || path.is_empty() {
        return None;
    }

    let candidate = Path::new(&path);
    if candidate.is_absolute() || path.chars().any(char::is_control) {
        return None;
    }

    let normalized = normalize_relative_diff_path(candidate)?;
    if normalized.to_string_lossy().contains(':') {
        return None;
    }

    let joined = repo_root.join(&normalized);
    if !has_repo_anchored_existing_ancestor(&joined, repo_root) {
        return None;
    }

    Some(normalized.to_string_lossy().into_owned())
}

fn normalize_relative_diff_path(path: &Path) -> Option<PathBuf> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }

    // SAFETY: `normalized` is rebuilt only from `Component::Normal` segments,
    // so any surviving `..` would indicate an unexpected path representation
    // and should be rejected before the path is joined against `repo_root`.
    if normalized
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return None;
    }

    (!normalized.as_os_str().is_empty()).then_some(normalized)
}

fn has_repo_anchored_existing_ancestor(path: &Path, repo_root: &Path) -> bool {
    let mut current = Some(path);
    while let Some(candidate) = current {
        match std::fs::canonicalize(candidate) {
            Ok(canonical) => return canonical.starts_with(repo_root),
            Err(_) => current = candidate.parent(),
        }
    }
    false
}

fn validate_ref_name(ref_name: &str) -> Result<String, SourceError> {
    let ref_name = ref_name.trim();
    if ref_name.is_empty() {
        return Err(SourceError::Git("git ref cannot be empty".into()));
    }

    // Security boundary: refs are passed to git as argv, but we still reject
    // option-like names and git's ambiguous revision syntax so auditors can see
    // the ref is constrained before `rev-parse` verifies it.
    if ref_name.starts_with('-')
        || ref_name
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
        || ref_name.contains("..")
        || ref_name.contains(':')
        || ref_name.contains('?')
        || ref_name.contains('*')
        || ref_name.contains('[')
        || ref_name.contains('\\')
    {
        return Err(SourceError::Git(format!("unsafe git ref '{ref_name}'")));
    }

    Ok(ref_name.to_string())
}

fn verify_ref(repo_path: &str, ref_name: &str) -> Result<(), SourceError> {
    let output = Command::new("git")
        .args(["-C", repo_path, "rev-parse", "--verify", "--end-of-options"])
        .arg(format!("{ref_name}^{{commit}}"))
        .output()
        .map_err(SourceError::Io)?;

    if !output.status.success() {
        return Err(SourceError::Git(format!(
            "ref '{}' not found in repository",
            ref_name
        )));
    }

    Ok(())
}

fn get_commit_hash(repo_path: &str, ref_name: &str) -> Result<String, SourceError> {
    let output = Command::new("git")
        // SAFETY: `--end-of-options` keeps validated refs from being re-read as
        // flags if a future caller ever relaxes `validate_ref_name`.
        .args(["-C", repo_path, "rev-parse", "--verify", "--end-of-options"])
        .arg(format!("{ref_name}^{{commit}}"))
        .output()
        .map_err(SourceError::Io)?;

    if !output.status.success() {
        return Err(SourceError::Git(format!(
            "failed to resolve ref: {}",
            ref_name
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn get_commit_author(repo_path: &str, ref_name: &str) -> Result<String, SourceError> {
    let output = Command::new("git")
        .args([
            "-C",
            repo_path,
            "log",
            "-1",
            "--format=%an",
            "--end-of-options",
        ])
        .arg(ref_name)
        .output()
        .map_err(SourceError::Io)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SourceError::Git(format!(
            "failed to read commit author for '{}': {}",
            ref_name,
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn get_commit_date(repo_path: &str, ref_name: &str) -> Result<String, SourceError> {
    let output = Command::new("git")
        .args([
            "-C",
            repo_path,
            "log",
            "-1",
            "--format=%aI",
            "--end-of-options",
        ])
        .arg(ref_name)
        .output()
        .map_err(SourceError::Io)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SourceError::Git(format!(
            "failed to read commit date for '{}': {}",
            ref_name,
            stderr.trim()
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
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
        assert!(validate_ref_name("--upload-pack=sh").is_err());
        assert!(validate_ref_name("main..feature").is_err());
        assert!(validate_ref_name("feature branch").is_err());
        assert_eq!(validate_ref_name("HEAD~1").unwrap(), "HEAD~1");
        assert_eq!(
            validate_ref_name("refs/heads/main").unwrap(),
            "refs/heads/main"
        );
    }

    #[test]
    fn rejects_option_like_repo_paths() {
        let error = validate_repo_path(Path::new("-c")).unwrap_err();
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
    fn sanitize_diff_path_allows_missing_nested_file_inside_repo() {
        let temp_dir = tempfile::tempdir().unwrap();
        let repo_root = temp_dir.path();

        let sanitized = sanitize_diff_path("new/dir/file.txt", repo_root);
        assert_eq!(sanitized.as_deref(), Some("new/dir/file.txt"));
    }

    #[test]
    fn sanitize_diff_path_normalizes_curdir_segments() {
        let temp_dir = tempfile::tempdir().unwrap();
        let repo_root = temp_dir.path();

        let sanitized = sanitize_diff_path("./src/./main.rs", repo_root);
        assert_eq!(sanitized.as_deref(), Some("src/main.rs"));
    }

    #[cfg(unix)]
    #[test]
    fn sanitize_diff_path_rejects_missing_file_through_escape_symlink() {
        let temp_dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), temp_dir.path().join("escape")).unwrap();

        let sanitized = sanitize_diff_path("escape/new-secret.txt", temp_dir.path());
        assert!(sanitized.is_none());
    }
}
