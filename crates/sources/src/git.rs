//! Git repository source: scans repository commits and extracts text blobs with
//! `gix`, stopping once the in-memory byte cap is reached.

use std::collections::HashSet;
use std::path::PathBuf;

use gix::objs::Kind;
use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};

const MAX_GIT_TOTAL_BYTES: usize = 256 * 1024 * 1024;
const MAX_GIT_BLOB_BYTES: u64 = 10 * 1024 * 1024;

/// Scans git history: traverses commits and extracts text blob contents.
pub struct GitSource {
    repo_path: PathBuf,
    max_commits: Option<usize>,
}

impl GitSource {
    /// Create a source that traverses a git repository.
    pub fn new(repo_path: PathBuf) -> Self {
        Self {
            repo_path,
            max_commits: None,
        }
    }

    /// Limit how many commits are traversed from `HEAD`.
    pub fn with_max_commits(mut self, n: usize) -> Self {
        self.max_commits = Some(n);
        self
    }
}

impl Source for GitSource {
    fn name(&self) -> &str {
        "git"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        let chunk_collection = collect_git_chunks(&self.repo_path, self.max_commits);
        match chunk_collection {
            Ok(chunks) => Box::new(chunks.into_iter().map(Ok)),
            Err(e) => Box::new(std::iter::once(Err(e))),
        }
    }
}

fn collect_git_chunks(
    repo_path: &std::path::Path,
    max_commits: Option<usize>,
) -> Result<Vec<Chunk>, SourceError> {
    let repo = gix::open(repo_path).map_err(|e| SourceError::Git(e.to_string()))?;

    let head = repo
        .head_commit()
        .map_err(|e| SourceError::Git(format!("failed to get HEAD: {}", e)))?;

    let ancestors = head
        .ancestors()
        .all()
        .map_err(|e| SourceError::Git(format!("failed to traverse: {}", e)))?;

    let mut chunks = Vec::new();
    let mut seen_blobs: HashSet<gix::ObjectId> = HashSet::new();
    let mut total_bytes = 0usize;
    let mut traversal = BlobTraversal {
        seen_blobs: &mut seen_blobs,
        chunks: &mut chunks,
        total_bytes: &mut total_bytes,
    };
    for (count, info) in ancestors.enumerate() {
        if let Some(max) = max_commits
            && count >= max
        {
            break;
        }

        let info = match info {
            Ok(i) => i,
            Err(e) => {
                tracing::debug!("failed to traverse git commit: {}", e);
                continue;
            }
        };

        let obj = match info.id().object() {
            Ok(o) => o,
            Err(_) => continue,
        };
        let commit: gix::Commit<'_> = match obj.try_into_commit() {
            Ok(c) => c,
            Err(_) => continue,
        };

        let commit_id = info.id().to_string();
        let author = commit
            .author()
            .map(|a| a.name.to_string())
            .unwrap_or_default();

        let tree = match commit.tree() {
            Ok(t) => t,
            Err(_) => continue,
        };

        collect_tree_blobs(&repo, &tree, &commit_id, &author, &mut traversal, b"");
        if *traversal.total_bytes >= MAX_GIT_TOTAL_BYTES {
            tracing::warn!(
                "failed to continue git history scan: reached {} byte in-memory limit",
                MAX_GIT_TOTAL_BYTES
            );
            break;
        }
    }

    Ok(chunks)
}

struct BlobTraversal<'a> {
    seen_blobs: &'a mut HashSet<gix::ObjectId>,
    chunks: &'a mut Vec<Chunk>,
    total_bytes: &'a mut usize,
}

fn collect_tree_blobs(
    repo: &gix::Repository,
    tree: &gix::Tree<'_>,
    commit_id: &str,
    author: &str,
    traversal: &mut BlobTraversal<'_>,
    prefix: &[u8],
) {
    if *traversal.total_bytes >= MAX_GIT_TOTAL_BYTES {
        return;
    }
    for entry_ref in tree.iter() {
        if *traversal.total_bytes >= MAX_GIT_TOTAL_BYTES {
            return;
        }
        let entry = match entry_ref {
            Ok(e) => e,
            Err(_) => continue,
        };

        let oid = entry.oid().to_owned();

        let filepath = if prefix.is_empty() {
            entry.filename().to_vec()
        } else {
            let mut p = prefix.to_vec();
            p.push(b'/');
            p.extend_from_slice(entry.filename());
            p
        };

        let mode = entry.mode();

        if mode.is_tree() {
            if let Ok(obj) = repo.find_object(oid)
                && let Ok(subtree) = obj.try_into_tree()
            {
                collect_tree_blobs(repo, &subtree, commit_id, author, traversal, &filepath);
            }
            continue;
        }

        if !mode.is_blob() {
            continue;
        }

        if !traversal.seen_blobs.insert(oid) {
            continue;
        }

        let header = match repo.find_header(oid) {
            Ok(header) => header,
            Err(_) => continue,
        };
        if header.kind() != Kind::Blob || header.size() > MAX_GIT_BLOB_BYTES {
            continue;
        }

        let obj = match repo.find_object(oid) {
            Ok(o) => o,
            Err(_) => continue,
        };

        let file_text = match std::str::from_utf8(&obj.data) {
            Ok(text) => text.to_string(),
            Err(_) => continue,
        };

        let path = String::from_utf8_lossy(&filepath).to_string();
        *traversal.total_bytes = traversal.total_bytes.saturating_add(file_text.len());

        traversal.chunks.push(Chunk {
            data: file_text,
            metadata: ChunkMetadata {
                source_type: "git".into(),
                path: Some(path),
                commit: Some(commit_id.to_string()),
                author: Some(author.to_string()),
                date: None,
            },
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_source_name() {
        let source = GitSource::new(PathBuf::from("/tmp"));
        assert_eq!(source.name(), "git");
    }

    #[test]
    fn git_source_with_max_commits() {
        let source = GitSource::new(PathBuf::from("/tmp")).with_max_commits(100);
        assert_eq!(source.max_commits, Some(100));
    }

    #[test]
    fn git_source_default_no_commit_limit() {
        let source = GitSource::new(PathBuf::from("/tmp"));
        assert!(source.max_commits.is_none());
    }
}
