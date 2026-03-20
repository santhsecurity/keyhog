//! Match resolution: when multiple detectors match the same region, keep only
//! the most specific, highest-confidence match. Eliminates duplicates.

use std::collections::{HashMap, HashSet};

use keyhog_core::RawMatch;

const ADJACENT_LINE_DISTANCE: usize = 2;
const SINGLE_MATCH_COUNT: usize = 1;
const SCORE_EPSILON: f64 = 1e-9;
const ENTROPY_MATCH_SCORE: f64 = 0.0;
const NAMED_DETECTOR_SCORE: f64 = 10.0;
const CONFIDENCE_WEIGHT: f64 = 5.0;
const DETECTOR_ID_LENGTH_WEIGHT: f64 = 0.1;
const MAX_CREDENTIAL_SCORE_LENGTH: usize = 200;
const CREDENTIAL_LENGTH_WEIGHT: f64 = 0.01;

/// Resolve overlapping matches: for each credential text region,
/// keep only the best match. Also suppress entropy findings when
/// a named detector already found a secret on the same line.
pub fn resolve_matches(mut matches: Vec<RawMatch>) -> Vec<RawMatch> {
    if matches.len() <= SINGLE_MATCH_COUNT {
        return matches;
    }
    suppress_entropy_matches_near_named_detectors(&mut matches);
    resolve_match_groups(matches)
}

fn suppress_entropy_matches_near_named_detectors(matches: &mut Vec<RawMatch>) {
    let named_lines: HashSet<(String, usize)> = matches
        .iter()
        .filter(|m| m.detector_id != "entropy")
        .filter_map(|m| {
            let path = m.location.file_path.clone().unwrap_or_default();
            m.location.line.map(|line| (path, line))
        })
        .collect();
    matches.retain(|m| {
        if m.detector_id != "entropy" {
            return true;
        }
        let path = m.location.file_path.clone().unwrap_or_default();
        if let Some(line) = m.location.line {
            for offset in 0..=ADJACENT_LINE_DISTANCE {
                if named_lines.contains(&(path.clone(), line.saturating_sub(offset)))
                    || named_lines.contains(&(path.clone(), line.saturating_add(offset)))
                {
                    return false;
                }
            }
        }
        true
    });
}

fn resolve_match_groups(mut matches: Vec<RawMatch>) -> Vec<RawMatch> {
    // Group by (credential, file_path) — resolution only deduplicates within the
    // same file. Cross-file dedup is the CLI's responsibility via --dedup.
    let mut groups: HashMap<(String, String), Vec<RawMatch>> = HashMap::new();
    for m in matches.drain(..) {
        let file = m.location.file_path.clone().unwrap_or_default();
        groups
            .entry((m.credential.clone(), file))
            .or_default()
            .push(m);
    }
    let mut resolved = Vec::new();
    for group in groups.into_values() {
        if group.len() == SINGLE_MATCH_COUNT {
            resolved.extend(group);
            continue;
        }
        resolved.extend(best_matches_for_group(group));
    }
    resolved
}

fn best_matches_for_group(group: Vec<RawMatch>) -> Vec<RawMatch> {
    let mut scored: Vec<(f64, RawMatch)> = group
        .into_iter()
        .map(|matched| (match_priority_score(&matched), matched))
        .collect();
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let top_score = scored[0].0;
    scored
        .into_iter()
        .take_while(|(score, _)| (*score - top_score).abs() < SCORE_EPSILON)
        .map(|(_, matched)| matched)
        .collect()
}

/// Compute the priority score used to break ties between overlapping matches.
fn match_priority_score(m: &RawMatch) -> f64 {
    let mut score = ENTROPY_MATCH_SCORE;

    // Named detector vs entropy: named always wins.
    if m.detector_id == "entropy" {
        score += ENTROPY_MATCH_SCORE;
    } else {
        score += NAMED_DETECTOR_SCORE;
    }

    // Confidence score contributes directly.
    if let Some(conf) = m.confidence {
        score += conf * CONFIDENCE_WEIGHT;
    }

    // Longer detector ID prefix in the credential = more specific match.
    // e.g., "openai-api-key" matching "sk-proj-..." is more specific than
    // "deepseek-api-key" matching "sk-..." on the same text.
    // We approximate this by the detector_id length (longer IDs tend to be
    // more specific services, not generic patterns).
    score += (m.detector_id.len() as f64) * DETECTOR_ID_LENGTH_WEIGHT;

    // Credential length matters: longer credentials are more specific matches.
    score +=
        (m.credential.len().min(MAX_CREDENTIAL_SCORE_LENGTH) as f64) * CREDENTIAL_LENGTH_WEIGHT;

    score
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyhog_core::{MatchLocation, Severity};

    fn make_match(detector_id: &str, credential: &str, confidence: Option<f64>) -> RawMatch {
        RawMatch {
            detector_id: detector_id.into(),
            detector_name: detector_id.into(),
            service: "test".into(),
            severity: Severity::High,
            credential: credential.into(),
            companion: None,
            location: MatchLocation {
                source: "test".into(),
                file_path: Some("test.txt".into()),
                line: Some(1),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            entropy: None,
            confidence,
        }
    }

    #[test]
    fn named_beats_entropy() {
        let matches = vec![
            make_match("github-classic-pat", "ghp_ABC123", Some(0.75)),
            make_match("entropy", "ghp_ABC123", Some(0.90)),
        ];
        let resolved = resolve_matches(matches);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].detector_id, "github-classic-pat");
        assert_eq!(resolved[0].credential, "ghp_ABC123");
    }

    #[test]
    fn higher_confidence_wins() {
        let matches = vec![
            make_match("stripe-secret-key", "sk_live_abc123", Some(0.85)),
            make_match("generic-sk-token", "sk_live_abc123", Some(0.40)),
        ];
        let resolved = resolve_matches(matches);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].detector_id, "stripe-secret-key");
        assert_eq!(resolved[0].credential, "sk_live_abc123");
    }

    #[test]
    fn single_match_passes_through() {
        let matches = vec![make_match("aws", "AKIA123", Some(0.5))];
        let resolved = resolve_matches(matches);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].credential, "AKIA123");
    }

    #[test]
    fn different_credentials_kept() {
        let matches = vec![
            make_match("github", "ghp_ABC", Some(0.8)),
            make_match("slack", "xoxb-123", Some(0.8)),
        ];
        let resolved = resolve_matches(matches);
        assert_eq!(resolved.len(), 2);
        assert!(resolved.iter().any(|m| m.credential == "ghp_ABC"));
        assert!(resolved.iter().any(|m| m.credential == "xoxb-123"));
    }

    #[test]
    fn empty_input() {
        let resolved = resolve_matches(vec![]);
        assert!(resolved.is_empty());
    }
}
