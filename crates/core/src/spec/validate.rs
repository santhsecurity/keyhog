//! Detector quality gate validation rules used while loading TOML specs.

use super::DetectorSpec;
use regex_syntax::ast::{self, Ast};

const MAX_REGEX_PATTERN_LEN: usize = 4096;
const MAX_REGEX_AST_NODES: usize = 512;
const MAX_REGEX_ALTERNATION_BRANCHES: usize = 64;
const MAX_REGEX_REPEAT_BOUND: u32 = 10_000;

/// Quality issue found in a detector spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QualityIssue {
    Error(String),
    Warning(String),
}

/// Validate a detector spec against the quality gate.
pub fn validate_detector(spec: &DetectorSpec) -> Vec<QualityIssue> {
    let mut issues = Vec::new();
    validate_patterns_present(spec, &mut issues);
    validate_regexes(spec, &mut issues);
    validate_keywords(spec, &mut issues);
    validate_pattern_specificity(spec, &mut issues);
    validate_companion(spec, &mut issues);
    validate_verify_spec(spec, &mut issues);
    issues
}

fn validate_patterns_present(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    if spec.patterns.is_empty() {
        issues.push(QualityIssue::Error("no patterns defined".into()));
    }
}

fn validate_regexes(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    for (i, pat) in spec.patterns.iter().enumerate() {
        if pat.regex.len() > MAX_REGEX_PATTERN_LEN {
            issues.push(QualityIssue::Error(format!(
                "pattern {} regex is too large ({} bytes > {} byte limit)",
                i,
                pat.regex.len(),
                MAX_REGEX_PATTERN_LEN
            )));
            continue;
        }

        match ast::parse::Parser::new().parse(&pat.regex) {
            Ok(ast) => validate_regex_complexity(i, &ast, issues),
            Err(_) => issues.push(QualityIssue::Error(format!(
                "pattern {} regex does not compile: {}",
                i, pat.regex
            ))),
        }
    }
}

fn validate_keywords(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    if spec.keywords.is_empty() {
        issues.push(QualityIssue::Warning(
            "no keywords defined — pattern may produce false positives".into(),
        ));
    }
}

fn validate_pattern_specificity(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    for (i, pat) in spec.patterns.iter().enumerate() {
        let has_prefix = has_literal_prefix(&pat.regex, 3);
        let has_group = pat.group.is_some();
        let is_pure_charclass = is_pure_character_class(&pat.regex);

        if is_pure_charclass && !has_group {
            issues.push(QualityIssue::Error(format!(
                "pattern {} is a pure character class ({}) — too broad without context anchoring. \
                 Use a capture group or add a literal prefix.",
                i, pat.regex
            )));
        } else if !has_prefix && !has_group && spec.keywords.is_empty() {
            issues.push(QualityIssue::Warning(format!(
                "pattern {} has no literal prefix and no capture group — may false-positive",
                i
            )));
        }
    }
}

fn validate_companion(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    if let Some(companion) = &spec.companion
        && companion.name.trim().is_empty()
    {
        issues.push(QualityIssue::Error(
            "companion name must not be empty".into(),
        ));
    }
}

fn validate_verify_spec(spec: &DetectorSpec, issues: &mut Vec<QualityIssue>) {
    if let Some(ref verify) = spec.verify {
        if verify.url.is_empty() {
            issues.push(QualityIssue::Error("verify URL is empty".into()));
        }
        if verify.url.starts_with("http://") && !verify.url.contains("localhost") {
            issues.push(QualityIssue::Warning(
                "verify URL uses HTTP instead of HTTPS".into(),
            ));
        }
    }
}

fn has_literal_prefix(pattern: &str, min_len: usize) -> bool {
    let mut count = 0;
    for ch in pattern.chars() {
        match ch {
            '[' | '(' | '.' | '*' | '+' | '?' | '{' | '\\' | '|' | '^' | '$' => break,
            _ => count += 1,
        }
    }
    count >= min_len
}

fn is_pure_character_class(pattern: &str) -> bool {
    let trimmed = pattern.trim();
    if !trimmed.starts_with('[') {
        return false;
    }

    let Some(close) = trimmed.find(']') else {
        return false;
    };
    let remainder = trimmed[close + 1..].trim();
    if remainder.is_empty() {
        return true;
    }
    if remainder == "+" || remainder == "*" || remainder == "?" {
        return true;
    }
    if remainder.starts_with('{')
        && let Some(qclose) = remainder.find('}')
    {
        let after_quantifier = remainder[qclose + 1..].trim();
        return after_quantifier.is_empty();
    }

    false
}

fn validate_regex_complexity(index: usize, ast: &Ast, issues: &mut Vec<QualityIssue>) {
    let mut stats = RegexComplexityStats::default();
    collect_regex_complexity(ast, &mut stats);
    collect_redos_risks(ast, &mut stats, false);

    if stats.nodes > MAX_REGEX_AST_NODES {
        issues.push(QualityIssue::Error(format!(
            "pattern {} regex is too complex ({} AST nodes > {} limit)",
            index, stats.nodes, MAX_REGEX_AST_NODES
        )));
    }

    if stats.max_alternation_branches > MAX_REGEX_ALTERNATION_BRANCHES {
        issues.push(QualityIssue::Error(format!(
            "pattern {} regex has too many alternation branches ({} > {} limit)",
            index, stats.max_alternation_branches, MAX_REGEX_ALTERNATION_BRANCHES
        )));
    }

    if stats.max_repeat_bound > MAX_REGEX_REPEAT_BOUND {
        issues.push(QualityIssue::Error(format!(
            "pattern {} regex has an excessive counted repetition bound ({} > {} limit)",
            index, stats.max_repeat_bound, MAX_REGEX_REPEAT_BOUND
        )));
    }

    if stats.has_nested_quantifier {
        issues.push(QualityIssue::Error(format!(
            "pattern {} regex contains nested quantifiers that can trigger pathological matching",
            index
        )));
    }

    if stats.has_quantified_overlapping_alternation {
        issues.push(QualityIssue::Error(format!(
            "pattern {} regex repeats overlapping alternations; use unambiguous branches instead",
            index
        )));
    }
}

#[derive(Default)]
struct RegexComplexityStats {
    nodes: usize,
    max_alternation_branches: usize,
    max_repeat_bound: u32,
    has_nested_quantifier: bool,
    has_quantified_overlapping_alternation: bool,
}

fn collect_regex_complexity(ast: &Ast, stats: &mut RegexComplexityStats) {
    stats.nodes += 1;
    match ast {
        Ast::Repetition(repetition) => {
            update_repeat_bound(&repetition.op.kind, stats);
            collect_regex_complexity(&repetition.ast, stats);
        }
        Ast::Group(group) => collect_regex_complexity(&group.ast, stats),
        Ast::Alternation(alternation) => {
            stats.max_alternation_branches =
                stats.max_alternation_branches.max(alternation.asts.len());
            for ast in &alternation.asts {
                collect_regex_complexity(ast, stats);
            }
        }
        Ast::Concat(concat) => {
            for ast in &concat.asts {
                collect_regex_complexity(ast, stats);
            }
        }
        Ast::Empty(_)
        | Ast::Flags(_)
        | Ast::Literal(_)
        | Ast::Dot(_)
        | Ast::Assertion(_)
        | Ast::ClassUnicode(_)
        | Ast::ClassPerl(_)
        | Ast::ClassBracketed(_) => {}
    }
}

fn collect_redos_risks(ast: &Ast, stats: &mut RegexComplexityStats, inside_repetition: bool) {
    match ast {
        Ast::Repetition(repetition) => {
            // Flag nested quantifiers only when they can cause exponential backtracking.
            //
            // SAFE patterns (char class quantifier inside group quantifier):
            //   (?:api[_\s.-]*)? — [_\s.-]* is atomic, can't overlap
            //   (?:key|token)[=:\s"']+  — char class quantifier, deterministic
            //
            // DANGEROUS patterns (group/concat quantifier inside quantifier):
            //   (a+)+       — classic ReDoS
            //   (\w+\s*)+   — overlapping quantifiers on non-atomic elements
            //
            // Strategy: only flag when THIS repetition wraps a non-atomic element
            // AND we're inside another repetition, OR when our inner AST itself
            // contains a nested repetition wrapping a non-atomic element.
            let this_is_simple_atom = matches!(
                &*repetition.ast,
                Ast::Literal(_)
                    | Ast::Dot(_)
                    | Ast::ClassBracketed(_)
                    | Ast::ClassPerl(_)
                    | Ast::ClassUnicode(_)
            );
            let this_is_unbounded = matches!(
                repetition.op.kind,
                ast::RepetitionKind::ZeroOrMore
                    | ast::RepetitionKind::OneOrMore
                    | ast::RepetitionKind::Range(ast::RepetitionRange::AtLeast { .. })
            );
            // Only flag when BOTH the outer and this repetition are unbounded
            // and this wraps a non-atomic element. (?:group)? is safe because
            // ? is {0,1} — it can't cause exponential backtracking.
            if inside_repetition && !this_is_simple_atom && this_is_unbounded {
                stats.has_nested_quantifier = true;
            }
            if !inside_repetition
                && this_is_unbounded
                && !this_is_simple_atom
                && ast_contains_repetition(&repetition.ast)
            {
                stats.has_nested_quantifier = true;
            }
            if alternation_has_overlapping_prefixes(&repetition.ast) {
                stats.has_quantified_overlapping_alternation = true;
            }
            // Only propagate inside_repetition when this is unbounded
            collect_redos_risks(
                &repetition.ast,
                stats,
                inside_repetition || this_is_unbounded,
            );
        }
        Ast::Group(group) => collect_redos_risks(&group.ast, stats, inside_repetition),
        Ast::Alternation(alternation) => {
            for ast in &alternation.asts {
                collect_redos_risks(ast, stats, inside_repetition);
            }
        }
        Ast::Concat(concat) => {
            for ast in &concat.asts {
                collect_redos_risks(ast, stats, inside_repetition);
            }
        }
        Ast::Empty(_)
        | Ast::Flags(_)
        | Ast::Literal(_)
        | Ast::Dot(_)
        | Ast::Assertion(_)
        | Ast::ClassUnicode(_)
        | Ast::ClassPerl(_)
        | Ast::ClassBracketed(_) => {}
    }
}

fn ast_contains_repetition(ast: &Ast) -> bool {
    match ast {
        Ast::Repetition(_) => true,
        Ast::Group(group) => ast_contains_repetition(&group.ast),
        Ast::Alternation(alternation) => alternation.asts.iter().any(ast_contains_repetition),
        Ast::Concat(concat) => concat.asts.iter().any(ast_contains_repetition),
        Ast::Empty(_)
        | Ast::Flags(_)
        | Ast::Literal(_)
        | Ast::Dot(_)
        | Ast::Assertion(_)
        | Ast::ClassUnicode(_)
        | Ast::ClassPerl(_)
        | Ast::ClassBracketed(_) => false,
    }
}

fn alternation_has_overlapping_prefixes(ast: &Ast) -> bool {
    let alternatives = match ast {
        Ast::Alternation(alternation) => &alternation.asts,
        Ast::Group(group) => return alternation_has_overlapping_prefixes(&group.ast),
        _ => return false,
    };

    let prefixes = alternatives
        .iter()
        .filter_map(literalish_prefix)
        .collect::<Vec<_>>();
    for (idx, prefix) in prefixes.iter().enumerate() {
        for other in prefixes.iter().skip(idx + 1) {
            if prefix.starts_with(other) || other.starts_with(prefix) {
                return true;
            }
        }
    }
    false
}

fn literalish_prefix(ast: &Ast) -> Option<String> {
    match ast {
        Ast::Literal(literal) => Some(literal.c.to_string()),
        Ast::Concat(concat) => {
            let mut prefix = String::new();
            for node in &concat.asts {
                match node {
                    Ast::Literal(literal) => prefix.push(literal.c),
                    Ast::Group(group) => prefix.push_str(&literalish_prefix(&group.ast)?),
                    _ => break,
                }
            }
            (!prefix.is_empty()).then_some(prefix)
        }
        Ast::Group(group) => literalish_prefix(&group.ast),
        _ => None,
    }
}

fn update_repeat_bound(kind: &ast::RepetitionKind, stats: &mut RegexComplexityStats) {
    let bound = match kind {
        ast::RepetitionKind::ZeroOrOne => 1,
        ast::RepetitionKind::ZeroOrMore | ast::RepetitionKind::OneOrMore => MAX_REGEX_REPEAT_BOUND,
        ast::RepetitionKind::Range(range) => match range {
            ast::RepetitionRange::Exactly(max)
            | ast::RepetitionRange::AtLeast(max)
            | ast::RepetitionRange::Bounded(_, max) => *max,
        },
    };
    stats.max_repeat_bound = stats.max_repeat_bound.max(bound);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Severity;

    fn detector_with_pattern(regex: &str) -> DetectorSpec {
        DetectorSpec {
            id: "test-detector".into(),
            name: "Test Detector".into(),
            service: "test".into(),
            severity: Severity::High,
            keywords: vec!["token".into()],
            patterns: vec![crate::PatternSpec {
                regex: regex.into(),
                description: None,
                group: None,
            }],
            verify: None,
            companion: None,
        }
    }

    #[test]
    fn rejects_excessive_alternation_fanout() {
        let regex = (0..65)
            .map(|i| format!("opt{i}"))
            .collect::<Vec<_>>()
            .join("|");
        let issues = validate_detector(&detector_with_pattern(&regex));

        assert!(issues.iter().any(|issue| matches!(
            issue,
            QualityIssue::Error(message) if message.contains("alternation branches")
        )));
    }

    #[test]
    fn rejects_excessive_counted_repetition() {
        let issues = validate_detector(&detector_with_pattern("token[a-z]{10001}"));

        assert!(issues.iter().any(|issue| matches!(
            issue,
            QualityIssue::Error(message) if message.contains("counted repetition bound")
        )));
    }

    #[test]
    fn rejects_nested_quantifiers() {
        let issues = validate_detector(&detector_with_pattern("(a+)+b"));

        assert!(issues.iter().any(|issue| matches!(
            issue,
            QualityIssue::Error(message) if message.contains("nested quantifiers")
        )));
    }

    #[test]
    fn rejects_quantified_overlapping_alternation() {
        let issues = validate_detector(&detector_with_pattern("(ab|a)+z"));

        assert!(issues.iter().any(|issue| matches!(
            issue,
            QualityIssue::Error(message) if message.contains("overlapping alternations")
        )));
    }
}
