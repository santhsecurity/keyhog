use super::*;

impl CompiledScanner {
    #[allow(clippy::too_many_arguments, dead_code)]
    pub(crate) fn scan_fallback_patterns(
        &self,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
    ) {
        if let Some(deadline) = deadline
            && std::time::Instant::now() >= deadline
        {
            return;
        }

        if preprocessed.text.len() > LARGE_FALLBACK_SCAN_THRESHOLD && !self.fallback.is_empty() {
            self.scan_large_fallback_patterns(
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
                deadline,
            );
            return;
        }
        let active_patterns = self.active_fallback_patterns(&chunk.data);

        for (index, (entry, _keywords)) in self.fallback.iter().enumerate() {
            if !active_patterns[index] {
                continue;
            }
            if let Some(deadline) = deadline
                && index % 16 == 0
                && std::time::Instant::now() >= deadline
            {
                break;
            }
            self.extract_matches(
                entry,
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
                0,
                0,
            );
        }
    }

    #[allow(dead_code)]
    fn active_fallback_patterns(&self, data: &str) -> Vec<bool> {
        if let Some(keyword_ac) = &self.fallback_keyword_ac {
            let mut active = vec![false; self.fallback.len()];
            for (index, (_pattern, keywords)) in self.fallback.iter().enumerate() {
                if !keywords.iter().any(|keyword| keyword.len() >= 4) {
                    active[index] = true;
                }
            }
            for mat in keyword_ac.find_iter(data) {
                let keyword_idx = mat.pattern().as_usize();
                if keyword_idx < self.fallback_keyword_to_patterns.len() {
                    for &pattern_idx in &self.fallback_keyword_to_patterns[keyword_idx] {
                        if pattern_idx < active.len() {
                            active[pattern_idx] = true;
                        }
                    }
                }
            }
            active
        } else {
            vec![true; self.fallback.len()]
        }
    }

    #[allow(clippy::too_many_arguments, dead_code)]
    fn scan_large_fallback_patterns(
        &self,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        scan_state: &mut ScanState,
        deadline: Option<std::time::Instant>,
    ) {
        let active_set = self.active_fallback_patterns(&chunk.data);
        let active_fallback: Vec<&CompiledPattern> = self
            .fallback
            .iter()
            .enumerate()
            .filter(|(index, _)| active_set[*index])
            .map(|(_, (entry, _))| entry)
            .collect();

        if active_fallback.is_empty() {
            return;
        }

        for (index, entry) in active_fallback.iter().enumerate() {
            if let Some(deadline) = deadline
                && index % 16 == 0
                && std::time::Instant::now() >= deadline
            {
                break;
            }
            self.extract_matches(
                entry,
                preprocessed,
                line_offsets,
                code_lines,
                documentation_lines,
                chunk,
                scan_state,
                0,
                0,
            );
        }
    }

    #[cfg(feature = "entropy")]
    pub(crate) fn scan_entropy_fallback(
        &self,
        preprocessed: &ScannerPreprocessedText,
        line_offsets: &[usize],
        chunk: &Chunk,
        scan_state: &mut ScanState,
    ) {
        if !self.config.entropy_enabled {
            return;
        }
        if !crate::entropy::is_entropy_appropriate(
            chunk.metadata.path.as_deref(),
            self.config.entropy_in_source_files,
        ) {
            return;
        }

        // Skip entropy scanning on lines that already have named detector matches.
        let mut skip_lines = std::collections::HashSet::new();
        for m in &scan_state.matches {
            let id = &*m.0.detector_id;
            if !id.starts_with("generic-")
                && !id.starts_with("entropy-")
                && let Some(line) = m.0.location.line
            {
                skip_lines.insert(line);
            }
        }

        let keyword_free_threshold =
            if crate::entropy::is_sensitive_file(chunk.metadata.path.as_deref()) {
                crate::entropy::SENSITIVE_FILE_VERY_HIGH_ENTROPY_THRESHOLD
            } else {
                crate::entropy::VERY_HIGH_ENTROPY_THRESHOLD
            };

        let entropy_matches = crate::entropy::find_entropy_secrets_with_threshold(
            &preprocessed.text,
            16,
            1,
            self.config.entropy_threshold,
            keyword_free_threshold,
            &self.config.secret_keywords,
            &self.config.test_keywords,
            &self.config.placeholder_keywords,
            Some(&skip_lines),
        );

        for entropy_match in entropy_matches {
            let (detector_id_value, detector_name_value, service_value) =
                classify_entropy_detector(&entropy_match.keyword);
            let base_confidence =
                if entropy_match.entropy >= crate::entropy::VERY_HIGH_ENTROPY_THRESHOLD {
                    0.75
                } else if entropy_match.entropy >= crate::entropy::HIGH_ENTROPY_THRESHOLD {
                    0.65
                } else {
                    0.55_f64.min(entropy_match.entropy / 8.0)
                };
            let confidence = if entropy_match.keyword != "none (high-entropy)" {
                (base_confidence + 0.1).min(0.90_f64)
            } else {
                base_confidence
            };
            let offset = if entropy_match.line > 0 && entropy_match.line <= line_offsets.len() {
                line_offsets[entropy_match.line - 1] + entropy_match.offset
            } else {
                entropy_match.offset
            };

            let detector_id = scan_state.intern_metadata(detector_id_value);
            let detector_name = scan_state.intern_metadata(detector_name_value);
            let service = scan_state.intern_metadata(service_value);
            let credential = scan_state.intern_credential(&entropy_match.value);
            let source = scan_state.intern_metadata(&chunk.metadata.source_type);
            let file_path = chunk
                .metadata
                .path
                .as_ref()
                .map(|path| scan_state.intern_metadata(path));
            let commit = chunk
                .metadata
                .commit
                .as_ref()
                .map(|commit| scan_state.intern_metadata(commit));
            let author = chunk
                .metadata
                .author
                .as_ref()
                .map(|author| scan_state.intern_metadata(author));
            let date = chunk
                .metadata
                .date
                .as_ref()
                .map(|date| scan_state.intern_metadata(date));

            scan_state.push_match(
                RawMatch {
                    credential_hash: crate::sha256_hash(&entropy_match.value),
                    detector_id,
                    detector_name,
                    service,
                    severity: keyhog_core::Severity::High,
                    credential,
                    companions: HashMap::new(),
                    location: MatchLocation {
                        source,
                        file_path,
                        line: Some(entropy_match.line),
                        offset,
                        commit,
                        author,
                        date,
                    },
                    entropy: Some(entropy_match.entropy),
                    confidence: Some(confidence),
                },
                self.config.max_matches_per_chunk,
            );
        }
    }

    pub(crate) fn match_companions(
        &self,
        entry: &CompiledPattern,
        preprocessed: &ScannerPreprocessedText,
        line: usize,
    ) -> Option<HashMap<String, String>> {
        let mut results = HashMap::new();
        if let Some(detector_companions) = self.companions.get(entry.detector_index) {
            for companion in detector_companions {
                if let Some(val) = find_companion(preprocessed, line, companion) {
                    results.insert(companion.name.clone(), val);
                } else if companion.required {
                    return None;
                }
            }
        }
        Some(results)
    }

    pub(crate) fn match_confidence(
        &self,
        entry: &CompiledPattern,
        detector: &DetectorSpec,
        code_lines: &[&str],
        documentation_lines: &[bool],
        chunk: &Chunk,
        credential: &str,
        data: &str,
        line: usize,
        entropy: f64,
        has_companion: bool,
        scan_state: &mut ScanState,
    ) -> Option<MlScoreResult> {
        let raw_conf =
            crate::confidence::compute_confidence(&crate::confidence::ConfidenceSignals {
                has_literal_prefix: extract_literal_prefix(entry.regex.as_str()).is_some(),
                has_context_anchor: entry.group.is_some(),
                entropy,
                keyword_nearby: detector
                    .keywords
                    .iter()
                    .any(|keyword| chunk.data.contains(keyword.as_str())),
                sensitive_file: chunk
                    .metadata
                    .path
                    .as_deref()
                    .map(crate::confidence::is_sensitive_path)
                    .unwrap_or(false),
                match_length: credential.len(),
                has_companion,
            });

        // Checksum validation is handled in process_match (early reject for Invalid,
        // confidence floor for Valid). No need to re-validate here.

        let context = context::infer_context_with_documentation(
            code_lines,
            line.saturating_sub(PREVIOUS_LINE_DISTANCE),
            chunk.metadata.path.as_deref(),
            documentation_lines,
        );
        let heuristic_conf = raw_conf * context.confidence_multiplier();
        let score_result = self.calculate_final_score(
            heuristic_conf,
            context,
            credential,
            data,
            line,
            chunk,
            scan_state,
        )?;

        match score_result {
            MlScoreResult::Final(confidence) => {
                let final_score = if let Some(floor) =
                    crate::confidence::known_prefix_confidence_floor(credential)
                {
                    confidence.max(floor)
                } else {
                    confidence
                };

                if context.should_hard_suppress(final_score) {
                    None
                } else {
                    Some(MlScoreResult::Final(final_score))
                }
            }
            #[cfg(feature = "ml")]
            MlScoreResult::Pending { .. } => Some(score_result),
        }
    }

    fn calculate_final_score(
        &self,
        heuristic_conf: f64,
        context: CodeContext,
        credential: &str,
        data: &str,
        line: usize,
        chunk: &Chunk,
        _scan_state: &mut ScanState,
    ) -> Option<MlScoreResult> {
        #[cfg(not(feature = "ml"))]
        {
            let _ = (context, credential, data, line, chunk);
            Some(MlScoreResult::Final(heuristic_conf))
        }

        #[cfg(feature = "ml")]
        {
            if !crate::probabilistic_gate::ProbabilisticGate::looks_promising(credential) {
                return Some(MlScoreResult::Final(0.1));
            }

            let text_context = local_context_window(data, line, ML_CONTEXT_RADIUS_LINES);
            let ml_context = match chunk.metadata.path.as_deref() {
                Some(path) => format!("file:{path}\n{text_context}"),
                None => text_context,
            };

            Some(MlScoreResult::Pending {
                heuristic_conf,
                code_context: context,
                credential: credential.to_string(),
                ml_context,
            })
        }
    }
}

impl CompiledScanner {
    /// Scan for generic `SECRET_NAME = "high_entropy_value"` patterns.
    /// This is the precision-gated equivalent of Gitleaks's `generic-api-key`.
    /// Only fires when:
    ///   1. The variable name contains a secret-related keyword
    ///   2. The value has entropy >= 3.5 (random-looking)
    ///   3. No named detector already matched the same line
    ///   4. The value is not a known placeholder/example
    pub(crate) fn scan_generic_assignments(
        &self,
        code_lines: &[&str],
        chunk: &Chunk,
        scan_state: &mut ScanState,
    ) {
        use std::sync::LazyLock;
        static GENERIC_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(
                r#"(?i)(?:secret|password|passwd|pwd|token|api[_-]?key|apikey|auth[_-]?token|auth[_-]?key|credential|private[_-]?key|signing[_-]?key|encryption[_-]?key|access[_-]?key|client[_-]?secret|app[_-]?secret|master[_-]?key|license[_-]?key)\s*[=:]\s*["'`]?([a-zA-Z0-9/+=_.!@#$%^&*-]{8,128})["'`]?"#
            ).expect("hardcoded generic regex")
        });

        let covered_lines: std::collections::HashSet<usize> = {
            let lines: Vec<usize> = scan_state
                .matches
                .iter()
                .filter_map(|m| m.0.location.line)
                .collect();
            lines.into_iter().collect()
        };

        for (line_idx, line) in code_lines.iter().enumerate() {
            let line_num = line_idx + 1;
            if covered_lines.contains(&line_num) {
                continue;
            }

            for caps in GENERIC_RE.captures_iter(line) {
                let Some(value_match) = caps.get(1) else {
                    continue;
                };
                let value = value_match.as_str();

                // Entropy gate: reject low-entropy values (variable names, prose)
                let entropy = crate::pipeline::match_entropy(value.as_bytes());
                // Per-length entropy floor: short tokens (API keys) have lower
                // entropy than long random strings. A blanket 3.5 misses them.
                let min_entropy = if value.len() <= 24 { 2.8 } else if value.len() <= 40 { 3.2 } else { 3.5 };
                if entropy < min_entropy {
                    continue;
                }

                // Length gate
                if value.len() < 8 {
                    continue;
                }

                // Variable-name filter: real secrets have mixed character classes.
                // Reject if the value looks like a code expression (has parens,
                // brackets, dots, or is pure snake_case/camelCase).
                if value.contains('(')
                    || value.contains('[')
                    || value.contains('{')
                    || value.contains(' ')
                {
                    continue;
                }
                // Allow dots ONLY in JWT-like patterns (exactly 2 dots separating
                // base64 segments). Reject other dotted values (method chains, FQDNs).
                if value.contains('.') {
                    let dot_count = value.chars().filter(|&c| c == '.').count();
                    let segments: Vec<&str> = value.split('.').collect();
                    let is_jwt_like = dot_count == 2
                        && segments.len() == 3
                        && segments.iter().all(|s| s.len() >= 4 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '-' || c == '_'));
                    if !is_jwt_like {
                        continue;
                    }
                }
                // Reject pure identifiers: only alphanumeric + underscore
                if value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    // Must have at least one digit AND one letter to not be a variable name
                    let has_digit = value.chars().any(|c| c.is_ascii_digit());
                    let has_upper = value.chars().any(|c| c.is_ascii_uppercase());
                    let has_lower = value.chars().any(|c| c.is_ascii_lowercase());
                    if !(has_digit && (has_upper || has_lower)) {
                        continue;
                    }
                }

                // Placeholder suppression
                if crate::pipeline::should_suppress_known_example_credential(
                    value,
                    chunk.metadata.path.as_deref(),
                    crate::context::CodeContext::Unknown,
                ) {
                    continue;
                }

                // Context suppression: test files get lower confidence
                let context = crate::context::infer_context(
                    code_lines,
                    line_idx,
                    chunk.metadata.path.as_deref(),
                );
                let base_conf = match context {
                    crate::context::CodeContext::TestCode => 0.25,
                    crate::context::CodeContext::Comment
                    | crate::context::CodeContext::Documentation => 0.30,
                    _ => 0.60,
                };

                // Boost confidence for longer, higher-entropy values
                let entropy_boost = ((entropy - 3.5) * 0.1).min(0.25);
                let length_boost = ((value.len() as f64 - 16.0) * 0.005).clamp(0.0, 0.15);
                let confidence = (base_conf + entropy_boost + length_boost).min(0.95);

                if confidence < self.config.min_confidence {
                    continue;
                }

                let raw = keyhog_core::RawMatch {
                    credential_hash: crate::sha256_hash(value),
                    detector_id: Arc::from("generic-secret"),
                    detector_name: Arc::from("Generic Secret (Key=Value)"),
                    service: Arc::from("generic"),
                    severity: keyhog_core::Severity::Medium,
                    credential: Arc::from(value),
                    companions: HashMap::new(),
                    location: keyhog_core::MatchLocation {
                        source: Arc::from(chunk.metadata.source_type.as_str()),
                        file_path: chunk.metadata.path.as_deref().map(Arc::from),
                        line: Some(line_num),
                        offset: 0,
                        commit: chunk.metadata.commit.as_deref().map(Arc::from),
                        author: chunk.metadata.author.as_deref().map(Arc::from),
                        date: chunk.metadata.date.as_deref().map(Arc::from),
                    },
                    entropy: Some(entropy),
                    confidence: Some(confidence),
                };
                scan_state.push_match(raw, self.config.max_matches_per_chunk);
            }
        }
    }
}

#[cfg(feature = "entropy")]
fn classify_entropy_detector(keyword: &str) -> (&'static str, &'static str, &'static str) {
    if keyword == "none (high-entropy)" {
        ("entropy-generic", "Generic High-Entropy Secret", "generic")
    } else if keyword.contains("password") || keyword.contains("pwd") {
        ("entropy-password", "Password (Entropy Detected)", "generic")
    } else if keyword.contains("token") {
        ("entropy-token", "API Token (Entropy Detected)", "generic")
    } else {
        ("entropy-api-key", "API Key (Entropy Detected)", "generic")
    }
}
