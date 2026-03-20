//! Human-readable terminal reporter with severity coloring and rich finding details.

use std::io::IsTerminal;
use std::io::Write;

use crate::{MatchLocation, Severity, VerificationResult, VerifiedFinding};

use super::{ReportError, Reporter};

/// Human-readable text output.
pub struct TextReporter<W: Write> {
    writer: W,
    count: usize,
    color: bool,
}

impl<W: Write> TextReporter<W> {
    /// Create a text reporter with ANSI colors enabled when stdout is a TTY.
    pub fn new(writer: W) -> Self {
        Self::with_color(writer, std::io::stdout().is_terminal())
    }

    /// Create a text reporter with explicit ANSI color control.
    pub fn with_color(writer: W, color: bool) -> Self {
        Self {
            writer,
            count: 0,
            color,
        }
    }

    fn print_header(&mut self) -> Result<(), ReportError> {
        let border = dim(
            "===============================================================",
            self.color,
        );
        writeln!(self.writer, "\n{}", border)?;
        writeln!(
            self.writer,
            "  {} {}",
            highlight("KEYHOG", self.color),
            colorize("Security Scan", "36", self.color)
        )?;
        writeln!(self.writer, "{}\n", border)?;
        Ok(())
    }
}

impl<W: Write> Reporter for TextReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        if self.count == 0 {
            self.print_header()?;
        }
        self.count += 1;

        let severity = format_severity(finding.severity, self.color);
        let verified = format_verification(&finding.verification, self.color);
        let location = format_location(&finding.location);
        let confidence = format_confidence(finding.confidence.unwrap_or(0.0), self.color);

        let title_color = match finding.severity {
            Severity::Critical => "1;31",
            Severity::High => "31",
            Severity::Medium => "33",
            Severity::Low => "36",
            Severity::Info => "37",
        };

        writeln!(
            self.writer,
            "{} {}",
            colorize("■", title_color, self.color),
            highlight(&finding.detector_name, self.color),
        )?;

        writeln!(
            self.writer,
            "  {} │ {} {} {}",
            dim("Severity:", self.color),
            severity,
            confidence,
            if verified.is_empty() {
                String::new()
            } else {
                format!("({})", verified)
            }
        )?;

        writeln!(
            self.writer,
            "  {} │ {}",
            dim("Secret:  ", self.color),
            highlight(&finding.credential_redacted, self.color)
        )?;

        writeln!(
            self.writer,
            "  {} │ {}",
            dim("Location:", self.color),
            location
        )?;

        if let Some(commit) = &finding.location.commit {
            writeln!(
                self.writer,
                "  {} │ {}",
                dim("Commit:  ", self.color),
                commit
            )?;
        }

        if let Some(author) = &finding.location.author {
            writeln!(
                self.writer,
                "  {} │ {}",
                dim("Author:  ", self.color),
                author
            )?;
        }

        if let Some(date) = &finding.location.date {
            writeln!(self.writer, "  {} │ {}", dim("Date:    ", self.color), date)?;
        }

        for (key, value) in &finding.metadata {
            writeln!(
                self.writer,
                "  {} │ {}",
                dim(&format!("{:<9}", format!("{}:", key)), self.color),
                value
            )?;
        }

        if !finding.additional_locations.is_empty() {
            writeln!(
                self.writer,
                "  {} │ (+{} more locations)",
                dim("Extra:   ", self.color),
                finding.additional_locations.len()
            )?;
        }

        // Remediation hint
        let remediation = match finding.severity {
            Severity::Critical | Severity::High => "Revoke immediately and rotate.",
            Severity::Medium => "Review usage and rotate if active.",
            _ => "Remove from codebase.",
        };
        writeln!(
            self.writer,
            "  {} │ {}",
            dim("Action:  ", self.color),
            colorize(remediation, "3;32", self.color)
        )?;

        writeln!(self.writer)?;

        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        let border = dim(
            "===============================================================",
            self.color,
        );
        if self.count == 0 {
            self.print_header()?;
            writeln!(
                self.writer,
                "  {}\n",
                colorize(
                    "🎉 No secrets found! Your code is clean.",
                    "1;32",
                    self.color
                )
            )?;
        } else {
            writeln!(self.writer, "{}", border)?;
            writeln!(
                self.writer,
                "  {}\n",
                highlight(
                    &format!(
                        "⚠️  Found {} secret{}.",
                        self.count,
                        if self.count == 1 { "" } else { "s" }
                    ),
                    self.color
                ),
            )?;
            writeln!(
                self.writer,
                "  {}",
                highlight("Actionable Next Steps:", self.color)
            )?;
            writeln!(
                self.writer,
                "    1. {} Revoke the active secrets immediately in the provider's dashboard.",
                colorize("Revoke:", "1;31", self.color)
            )?;
            writeln!(
                self.writer,
                "    2. {} Remove the credentials from your codebase and git history.",
                colorize("Clean:", "1;33", self.color)
            )?;
            writeln!(
                self.writer,
                "    3. {} Use a secure secret manager or environment variables instead.\n",
                colorize("Secure:", "1;32", self.color)
            )?;
        }
        Ok(())
    }
}

fn format_severity(severity: Severity, color: bool) -> String {
    let style = match severity {
        Severity::Critical => "1;31",
        Severity::High => "31",
        Severity::Medium => "33",
        Severity::Low => "36",
        Severity::Info => "37",
    };
    colorize(&format!("{:>8}", severity.to_string()), style, color)
}

fn format_verification(result: &VerificationResult, color: bool) -> String {
    match result {
        VerificationResult::Live => colorize("LIVE", "1;31;43", color), // bold red on yellow background
        VerificationResult::Dead => colorize("dead", "32", color),
        VerificationResult::RateLimited => colorize("limited", "33", color),
        VerificationResult::Error(_) => colorize("error", "33", color),
        VerificationResult::Unverifiable | VerificationResult::Skipped => String::new(),
    }
}

fn format_location(location: &MatchLocation) -> String {
    match (&location.file_path, location.line) {
        (Some(path), Some(line)) => format!("{}:{}", path, line),
        (Some(path), None) => path.clone(),
        _ => location.source.clone(),
    }
}

fn format_confidence(confidence: f64, color: bool) -> String {
    const CONFIDENCE_BAR_WIDTH: usize = 6;
    let filled = (confidence * CONFIDENCE_BAR_WIDTH as f64) as usize;
    let bar = format!(
        "{}{}",
        "■".repeat(filled.min(CONFIDENCE_BAR_WIDTH)),
        "□".repeat(CONFIDENCE_BAR_WIDTH.saturating_sub(filled.min(CONFIDENCE_BAR_WIDTH)))
    );
    let tone = if confidence >= 0.8 {
        "31"
    } else if confidence >= 0.5 {
        "33"
    } else {
        "90"
    };
    format!(
        "{} {}",
        colorize(&bar, tone, color),
        colorize(&format!("{:>3}%", (confidence * 100.0) as u32), "90", color)
    )
}

fn highlight(text: &str, color: bool) -> String {
    colorize(text, "1", color) // Bold
}

fn dim(text: &str, color: bool) -> String {
    colorize(text, "90", color) // Gray
}

fn colorize(text: &str, ansi: &str, color: bool) -> String {
    if color {
        format!("\x1b[{ansi}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}
