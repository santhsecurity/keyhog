//! Machine-readable JSON reporters: JSON Lines for streams and pretty JSON arrays
//! for batch output.

use std::io::Write;

use crate::VerifiedFinding;

use super::{ReportError, Reporter};

/// One JSON object per line (JSONL).
pub struct JsonlReporter<W: Write> {
    writer: W,
}

impl<W: Write> JsonlReporter<W> {
    /// Create a JSON Lines reporter.
    pub fn new(writer: W) -> Self {
        Self { writer }
    }
}

impl<W: Write> Reporter for JsonlReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        serde_json::to_writer(&mut self.writer, finding)?;
        writeln!(self.writer)?;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        self.writer.flush()?;
        Ok(())
    }
}

/// Full JSON array output.
pub struct JsonReporter<W: Write> {
    writer: W,
    findings: Vec<VerifiedFinding>,
}

impl<W: Write> JsonReporter<W> {
    /// Create a JSON array reporter.
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            findings: Vec::new(),
        }
    }
}

impl<W: Write> Reporter for JsonReporter<W> {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
        self.findings.push(finding.clone());
        Ok(())
    }

    fn finish(&mut self) -> Result<(), ReportError> {
        serde_json::to_writer_pretty(&mut self.writer, &self.findings)?;
        writeln!(self.writer)?;
        Ok(())
    }
}
