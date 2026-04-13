//! Reporting logic for scan results.

mod json;
mod sarif;
mod text;

pub mod banner;

use std::io::Write;

use crate::VerifiedFinding;

pub use json::{JsonArrayReporter, JsonReporter, JsonlReporter};
pub use sarif::SarifReporter;
pub use text::TextReporter;

/// Common error type used by all reporters.
pub type ReportError = anyhow::Error;

/// Common trait for all finding reporters.
pub trait Reporter: Send {
    /// Report a single finding.
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError>;

    /// Finalize the report and flush buffered bytes.
    fn finish(&mut self) -> Result<(), ReportError>;
}

trait WriterBackedReporter {
    type Writer: Write;

    fn writer_mut(&mut self) -> &mut Self::Writer;

    fn flush_writer(&mut self) -> Result<(), ReportError> {
        self.writer_mut().flush()?;
        Ok(())
    }
}

trait BufferedFindingReporter {
    fn findings_mut(&mut self) -> &mut Vec<VerifiedFinding>;

    fn push_finding(&mut self, finding: &VerifiedFinding) {
        self.findings_mut().push(finding.clone());
    }
}
