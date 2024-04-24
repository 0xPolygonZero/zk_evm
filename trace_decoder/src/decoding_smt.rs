use thiserror::Error;

/// Stores the result of parsing tries. Returns a [TraceParsingError] upon
/// failure.
pub type SmtTraceParsingResult<T> = Result<T, SmtTraceParsingError>;

/// Error from parsing an SMT trie.
#[derive(Clone, Debug, Error)]
pub enum SmtTraceParsingError {}
