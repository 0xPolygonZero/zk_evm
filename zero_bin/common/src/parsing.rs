//! Parsing utilities.
use std::{fmt::Display, ops::Range, str::FromStr};

use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum RangeParseError<T>
where
    T: FromStr + Display,
    T::Err: Display,
{
    #[error("empty input")]
    EmptyInput,
    #[error("failed to parse right hand side of range: {0}")]
    RhsParseError(T::Err),
    #[error("failed to parse left hand side of range: {0}. ")]
    LhsParseError(T::Err),
    #[error("missing left hand size of range. expecting `start..end`")]
    LhsMissing,
    #[error("missing right hand side of range. expecting `start..end`")]
    RhsMissing,
}

/// Parse a range from a string.
///
/// A valid range is of the form `lhs..rhs`, where `lhs` and `rhs` are numbers.
///
/// # Example
///
/// ```rust
/// # use common::parsing::parse_range;
/// assert_eq!(parse_range::<usize>("0..10"), Ok(0..10));
/// ```
pub fn parse_range<T>(s: &str) -> Result<Range<T>, RangeParseError<T>>
where
    T: Display + FromStr,
    T::Err: Display,
{
    let mut pairs = s.split("..");
    match (pairs.next(), pairs.next()) {
        // Empty input, ""
        (Some(""), None) => Err(RangeParseError::EmptyInput),
        // RHS missing, e.g., "10.." or "10"
        (Some(_), None | Some("")) => Err(RangeParseError::RhsMissing),
        // LHS missing, e.g., "..10"
        (Some(""), _) => Err(RangeParseError::LhsMissing),
        (Some(lhs), Some(rhs)) => {
            let lhs = lhs.parse().map_err(RangeParseError::LhsParseError)?;
            let rhs = rhs.parse().map_err(RangeParseError::RhsParseError)?;
            Ok(lhs..rhs)
        }
        // (None, _) is not possible, because split always returns at least one element.
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_parses_ranges() {
        assert_eq!(parse_range::<usize>("0..10"), Ok(0..10));
    }

    #[test]
    fn it_handles_missing_lhs() {
        assert_eq!(
            parse_range::<usize>("..10").unwrap_err(),
            RangeParseError::LhsMissing
        );
    }

    #[test]
    fn it_handles_missing_rhs() {
        assert_eq!(
            parse_range::<usize>("10..").unwrap_err(),
            RangeParseError::RhsMissing
        );
    }

    #[test]
    fn it_handles_empty_input() {
        assert_eq!(
            parse_range::<usize>("").unwrap_err(),
            RangeParseError::EmptyInput
        );
    }

    #[test]
    fn it_handles_rhs_parse_error() {
        assert_eq!(
            parse_range::<usize>("10..f").unwrap_err(),
            RangeParseError::RhsParseError("f".parse::<usize>().unwrap_err())
        );
    }

    #[test]
    fn it_handles_lhs_parse_error() {
        assert_eq!(
            parse_range::<usize>("hello..10").unwrap_err(),
            RangeParseError::LhsParseError("hello".parse::<usize>().unwrap_err())
        );
    }
}
