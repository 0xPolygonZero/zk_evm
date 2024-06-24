//! Parsing utilities.
use std::{fmt::Display, ops::Add, ops::Range, str::FromStr};

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

/// Parse an exclusive range from a string.
///
/// A valid range is of the form `lhs..rhs`, where `lhs` and `rhs` are numbers.
pub(crate) fn parse_range_exclusive<NumberT>(
    s: &str,
) -> Result<Range<NumberT>, RangeParseError<NumberT>>
where
    NumberT: Display + FromStr + From<u8> + Add<Output = NumberT>,
    NumberT::Err: Display,
{
    parse_range_gen(s, "..", false)
}

/// Parse an inclusive range from a string.
///
/// A valid range is of the form `lhs..=rhs`, where `lhs` and `rhs` are numbers.
pub(crate) fn parse_range_inclusive<NumberT>(
    s: &str,
) -> Result<Range<NumberT>, RangeParseError<NumberT>>
where
    NumberT: Display + FromStr + From<u8> + Add<Output = NumberT>,
    NumberT::Err: Display,
{
    parse_range_gen(s, "..=", true)
}

pub(crate) fn parse_range_gen<NumberT, SeparatorT>(
    s: &str,
    separator: SeparatorT,
    inclusive: bool,
) -> Result<Range<NumberT>, RangeParseError<NumberT>>
where
    NumberT: Display + FromStr + From<u8> + Add<Output = NumberT>,
    NumberT::Err: Display,
    SeparatorT: AsRef<str>,
{
    let mut pairs = s.split(separator.as_ref());
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
            if inclusive {
                Ok(lhs..(rhs + NumberT::from(1u8)))
            } else {
                Ok(lhs..rhs)
            }
        }
        // (None, _) is not possible, because split always returns at least one element.
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn it_parses_exclusive_ranges() {
        assert_eq!(parse_range_exclusive::<usize>("0..10"), Ok(0..10));
    }

    #[test]
    fn it_parses_inclusive_ranges() {
        assert_eq!(parse_range_inclusive::<usize>("0..=10"), Ok(0..11));
    }

    #[test]
    fn it_handles_missing_lhs() {
        assert_eq!(
            parse_range_exclusive::<usize>("..10").unwrap_err(),
            RangeParseError::LhsMissing
        );
    }

    #[test]
    fn it_handles_missing_rhs() {
        assert_eq!(
            parse_range_exclusive::<usize>("10..").unwrap_err(),
            RangeParseError::RhsMissing
        );
    }

    #[test]
    fn it_handles_empty_input() {
        assert_eq!(
            parse_range_exclusive::<usize>("").unwrap_err(),
            RangeParseError::EmptyInput
        );
    }

    #[test]
    fn it_handles_rhs_parse_error() {
        assert_eq!(
            parse_range_exclusive::<usize>("10..f").unwrap_err(),
            RangeParseError::RhsParseError("f".parse::<usize>().unwrap_err())
        );
    }

    #[test]
    fn it_handles_lhs_parse_error() {
        assert_eq!(
            parse_range_exclusive::<usize>("hello..10").unwrap_err(),
            RangeParseError::LhsParseError("hello".parse::<usize>().unwrap_err())
        );
    }
}
