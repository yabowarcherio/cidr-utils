//! Error type for parsing CIDR blocks and address ranges.

use std::fmt;

/// An error produced while parsing a CIDR block, address range, or IP address.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// The input was empty or contained only whitespace.
    Empty,
    /// The IP address portion could not be parsed.
    BadAddr(String),
    /// The prefix length was missing, non-numeric, or out of range for the
    /// address family (0..=32 for IPv4, 0..=128 for IPv6).
    BadPrefix(String),
    /// A range's `start` and `end` are different address families
    /// (e.g. an IPv4 start with an IPv6 end).
    MixedFamilies,
    /// A range's `start` address sorts after its `end` address.
    StartAfterEnd,
    /// The input did not look like a CIDR block or a range, or had stray parts.
    Malformed(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Empty => write!(f, "empty input"),
            ParseError::BadAddr(s) => write!(f, "invalid IP address: {s:?}"),
            ParseError::BadPrefix(s) => write!(f, "invalid prefix length: {s:?}"),
            ParseError::MixedFamilies => {
                write!(f, "range mixes IPv4 and IPv6 addresses")
            }
            ParseError::StartAfterEnd => {
                write!(f, "range start is greater than range end")
            }
            ParseError::Malformed(s) => write!(f, "malformed input: {s:?}"),
        }
    }
}

impl std::error::Error for ParseError {}
