//! [`IpSet`] — a single scan target parsed from a string, be it a CIDR block,
//! an address range, or a lone IP. This is the high-level entry point most
//! callers (including host scanners) want.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::cidr::{IpCidr, Ipv4AddrIter, Ipv4Cidr, Ipv6AddrIter, Ipv6Cidr};
use crate::error::ParseError;
use crate::range::IpRange;

/// Collapse a mixed list of IPv4 and IPv6 blocks into the minimal equivalent
/// set, aggregating each family independently. IPv4 blocks are returned before
/// IPv6 blocks, each group sorted and non-overlapping.
pub fn aggregate(cidrs: &[IpCidr]) -> Vec<IpCidr> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for c in cidrs {
        match c {
            IpCidr::V4(c) => v4.push(*c),
            IpCidr::V6(c) => v6.push(*c),
        }
    }
    let mut out: Vec<IpCidr> = Ipv4Cidr::aggregate(&v4)
        .into_iter()
        .map(IpCidr::V4)
        .collect();
    out.extend(Ipv6Cidr::aggregate(&v6).into_iter().map(IpCidr::V6));
    out
}

/// A contiguous set of addresses described by one target string.
///
/// Accepts three textual forms via [`FromStr`]:
///
/// - CIDR — `192.168.1.0/24`, `2001:db8::/32`
/// - range — `192.168.1.1-192.168.1.50`, `192.168.1.1-50`
/// - single — `10.0.0.5` (treated as a `/32`, or `/128` for IPv6)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IpSet {
    /// A CIDR block.
    Cidr(IpCidr),
    /// An inclusive address range.
    Range(IpRange),
}

impl IpSet {
    /// The number of addresses described by this target.
    pub fn count(&self) -> u128 {
        match self {
            IpSet::Cidr(c) => c.address_count(),
            IpSet::Range(r) => r.count(),
        }
    }

    /// `true` if the target describes exactly one address.
    pub fn is_single(&self) -> bool {
        self.count() == 1
    }

    /// `true` if the target was written as a CIDR block (or a bare address).
    pub fn is_cidr(&self) -> bool {
        matches!(self, IpSet::Cidr(_))
    }

    /// `true` if the target was written as an address range.
    pub fn is_range(&self) -> bool {
        matches!(self, IpSet::Range(_))
    }

    /// The underlying [`IpCidr`], or `None` if the target is a range.
    pub fn as_cidr(&self) -> Option<IpCidr> {
        match self {
            IpSet::Cidr(c) => Some(*c),
            IpSet::Range(_) => None,
        }
    }

    /// The underlying [`IpRange`], or `None` if the target is a CIDR block.
    pub fn as_range(&self) -> Option<IpRange> {
        match self {
            IpSet::Range(r) => Some(*r),
            IpSet::Cidr(_) => None,
        }
    }

    /// The lowest address in the target.
    pub fn first(&self) -> IpAddr {
        match self {
            IpSet::Cidr(c) => c.network(),
            IpSet::Range(r) => r.start(),
        }
    }

    /// The highest address in the target.
    pub fn last(&self) -> IpAddr {
        match self {
            IpSet::Cidr(c) => c.last_address(),
            IpSet::Range(r) => r.end(),
        }
    }

    /// Returns `true` if `addr` belongs to this target.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match self {
            IpSet::Cidr(c) => c.contains(addr),
            IpSet::Range(r) => r.contains(addr),
        }
    }

    /// The target as a set of aligned CIDR blocks.
    ///
    /// A CIDR target yields itself; a range is decomposed into the minimal set
    /// of blocks that exactly cover it.
    pub fn to_cidrs(&self) -> Vec<IpCidr> {
        match self {
            IpSet::Cidr(c) => vec![*c],
            IpSet::Range(r) => r.to_cidrs(),
        }
    }

    /// Iterate over every address in the target, lowest to highest.
    ///
    /// For a CIDR block this includes the network and broadcast addresses; use
    /// [`hosts`](Self::hosts) to skip them under IPv4 conventions.
    pub fn addresses(&self) -> IpSetIter {
        match self {
            IpSet::Cidr(IpCidr::V4(c)) => IpSetIter::V4(c.addresses()),
            IpSet::Cidr(IpCidr::V6(c)) => IpSetIter::V6(c.addresses()),
            IpSet::Range(IpRange::V4(r)) => IpSetIter::V4(r.iter()),
            IpSet::Range(IpRange::V6(r)) => IpSetIter::V6(r.iter()),
        }
    }

    /// Iterate over the *host* addresses in the target.
    ///
    /// Identical to [`addresses`](Self::addresses) except for IPv4 CIDR blocks,
    /// where the network and broadcast addresses are excluded (`/31` and `/32`
    /// still yield every address).
    pub fn hosts(&self) -> IpSetIter {
        match self {
            IpSet::Cidr(IpCidr::V4(c)) => IpSetIter::V4(c.hosts()),
            other => other.addresses(),
        }
    }
}

impl fmt::Display for IpSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpSet::Cidr(c) => c.fmt(f),
            IpSet::Range(r) => r.fmt(f),
        }
    }
}

impl FromStr for IpSet {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        let t = s.trim();
        if t.is_empty() {
            return Err(ParseError::Empty);
        }
        if t.contains('/') {
            return IpCidr::from_str(t).map(IpSet::Cidr);
        }
        if t.contains('-') {
            return IpRange::from_str(t).map(IpSet::Range);
        }
        // Bare address → a single-host CIDR (/32 or /128).
        let addr = IpAddr::from_str(t).map_err(|_| ParseError::BadAddr(t.to_string()))?;
        let prefix = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        IpCidr::new(addr, prefix).map(IpSet::Cidr)
    }
}

impl From<IpCidr> for IpSet {
    fn from(c: IpCidr) -> Self {
        IpSet::Cidr(c)
    }
}

impl From<IpRange> for IpSet {
    fn from(r: IpRange) -> Self {
        IpSet::Range(r)
    }
}

/// Iterator over the addresses of an [`IpSet`], yielding [`IpAddr`].
#[derive(Debug, Clone)]
pub enum IpSetIter {
    /// IPv4 address iteration.
    V4(Ipv4AddrIter),
    /// IPv6 address iteration.
    V6(Ipv6AddrIter),
}

impl Iterator for IpSetIter {
    type Item = IpAddr;

    fn next(&mut self) -> Option<IpAddr> {
        match self {
            IpSetIter::V4(it) => it.next().map(IpAddr::V4),
            IpSetIter::V6(it) => it.next().map(IpAddr::V6),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            IpSetIter::V4(it) => it.size_hint(),
            IpSetIter::V6(it) => it.size_hint(),
        }
    }
}

impl DoubleEndedIterator for IpSetIter {
    fn next_back(&mut self) -> Option<IpAddr> {
        match self {
            IpSetIter::V4(it) => it.next_back().map(IpAddr::V4),
            IpSetIter::V6(it) => it.next_back().map(IpAddr::V6),
        }
    }
}
