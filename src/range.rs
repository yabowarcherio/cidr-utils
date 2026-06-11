//! Inclusive address ranges for IPv4 and IPv6, plus the family-agnostic
//! [`IpRange`].
//!
//! A range is a contiguous, inclusive span `start..=end`. Unlike a CIDR block
//! it need not align to a power-of-two boundary, so `192.168.1.10-192.168.1.20`
//! is expressible as a range but not as a single block.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::cidr::{IpCidr, Ipv4AddrIter, Ipv4Cidr, Ipv6AddrIter, Ipv6Cidr};
use crate::error::ParseError;
use crate::set::IpSetIter;

macro_rules! define_range {
    ($name:ident, $iter:ident, $addr:ty, $uint:ty) => {
        /// An inclusive range of addresses, `start..=end`.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name {
            start: $uint,
            end: $uint,
        }

        impl $name {
            /// Build a range from its inclusive endpoints.
            ///
            /// # Errors
            ///
            /// Returns [`ParseError::StartAfterEnd`] if `start` sorts after
            /// `end`.
            pub fn new(start: $addr, end: $addr) -> Result<Self, ParseError> {
                let (start, end) = (start.to_bits(), end.to_bits());
                if start > end {
                    return Err(ParseError::StartAfterEnd);
                }
                Ok(Self { start, end })
            }

            /// The first (lowest) address in the range.
            #[inline]
            pub fn start(&self) -> $addr {
                <$addr>::from_bits(self.start)
            }

            /// The last (highest) address in the range.
            #[inline]
            pub fn end(&self) -> $addr {
                <$addr>::from_bits(self.end)
            }

            /// Returns `true` if `addr` lies within the range, inclusive.
            #[inline]
            pub fn contains(&self, addr: $addr) -> bool {
                let a = addr.to_bits();
                self.start <= a && a <= self.end
            }

            /// The number of addresses in the range.
            ///
            /// Saturates to [`u128::MAX`] for the full IPv6 range (whose true
            /// count, `2^128`, does not fit in a `u128`).
            pub fn count(&self) -> u128 {
                ((self.end - self.start) as u128).saturating_add(1)
            }

            /// Iterate over every address in the range, lowest to highest.
            pub fn iter(&self) -> $iter {
                $iter::bounded(self.start, self.end)
            }

            /// Returns `true` if the two ranges share at least one address.
            pub fn overlaps(&self, other: &Self) -> bool {
                self.start <= other.end && other.start <= self.end
            }

            /// Returns `true` if `other` is entirely within this range.
            pub fn contains_range(&self, other: &Self) -> bool {
                self.start <= other.start && other.end <= self.end
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}-{}", self.start(), self.end())
            }
        }

        impl IntoIterator for $name {
            type Item = $addr;
            type IntoIter = $iter;
            fn into_iter(self) -> $iter {
                self.iter()
            }
        }
    };
}

define_range!(Ipv4Range, Ipv4AddrIter, Ipv4Addr, u32);
define_range!(Ipv6Range, Ipv6AddrIter, Ipv6Addr, u128);

impl Ipv4Range {
    /// Decompose this range into the **minimal** set of aligned CIDR blocks
    /// that exactly cover it.
    ///
    /// Any inclusive range can be covered by a handful of power-of-two blocks;
    /// this is the standard greedy algorithm that, at each step, emits the
    /// largest block that is both aligned to the current address and fits
    /// inside the remaining range. The returned blocks are in ascending order
    /// and do not overlap.
    ///
    /// ```
    /// use cidr_utils::Ipv4Range;
    /// let r: Ipv4Range = "192.168.1.0-192.168.1.130".parse().unwrap();
    /// let cidrs: Vec<_> = r.to_cidrs().iter().map(|c| c.to_string()).collect();
    /// assert_eq!(cidrs, ["192.168.1.0/25", "192.168.1.128/31", "192.168.1.130/32"]);
    /// ```
    pub fn to_cidrs(&self) -> Vec<Ipv4Cidr> {
        let mut out = Vec::new();
        // Work in u64 so `cur + block_size` can step one past u32::MAX cleanly.
        let end = u64::from(self.end);
        let mut cur = u64::from(self.start);
        while cur <= end {
            // Largest block aligned to `cur` (a /0 may start only at 0).
            let align_bits = if cur == 0 {
                32
            } else {
                (cur as u32).trailing_zeros()
            };
            // Largest power-of-two block that still fits the remaining count.
            let remaining = end - cur + 1;
            let count_bits = 63 - remaining.leading_zeros();
            let bits = align_bits.min(count_bits);
            let prefix = 32 - bits as u8;
            out.push(Ipv4Cidr::new(Ipv4Addr::from_bits(cur as u32), prefix).unwrap());
            cur += 1u64 << bits;
        }
        out
    }
}

impl Ipv6Range {
    /// Decompose this range into the **minimal** set of aligned CIDR blocks
    /// that exactly cover it — the IPv6 analogue of [`Ipv4Range::to_cidrs`].
    ///
    /// ```
    /// use cidr_utils::Ipv6Range;
    /// let r: Ipv6Range = "2001:db8::-2001:db8::ff".parse().unwrap();
    /// let cidrs: Vec<_> = r.to_cidrs().iter().map(|c| c.to_string()).collect();
    /// assert_eq!(cidrs, ["2001:db8::/120"]);
    /// ```
    pub fn to_cidrs(&self) -> Vec<Ipv6Cidr> {
        let (start, end) = (self.start, self.end);
        let mut out = Vec::new();
        let mut cur = start;
        loop {
            let align_bits = if cur == 0 { 128 } else { cur.trailing_zeros() };
            let remaining = end - cur; // count - 1; avoids a +1 overflow
            let count_bits = if remaining == u128::MAX {
                128
            } else {
                127 - (remaining + 1).leading_zeros()
            };
            let bits = align_bits.min(count_bits);
            let prefix = (128 - bits) as u8;
            out.push(Ipv6Cidr::new(Ipv6Addr::from_bits(cur), prefix).unwrap());
            if bits >= 128 {
                break; // covered the whole space in one /0
            }
            match cur.checked_add(1u128 << bits) {
                Some(next) if next <= end => cur = next,
                _ => break,
            }
        }
        out
    }
}

impl Ipv4Cidr {
    /// Collapse a list of IPv4 blocks into the **minimal** equivalent set,
    /// merging overlapping, adjacent, and contained blocks.
    ///
    /// The result covers exactly the same addresses as the input, sorted and
    /// non-overlapping, with adjacent siblings combined into larger blocks where
    /// possible.
    ///
    /// ```
    /// use cidr_utils::Ipv4Cidr;
    /// let blocks: Vec<Ipv4Cidr> = ["10.0.0.0/25", "10.0.0.128/25", "10.0.1.0/24"]
    ///     .iter().map(|s| s.parse().unwrap()).collect();
    /// let merged: Vec<_> = Ipv4Cidr::aggregate(&blocks).iter().map(|c| c.to_string()).collect();
    /// assert_eq!(merged, ["10.0.0.0/23"]);
    /// ```
    pub fn aggregate(cidrs: &[Ipv4Cidr]) -> Vec<Ipv4Cidr> {
        if cidrs.is_empty() {
            return Vec::new();
        }
        // Reduce to inclusive [start, end] intervals over a u64 number line.
        let mut intervals: Vec<(u64, u64)> = cidrs
            .iter()
            .map(|c| {
                (
                    u64::from(c.network().to_bits()),
                    u64::from(c.broadcast().to_bits()),
                )
            })
            .collect();
        intervals.sort_unstable();

        // Merge overlapping or directly adjacent intervals.
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (s, e) in intervals {
            match merged.last_mut() {
                Some(last) if s <= last.1 + 1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }

        // Re-decompose each merged span into aligned blocks.
        merged
            .into_iter()
            .flat_map(|(s, e)| {
                Ipv4Range::new(Ipv4Addr::from_bits(s as u32), Ipv4Addr::from_bits(e as u32))
                    .unwrap()
                    .to_cidrs()
            })
            .collect()
    }
}

impl Ipv6Cidr {
    /// Collapse a list of IPv6 blocks into the **minimal** equivalent set — the
    /// IPv6 analogue of [`Ipv4Cidr::aggregate`].
    pub fn aggregate(cidrs: &[Ipv6Cidr]) -> Vec<Ipv6Cidr> {
        if cidrs.is_empty() {
            return Vec::new();
        }
        let mut intervals: Vec<(u128, u128)> = cidrs
            .iter()
            .map(|c| (c.network().to_bits(), c.last_address().to_bits()))
            .collect();
        intervals.sort_unstable();

        let mut merged: Vec<(u128, u128)> = Vec::new();
        for (s, e) in intervals {
            match merged.last_mut() {
                // `saturating_add` guards the top of the address space.
                Some(last) if s <= last.1.saturating_add(1) => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }

        merged
            .into_iter()
            .flat_map(|(s, e)| {
                Ipv6Range::new(Ipv6Addr::from_bits(s), Ipv6Addr::from_bits(e))
                    .unwrap()
                    .to_cidrs()
            })
            .collect()
    }
}

impl FromStr for Ipv4Range {
    type Err = ParseError;

    /// Parse `start-end`, where `end` may be a full address
    /// (`192.168.1.1-192.168.1.50`) or a bare final octet
    /// (`192.168.1.1-50`, expanded against the start address).
    fn from_str(s: &str) -> Result<Self, ParseError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(ParseError::Empty);
        }
        let (start_str, end_str) = s
            .split_once('-')
            .ok_or_else(|| ParseError::Malformed(s.to_string()))?;
        let start = Ipv4Addr::from_str(start_str.trim())
            .map_err(|_| ParseError::BadAddr(start_str.to_string()))?;
        let end_str = end_str.trim();

        let end = if let Ok(addr) = Ipv4Addr::from_str(end_str) {
            addr
        } else if let Ok(octet) = end_str.parse::<u8>() {
            // Last-octet shorthand: keep the start's first three octets.
            let mut octets = start.octets();
            octets[3] = octet;
            Ipv4Addr::from(octets)
        } else {
            return Err(ParseError::BadAddr(end_str.to_string()));
        };

        Ipv4Range::new(start, end)
    }
}

impl FromStr for Ipv6Range {
    type Err = ParseError;

    /// Parse `start-end`, where both endpoints are full IPv6 addresses.
    fn from_str(s: &str) -> Result<Self, ParseError> {
        let s = s.trim();
        if s.is_empty() {
            return Err(ParseError::Empty);
        }
        let (start_str, end_str) = s
            .split_once('-')
            .ok_or_else(|| ParseError::Malformed(s.to_string()))?;
        let start = Ipv6Addr::from_str(start_str.trim())
            .map_err(|_| ParseError::BadAddr(start_str.to_string()))?;
        let end = Ipv6Addr::from_str(end_str.trim())
            .map_err(|_| ParseError::BadAddr(end_str.to_string()))?;
        Ipv6Range::new(start, end)
    }
}

/// An address-family-agnostic inclusive range — either IPv4 or IPv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IpRange {
    /// An IPv4 range.
    V4(Ipv4Range),
    /// An IPv6 range.
    V6(Ipv6Range),
}

impl IpRange {
    /// Build a range from two [`IpAddr`] endpoints of the same family.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError::MixedFamilies`] if `start` and `end` are different
    /// address families, or [`ParseError::StartAfterEnd`] if `start > end`.
    pub fn new(start: IpAddr, end: IpAddr) -> Result<Self, ParseError> {
        match (start, end) {
            (IpAddr::V4(s), IpAddr::V4(e)) => Ipv4Range::new(s, e).map(IpRange::V4),
            (IpAddr::V6(s), IpAddr::V6(e)) => Ipv6Range::new(s, e).map(IpRange::V6),
            _ => Err(ParseError::MixedFamilies),
        }
    }

    /// The first address in the range.
    pub fn start(&self) -> IpAddr {
        match self {
            IpRange::V4(r) => IpAddr::V4(r.start()),
            IpRange::V6(r) => IpAddr::V6(r.start()),
        }
    }

    /// The last address in the range.
    pub fn end(&self) -> IpAddr {
        match self {
            IpRange::V4(r) => IpAddr::V4(r.end()),
            IpRange::V6(r) => IpAddr::V6(r.end()),
        }
    }

    /// The number of addresses in the range.
    pub fn count(&self) -> u128 {
        match self {
            IpRange::V4(r) => r.count(),
            IpRange::V6(r) => r.count(),
        }
    }

    /// Returns `true` if `addr` lies within the range. A mismatched address
    /// family always returns `false`.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self, addr) {
            (IpRange::V4(r), IpAddr::V4(a)) => r.contains(a),
            (IpRange::V6(r), IpAddr::V6(a)) => r.contains(a),
            _ => false,
        }
    }

    /// Returns `true` if the two ranges share at least one address. A
    /// mismatched address family always returns `false`.
    pub fn overlaps(&self, other: &IpRange) -> bool {
        match (self, other) {
            (IpRange::V4(a), IpRange::V4(b)) => a.overlaps(b),
            (IpRange::V6(a), IpRange::V6(b)) => a.overlaps(b),
            _ => false,
        }
    }

    /// Returns `true` if `other` is entirely within this range. A mismatched
    /// address family always returns `false`.
    pub fn contains_range(&self, other: &IpRange) -> bool {
        match (self, other) {
            (IpRange::V4(a), IpRange::V4(b)) => a.contains_range(b),
            (IpRange::V6(a), IpRange::V6(b)) => a.contains_range(b),
            _ => false,
        }
    }

    /// Iterate over every address in the range as [`IpAddr`], lowest to highest.
    pub fn addresses(&self) -> IpSetIter {
        match self {
            IpRange::V4(r) => IpSetIter::V4(r.iter()),
            IpRange::V6(r) => IpSetIter::V6(r.iter()),
        }
    }

    /// Decompose the range into the minimal set of aligned CIDR blocks that
    /// exactly cover it, preserving the address family.
    pub fn to_cidrs(&self) -> Vec<IpCidr> {
        match self {
            IpRange::V4(r) => r.to_cidrs().into_iter().map(IpCidr::V4).collect(),
            IpRange::V6(r) => r.to_cidrs().into_iter().map(IpCidr::V6).collect(),
        }
    }
}

impl fmt::Display for IpRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpRange::V4(r) => r.fmt(f),
            IpRange::V6(r) => r.fmt(f),
        }
    }
}

impl FromStr for IpRange {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        if let Ok(r) = Ipv4Range::from_str(s) {
            return Ok(IpRange::V4(r));
        }
        Ipv6Range::from_str(s).map(IpRange::V6)
    }
}

impl From<Ipv4Range> for IpRange {
    fn from(r: Ipv4Range) -> Self {
        IpRange::V4(r)
    }
}

impl From<Ipv6Range> for IpRange {
    fn from(r: Ipv6Range) -> Self {
        IpRange::V6(r)
    }
}
