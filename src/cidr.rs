//! CIDR blocks for IPv4 and IPv6, plus the address-family-agnostic [`IpCidr`].

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::error::ParseError;
use crate::set::IpSetIter;

/// Generate a concrete CIDR type for one address family.
///
/// The IPv4 and IPv6 blocks share almost all of their logic; only a handful of
/// methods (IPv4 broadcast, host-count conventions) differ and are written by
/// hand below.
macro_rules! define_cidr {
    ($name:ident, $iter:ident, $subnets:ident, $addr:ty, $uint:ty, $bits:literal) => {
        /// A CIDR block: a network address paired with a prefix length.
        ///
        /// The stored network address is always canonical — host bits below the
        /// prefix are cleared on construction, so two equal blocks compare equal
        /// regardless of how they were written.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name {
            // Field order matters: derived ordering sorts by network first, then
            // by prefix length, which is the natural order for CIDR blocks.
            network: $uint,
            prefix_len: u8,
        }

        impl $name {
            /// The maximum prefix length for this family (32 for IPv4, 128 for
            /// IPv6).
            pub const MAX_PREFIX_LEN: u8 = $bits;

            /// Build a block from an address and prefix length, masking off any
            /// host bits so the stored network is canonical.
            ///
            /// # Errors
            ///
            /// Returns [`ParseError::BadPrefix`] if `prefix_len` exceeds
            /// [`Self::MAX_PREFIX_LEN`].
            pub fn new(addr: $addr, prefix_len: u8) -> Result<Self, ParseError> {
                if prefix_len > $bits {
                    return Err(ParseError::BadPrefix(prefix_len.to_string()));
                }
                let mask = Self::mask_bits(prefix_len);
                Ok(Self {
                    network: addr.to_bits() & mask,
                    prefix_len,
                })
            }

            /// The all-ones network mask for `prefix_len`, as a raw integer.
            const fn mask_bits(prefix_len: u8) -> $uint {
                if prefix_len == 0 {
                    0
                } else {
                    <$uint>::MAX << ($bits - prefix_len as u32)
                }
            }

            /// Convert a raw network mask to a prefix length, if the mask is a
            /// valid contiguous run of leading ones (e.g. `255.255.255.0`).
            fn prefix_from_mask(mask: $uint) -> Option<u8> {
                let ones = mask.leading_ones() as u8;
                (Self::mask_bits(ones) == mask).then_some(ones)
            }

            /// Convert a dotted/expanded network mask (e.g. `255.255.255.0`) to
            /// a prefix length. Returns `None` if `mask` is not a valid
            /// contiguous run of leading ones.
            pub fn mask_to_prefix_len(mask: $addr) -> Option<u8> {
                Self::prefix_from_mask(mask.to_bits())
            }

            /// The wildcard mask (`!netmask`), e.g. `0.0.0.255` for a `/24`.
            pub fn wildcard_mask(&self) -> $addr {
                <$addr>::from_bits(!Self::mask_bits(self.prefix_len))
            }

            /// The prefix length (number of leading network bits).
            #[inline]
            pub const fn prefix_len(&self) -> u8 {
                self.prefix_len
            }

            /// The network address (lowest address in the block).
            #[inline]
            pub fn network(&self) -> $addr {
                <$addr>::from_bits(self.network)
            }

            /// The network mask as an address (e.g. `255.255.255.0`).
            #[inline]
            pub fn netmask(&self) -> $addr {
                <$addr>::from_bits(Self::mask_bits(self.prefix_len))
            }

            /// The highest address in the block (all host bits set).
            ///
            /// For IPv4 this is the broadcast address; see also
            /// [`Ipv4Cidr::broadcast`].
            #[inline]
            pub fn last_address(&self) -> $addr {
                <$addr>::from_bits(self.network | !Self::mask_bits(self.prefix_len))
            }

            /// Returns `true` if `addr` falls inside this block.
            #[inline]
            pub fn contains(&self, addr: $addr) -> bool {
                addr.to_bits() & Self::mask_bits(self.prefix_len) == self.network
            }

            /// The total number of addresses in the block, i.e.
            /// `2^(MAX_PREFIX_LEN - prefix_len)`.
            ///
            /// Saturates to [`u128::MAX`] for an IPv6 `/0` (whose true count,
            /// `2^128`, does not fit in a `u128`).
            pub const fn address_count(&self) -> u128 {
                let host_bits = $bits - self.prefix_len as u32;
                if host_bits >= 128 {
                    u128::MAX
                } else {
                    1u128 << host_bits
                }
            }

            /// The address at offset `index` from the network address, or
            /// `None` if `index` is past the end of the block.
            ///
            /// `nth_address(0)` is the network address. This is an O(1) index,
            /// far cheaper than iterating for a known position.
            pub fn nth_address(&self, index: u128) -> Option<$addr> {
                if index >= self.address_count() {
                    return None;
                }
                let offset = <$uint>::try_from(index).ok()?;
                Some(<$addr>::from_bits(self.network + offset))
            }

            /// Iterate over every address in the block, lowest to highest.
            ///
            /// For large IPv6 blocks this iterator is effectively unbounded —
            /// prefer [`contains`](Self::contains) or a bounded range.
            pub fn addresses(&self) -> $iter {
                $iter::bounded(
                    self.network,
                    self.network | !Self::mask_bits(self.prefix_len),
                )
            }

            /// The immediately enclosing block, one prefix bit shorter.
            ///
            /// Returns `None` for a `/0`, which has no parent.
            pub fn supernet(&self) -> Option<Self> {
                if self.prefix_len == 0 {
                    return None;
                }
                let parent = self.prefix_len - 1;
                Some(Self {
                    network: self.network & Self::mask_bits(parent),
                    prefix_len: parent,
                })
            }

            /// Split this block into the sub-blocks of length `new_prefix`.
            ///
            /// The returned iterator is empty if `new_prefix` is shorter than
            /// this block's prefix or longer than [`Self::MAX_PREFIX_LEN`]. A
            /// `new_prefix` equal to this block's prefix yields the block itself.
            pub fn subnets(&self, new_prefix: u8) -> $subnets {
                if new_prefix < self.prefix_len || new_prefix > $bits {
                    return $subnets {
                        next: None,
                        last: 0,
                        step: 0,
                        new_prefix,
                    };
                }
                let last_addr = self.network | !Self::mask_bits(self.prefix_len);
                let last_network = last_addr & Self::mask_bits(new_prefix);
                // Block size of the child prefix; wraps to 0 only for a `/0`
                // child, which is single-shot so the step is never applied.
                let step = (!Self::mask_bits(new_prefix)).wrapping_add(1);
                $subnets {
                    next: Some(self.network),
                    last: last_network,
                    step,
                    new_prefix,
                }
            }

            /// The number of `new_prefix`-length sub-blocks this block splits
            /// into, without enumerating them.
            ///
            /// Returns `0` if `new_prefix` is shorter than this block's prefix
            /// or out of range, and saturates to [`u128::MAX`] for the IPv6 `/0`
            /// split to `/128`.
            pub fn subnet_count(&self, new_prefix: u8) -> u128 {
                if new_prefix < self.prefix_len || new_prefix > $bits {
                    return 0;
                }
                let diff = new_prefix - self.prefix_len;
                if diff >= 128 {
                    u128::MAX
                } else {
                    1u128 << diff
                }
            }

            /// Split this block into its two equal halves (each one prefix bit
            /// longer), or `None` if the block is already a single address
            /// (`/32` for IPv4, `/128` for IPv6).
            pub fn split(&self) -> Option<(Self, Self)> {
                if self.prefix_len >= $bits {
                    return None;
                }
                let child = self.prefix_len + 1;
                let half_bit: $uint = 1 << ($bits - child as u32);
                let lower = Self {
                    network: self.network,
                    prefix_len: child,
                };
                let upper = Self {
                    network: self.network | half_bit,
                    prefix_len: child,
                };
                Some((lower, upper))
            }

            /// Returns `true` if `other` is fully contained in this block — the
            /// same network bits and a prefix at least as long.
            pub fn contains_subnet(&self, other: &Self) -> bool {
                self.prefix_len <= other.prefix_len
                    && (other.network & Self::mask_bits(self.prefix_len)) == self.network
            }

            /// Returns `true` if this block is a supernet of (encloses) `other`.
            /// Equivalent to `self.contains_subnet(other)`.
            pub fn is_supernet_of(&self, other: &Self) -> bool {
                self.contains_subnet(other)
            }

            /// Returns `true` if this block is a subnet of (is enclosed by)
            /// `other`.
            pub fn is_subnet_of(&self, other: &Self) -> bool {
                other.contains_subnet(self)
            }

            /// Returns `true` if the two blocks share at least one address.
            ///
            /// For nested CIDR blocks this is always true; it is primarily
            /// useful when neither block contains the other in a list of
            /// arbitrary blocks.
            pub fn overlaps(&self, other: &Self) -> bool {
                let a_last = self.network | !Self::mask_bits(self.prefix_len);
                let b_last = other.network | !Self::mask_bits(other.prefix_len);
                self.network <= b_last && other.network <= a_last
            }

            /// Remove `other` from this block, returning the minimal set of CIDR
            /// blocks covering the remaining addresses, sorted ascending.
            ///
            /// - If `other` does not overlap this block, the result is just this
            ///   block unchanged.
            /// - If `other` fully covers this block, the result is empty.
            /// - Otherwise `other` is a strict subnet, and the result is the set
            ///   of sibling blocks along the path down to it.
            pub fn exclude(&self, other: &Self) -> Vec<Self> {
                if !self.overlaps(other) {
                    return vec![*self];
                }
                if other.contains_subnet(self) {
                    return Vec::new();
                }
                // `other` is necessarily a strict subnet here (CIDR blocks never
                // partially overlap). Walk down, keeping the sibling each step.
                let mut result = Vec::new();
                let mut current = *self;
                while current.prefix_len < other.prefix_len {
                    let child_prefix = current.prefix_len + 1;
                    let half_bit: $uint = 1 << ($bits - child_prefix as u32);
                    let lower = Self {
                        network: current.network,
                        prefix_len: child_prefix,
                    };
                    let upper = Self {
                        network: current.network | half_bit,
                        prefix_len: child_prefix,
                    };
                    if lower.contains_subnet(other) {
                        result.push(upper);
                        current = lower;
                    } else {
                        result.push(lower);
                        current = upper;
                    }
                }
                result.sort_unstable();
                result
            }
        }

        /// Iterator over the sub-blocks produced by `subnets`.
        #[derive(Debug, Clone)]
        pub struct $subnets {
            next: Option<$uint>,
            last: $uint,
            step: $uint,
            new_prefix: u8,
        }

        impl Iterator for $subnets {
            type Item = $name;

            fn next(&mut self) -> Option<$name> {
                let cur = self.next?;
                self.next = if cur >= self.last {
                    None
                } else {
                    Some(cur + self.step)
                };
                Some($name {
                    network: cur,
                    prefix_len: self.new_prefix,
                })
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}/{}", self.network(), self.prefix_len)
            }
        }

        impl FromStr for $name {
            type Err = ParseError;

            fn from_str(s: &str) -> Result<Self, ParseError> {
                let s = s.trim();
                if s.is_empty() {
                    return Err(ParseError::Empty);
                }
                let (addr_str, prefix_str) = s
                    .split_once('/')
                    .ok_or_else(|| ParseError::BadPrefix(s.to_string()))?;
                let addr = <$addr>::from_str(addr_str.trim())
                    .map_err(|_| ParseError::BadAddr(addr_str.to_string()))?;
                let prefix_str = prefix_str.trim();
                let prefix_len = match prefix_str.parse::<u8>() {
                    Ok(p) => p,
                    // Fall back to a dotted/expanded netmask, e.g. 255.255.255.0.
                    Err(_) => <$addr>::from_str(prefix_str)
                        .ok()
                        .and_then(|m| Self::prefix_from_mask(m.to_bits()))
                        .ok_or_else(|| ParseError::BadPrefix(prefix_str.to_string()))?,
                };
                Self::new(addr, prefix_len)
            }
        }

        /// Iterator over a contiguous run of addresses, lowest to highest.
        ///
        /// Yielded by both CIDR blocks and address ranges of this family.
        /// Implements [`DoubleEndedIterator`], so it can be walked from the top
        /// with [`Iterator::rev`] or [`DoubleEndedIterator::next_back`].
        #[derive(Debug, Clone)]
        pub struct $iter {
            front: $uint,
            back: $uint,
            done: bool,
        }

        impl $iter {
            /// Construct an inclusive iterator over `first..=last` raw values.
            /// An empty iterator results when `first > last`.
            pub(crate) fn bounded(first: $uint, last: $uint) -> Self {
                $iter {
                    front: first,
                    back: last,
                    done: first > last,
                }
            }
        }

        impl Iterator for $iter {
            type Item = $addr;

            fn next(&mut self) -> Option<$addr> {
                if self.done {
                    return None;
                }
                let cur = self.front;
                if cur == self.back {
                    self.done = true;
                } else {
                    self.front = cur + 1;
                }
                Some(<$addr>::from_bits(cur))
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                if self.done {
                    return (0, Some(0));
                }
                // `span` is the count minus one, widened so the IPv4 case never
                // overflows. `u128::from` is an identity conversion for the IPv6
                // (`u128`) instantiation.
                let span = u128::from(self.back) - u128::from(self.front);
                match usize::try_from(span) {
                    Ok(n) if n != usize::MAX => (n + 1, Some(n + 1)),
                    // Count exceeds `usize` (only possible for IPv6).
                    _ => (usize::MAX, None),
                }
            }
        }

        impl DoubleEndedIterator for $iter {
            fn next_back(&mut self) -> Option<$addr> {
                if self.done {
                    return None;
                }
                let cur = self.back;
                if cur == self.front {
                    self.done = true;
                } else {
                    self.back = cur - 1;
                }
                Some(<$addr>::from_bits(cur))
            }
        }
    };
}

define_cidr!(Ipv4Cidr, Ipv4AddrIter, Ipv4Subnets, Ipv4Addr, u32, 32);
define_cidr!(Ipv6Cidr, Ipv6AddrIter, Ipv6Subnets, Ipv6Addr, u128, 128);

impl Ipv4Cidr {
    /// The IPv4 broadcast address (highest address in the block).
    ///
    /// Identical to [`last_address`](Self::last_address); provided under the
    /// name network operators expect.
    #[inline]
    pub fn broadcast(&self) -> Ipv4Addr {
        self.last_address()
    }

    /// The number of *usable host* addresses, following the usual IPv4
    /// conventions:
    ///
    /// - `/31` → 2 (RFC 3021 point-to-point link)
    /// - `/32` → 1 (single host)
    /// - everything else → total minus the network and broadcast addresses
    pub fn host_count(&self) -> u64 {
        let total = self.address_count() as u64;
        match self.prefix_len() {
            32 => 1,
            31 => 2,
            _ => total - 2,
        }
    }

    /// `true` if the block sits in [RFC 1918] private space
    /// (`10/8`, `172.16/12`, `192.168/16`).
    ///
    /// [RFC 1918]: https://datatracker.ietf.org/doc/html/rfc1918
    pub fn is_private(&self) -> bool {
        self.network().is_private()
    }

    /// `true` if the block is the loopback range (`127/8`).
    pub fn is_loopback(&self) -> bool {
        self.network().is_loopback()
    }

    /// `true` if the block is link-local (`169.254/16`).
    pub fn is_link_local(&self) -> bool {
        self.network().is_link_local()
    }

    /// `true` if the block is documentation space (`192.0.2/24`,
    /// `198.51.100/24`, `203.0.113/24`).
    pub fn is_documentation(&self) -> bool {
        self.network().is_documentation()
    }

    /// `true` if the block is multicast (`224/4`).
    pub fn is_multicast(&self) -> bool {
        self.network().is_multicast()
    }

    /// The wildcard mask (inverse netmask), as used in Cisco ACLs.
    ///
    /// For a `/24` this is `0.0.0.255`.
    pub fn wildcard(&self) -> Ipv4Addr {
        Ipv4Addr::from_bits(!self.netmask().to_bits())
    }

    /// The first usable host address.
    ///
    /// For `/30` and shorter this is the address just above the network; for
    /// `/31` and `/32` it is the network address itself.
    pub fn first_host(&self) -> Ipv4Addr {
        self.hosts().next().unwrap_or_else(|| self.network())
    }

    /// The last usable host address.
    ///
    /// For `/30` and shorter this is the address just below the broadcast; for
    /// `/31` and `/32` it is the broadcast address itself.
    pub fn last_host(&self) -> Ipv4Addr {
        let last = self.last_address().to_bits();
        if self.prefix_len() <= 30 {
            Ipv4Addr::from_bits(last - 1)
        } else {
            Ipv4Addr::from_bits(last)
        }
    }

    /// Iterate over the usable host addresses, excluding the network and
    /// broadcast addresses for `/30` and shorter prefixes. For `/31` and `/32`
    /// every address is yielded (per RFC 3021 / single-host conventions).
    pub fn hosts(&self) -> Ipv4AddrIter {
        let first = self.network;
        let last = self.last_address().to_bits();
        if self.prefix_len() <= 30 {
            Ipv4AddrIter::bounded(first + 1, last - 1)
        } else {
            Ipv4AddrIter::bounded(first, last)
        }
    }
}

impl Ipv6Cidr {
    /// `true` if the block is the IPv6 loopback (`::1`).
    pub fn is_loopback(&self) -> bool {
        self.network().is_loopback()
    }

    /// `true` if the block is IPv6 multicast (`ff00::/8`).
    pub fn is_multicast(&self) -> bool {
        self.network().is_multicast()
    }

    /// `true` if the block is the unspecified address range (`::`).
    pub fn is_unspecified(&self) -> bool {
        self.network().is_unspecified()
    }

    /// `true` if the block is in the IPv6 unique-local range `fc00::/7`
    /// (RFC 4193). The IPv6 analogue of RFC 1918 private addresses.
    pub fn is_unique_local(&self) -> bool {
        let s = self.network().segments();
        (s[0] & 0xFE00) == 0xFC00
    }

    /// `true` if the block is in the IPv6 link-local range `fe80::/10`
    /// (RFC 4291 §2.4).
    pub fn is_link_local(&self) -> bool {
        let s = self.network().segments();
        (s[0] & 0xFFC0) == 0xFE80
    }

    /// `true` if the block is in the IPv6 documentation range `2001:db8::/32`
    /// (RFC 3849).
    pub fn is_documentation(&self) -> bool {
        let s = self.network().segments();
        s[0] == 0x2001 && s[1] == 0x0DB8
    }

    /// Iterate over the host addresses of the block.
    ///
    /// IPv6 has no broadcast address, so this is identical to
    /// [`addresses`](Self::addresses) and is provided for symmetry with
    /// [`Ipv4Cidr::hosts`].
    pub fn hosts(&self) -> Ipv6AddrIter {
        self.addresses()
    }
}

/// An address-family-agnostic CIDR block — either IPv4 or IPv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum IpCidr {
    /// An IPv4 block.
    V4(Ipv4Cidr),
    /// An IPv6 block.
    V6(Ipv6Cidr),
}

impl IpCidr {
    /// Build a block from any [`IpAddr`] and a prefix length.
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<Self, ParseError> {
        match addr {
            IpAddr::V4(a) => Ipv4Cidr::new(a, prefix_len).map(IpCidr::V4),
            IpAddr::V6(a) => Ipv6Cidr::new(a, prefix_len).map(IpCidr::V6),
        }
    }

    /// The prefix length of the underlying block.
    pub fn prefix_len(&self) -> u8 {
        match self {
            IpCidr::V4(c) => c.prefix_len(),
            IpCidr::V6(c) => c.prefix_len(),
        }
    }

    /// The network address of the underlying block.
    pub fn network(&self) -> IpAddr {
        match self {
            IpCidr::V4(c) => IpAddr::V4(c.network()),
            IpCidr::V6(c) => IpAddr::V6(c.network()),
        }
    }

    /// The highest address in the block.
    pub fn last_address(&self) -> IpAddr {
        match self {
            IpCidr::V4(c) => IpAddr::V4(c.last_address()),
            IpCidr::V6(c) => IpAddr::V6(c.last_address()),
        }
    }

    /// The network mask as an address.
    pub fn netmask(&self) -> IpAddr {
        match self {
            IpCidr::V4(c) => IpAddr::V4(c.netmask()),
            IpCidr::V6(c) => IpAddr::V6(c.netmask()),
        }
    }

    /// The immediately enclosing block, one prefix bit shorter, or `None` for a
    /// `/0`.
    pub fn supernet(&self) -> Option<IpCidr> {
        match self {
            IpCidr::V4(c) => c.supernet().map(IpCidr::V4),
            IpCidr::V6(c) => c.supernet().map(IpCidr::V6),
        }
    }

    /// Split this block into its two equal halves, or `None` if it is a single
    /// address.
    pub fn split(&self) -> Option<(IpCidr, IpCidr)> {
        match self {
            IpCidr::V4(c) => c.split().map(|(a, b)| (IpCidr::V4(a), IpCidr::V4(b))),
            IpCidr::V6(c) => c.split().map(|(a, b)| (IpCidr::V6(a), IpCidr::V6(b))),
        }
    }

    /// The number of `new_prefix`-length sub-blocks this block splits into.
    pub fn subnet_count(&self, new_prefix: u8) -> u128 {
        match self {
            IpCidr::V4(c) => c.subnet_count(new_prefix),
            IpCidr::V6(c) => c.subnet_count(new_prefix),
        }
    }

    /// Returns `true` if `other` is fully contained in this block. A mismatched
    /// address family always returns `false`.
    pub fn contains_subnet(&self, other: &IpCidr) -> bool {
        match (self, other) {
            (IpCidr::V4(a), IpCidr::V4(b)) => a.contains_subnet(b),
            (IpCidr::V6(a), IpCidr::V6(b)) => a.contains_subnet(b),
            _ => false,
        }
    }

    /// Returns `true` if the two blocks share at least one address. A
    /// mismatched address family always returns `false`.
    pub fn overlaps(&self, other: &IpCidr) -> bool {
        match (self, other) {
            (IpCidr::V4(a), IpCidr::V4(b)) => a.overlaps(b),
            (IpCidr::V6(a), IpCidr::V6(b)) => a.overlaps(b),
            _ => false,
        }
    }

    /// Remove `other` from this block, returning the minimal covering remainder.
    ///
    /// A mismatched address family removes nothing (returns this block
    /// unchanged).
    pub fn exclude(&self, other: &IpCidr) -> Vec<IpCidr> {
        match (self, other) {
            (IpCidr::V4(a), IpCidr::V4(b)) => a.exclude(b).into_iter().map(IpCidr::V4).collect(),
            (IpCidr::V6(a), IpCidr::V6(b)) => a.exclude(b).into_iter().map(IpCidr::V6).collect(),
            _ => vec![*self],
        }
    }

    /// The address at offset `index` from the network address, or `None` if
    /// `index` is past the end of the block.
    pub fn nth_address(&self, index: u128) -> Option<IpAddr> {
        match self {
            IpCidr::V4(c) => c.nth_address(index).map(IpAddr::V4),
            IpCidr::V6(c) => c.nth_address(index).map(IpAddr::V6),
        }
    }

    /// Iterate over every address in the block as [`IpAddr`], lowest to highest.
    pub fn addresses(&self) -> IpSetIter {
        match self {
            IpCidr::V4(c) => IpSetIter::V4(c.addresses()),
            IpCidr::V6(c) => IpSetIter::V6(c.addresses()),
        }
    }

    /// Iterate over the host addresses, applying IPv4 network/broadcast
    /// conventions (identical to [`addresses`](Self::addresses) for IPv6).
    pub fn hosts(&self) -> IpSetIter {
        match self {
            IpCidr::V4(c) => IpSetIter::V4(c.hosts()),
            IpCidr::V6(c) => IpSetIter::V6(c.addresses()),
        }
    }

    /// The total number of addresses in the block.
    pub fn address_count(&self) -> u128 {
        match self {
            IpCidr::V4(c) => c.address_count(),
            IpCidr::V6(c) => c.address_count(),
        }
    }

    /// Returns `true` if `addr` is in the block. A mismatched address family
    /// always returns `false`.
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self, addr) {
            (IpCidr::V4(c), IpAddr::V4(a)) => c.contains(a),
            (IpCidr::V6(c), IpAddr::V6(a)) => c.contains(a),
            _ => false,
        }
    }

    /// `true` if this is an IPv4 block.
    pub fn is_ipv4(&self) -> bool {
        matches!(self, IpCidr::V4(_))
    }

    /// `true` if this is an IPv6 block.
    pub fn is_ipv6(&self) -> bool {
        matches!(self, IpCidr::V6(_))
    }

    /// `true` if the block is the loopback range for its family — `127.0.0.0/8`
    /// for IPv4, `::1` for IPv6.
    pub fn is_loopback(&self) -> bool {
        match self {
            IpCidr::V4(c) => c.is_loopback(),
            IpCidr::V6(c) => c.is_loopback(),
        }
    }

    /// `true` if the block is multicast for its family — `224.0.0.0/4` for
    /// IPv4, `ff00::/8` for IPv6.
    pub fn is_multicast(&self) -> bool {
        match self {
            IpCidr::V4(c) => c.is_multicast(),
            IpCidr::V6(c) => c.is_multicast(),
        }
    }

    /// `true` if the block is "private" for its family — RFC 1918 for IPv4
    /// (`10/8`, `172.16/12`, `192.168/16`), RFC 4193 unique-local (`fc00::/7`)
    /// for IPv6.
    pub fn is_private(&self) -> bool {
        match self {
            IpCidr::V4(c) => c.is_private(),
            IpCidr::V6(c) => c.is_unique_local(),
        }
    }

    /// `true` if the block is link-local for its family — `169.254.0.0/16` for
    /// IPv4, `fe80::/10` for IPv6.
    pub fn is_link_local(&self) -> bool {
        match self {
            IpCidr::V4(c) => c.is_link_local(),
            IpCidr::V6(c) => c.is_link_local(),
        }
    }

    /// `true` if the block is documentation for its family — `192.0.2.0/24`,
    /// `198.51.100.0/24`, `203.0.113.0/24` for IPv4 (per `is_documentation` on
    /// `Ipv4Cidr`), `2001:db8::/32` for IPv6.
    pub fn is_documentation(&self) -> bool {
        match self {
            IpCidr::V4(c) => c.is_documentation(),
            IpCidr::V6(c) => c.is_documentation(),
        }
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpCidr::V4(c) => c.fmt(f),
            IpCidr::V6(c) => c.fmt(f),
        }
    }
}

impl FromStr for IpCidr {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        // Try IPv4 first (its addresses never parse as IPv6), then IPv6.
        if let Ok(c) = Ipv4Cidr::from_str(s) {
            return Ok(IpCidr::V4(c));
        }
        Ipv6Cidr::from_str(s).map(IpCidr::V6)
    }
}

impl From<Ipv4Cidr> for IpCidr {
    fn from(c: Ipv4Cidr) -> Self {
        IpCidr::V4(c)
    }
}

impl From<Ipv6Cidr> for IpCidr {
    fn from(c: Ipv6Cidr) -> Self {
        IpCidr::V6(c)
    }
}
