//! # cidr-utils
//!
//! Parse, enumerate, and test **IPv4 and IPv6** CIDR blocks and address ranges.
//! Pure integer math over [`std::net`] address types — no DNS, no sockets, no
//! allocation in the hot paths.
//!
//! ## The three target shapes
//!
//! Most callers want [`IpSet`], which parses any of the supported target
//! spellings and enumerates the addresses inside:
//!
//! ```
//! use cidr_utils::IpSet;
//!
//! let net: IpSet = "192.168.1.0/30".parse().unwrap();
//! assert_eq!(net.count(), 4);
//!
//! // `.hosts()` drops the network and broadcast addresses for IPv4 blocks.
//! let hosts: Vec<_> = net.hosts().map(|a| a.to_string()).collect();
//! assert_eq!(hosts, ["192.168.1.1", "192.168.1.2"]);
//! ```
//!
//! Ranges and bare addresses parse through the same entry point:
//!
//! ```
//! use cidr_utils::IpSet;
//!
//! let range: IpSet = "10.0.0.1-10.0.0.5".parse().unwrap();
//! assert_eq!(range.count(), 5);
//!
//! // Last-octet shorthand for IPv4 ranges.
//! let short: IpSet = "10.0.0.1-5".parse().unwrap();
//! assert_eq!(short.count(), 5);
//!
//! let single: IpSet = "10.0.0.42".parse().unwrap();
//! assert_eq!(single.count(), 1);
//! ```
//!
//! ## Working with a specific family
//!
//! When you know the family, the concrete [`Ipv4Cidr`] / [`Ipv6Cidr`] and
//! [`Ipv4Range`] / [`Ipv6Range`] types expose the full surface (network mask,
//! broadcast, containment, counts):
//!
//! ```
//! use cidr_utils::Ipv4Cidr;
//! use std::net::Ipv4Addr;
//!
//! let block: Ipv4Cidr = "192.168.0.0/24".parse().unwrap();
//! assert_eq!(block.network(), Ipv4Addr::new(192, 168, 0, 0));
//! assert_eq!(block.broadcast(), Ipv4Addr::new(192, 168, 0, 255));
//! assert_eq!(block.netmask(), Ipv4Addr::new(255, 255, 255, 0));
//! assert_eq!(block.host_count(), 254);
//! assert!(block.contains(Ipv4Addr::new(192, 168, 0, 50)));
//! ```
//!
//! ## Features
//!
//! - `cli` *(default)* — pulls in the dependencies for the `cidr-utils` binary.
//!   Disable it (`default-features = false`) for a slim library dependency.
//! - `serde` — derives [`serde::Serialize`]/[`serde::Deserialize`] on the public
//!   address, range, and set types.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod cidr;
mod error;
mod range;
mod set;

pub use cidr::{IpCidr, Ipv4AddrIter, Ipv4Cidr, Ipv6AddrIter, Ipv6Cidr};
pub use error::ParseError;
pub use range::{IpRange, Ipv4Range, Ipv6Range};
pub use set::{aggregate, IpSet, IpSetIter};
