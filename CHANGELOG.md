# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Block hierarchy: `supernet()`, `subnets(prefix)`, `contains_subnet`,
  `is_subnet_of`, `is_supernet_of`, and `overlaps` on the CIDR types.
- IPv4 helpers: `wildcard()`, `first_host()`, `last_host()`, and classification
  predicates (`is_private`, `is_loopback`, `is_link_local`, `is_documentation`,
  `is_multicast`); IPv6 `is_loopback`/`is_multicast`/`is_unspecified`.
- Range/CIDR conversion: `Ipv4Range::to_cidrs`, `Ipv6Range::to_cidrs`,
  `IpRange::to_cidrs`, and `IpSet::to_cidrs` for minimal CIDR decomposition.
- Aggregation: `Ipv4Cidr::aggregate` / `Ipv6Cidr::aggregate` to merge a list of
  blocks into the minimal equivalent set.
- `Ord`/`PartialOrd` on the CIDR types for canonical sorting.
- Parsing now accepts the dotted-netmask form (`192.168.1.0/255.255.255.0`).
- `size_hint` on the address iterators (exact for IPv4).
- CLI: `--cidrs`, `--aggregate`, `--split <PREFIX>`, and a wildcard mask plus
  address class in `--info`.
- CIDR subtraction: `exclude()` on the CIDR types and `IpCidr`, plus the CLI
  `--exclude <CIDR>`.
- Block utilities: `split()`, `subnet_count()`, and `nth_address()` (O(1)
  indexing) on the CIDR types, with `nth_address` on `IpCidr`.
- Iteration: address iterators are now `DoubleEndedIterator` (reverse / `rev`);
  `IpCidr`/`IpRange` gained `addresses()`/`hosts()`, and `IpSetIter` forwards
  `size_hint` and reverses.
- Ranges: `overlaps()` / `contains_range()` and `Ord`/`PartialOrd`.
- `IpSet`: `is_single`/`is_cidr`/`is_range`, `as_cidr`/`as_range`.
- Top-level `aggregate()` for mixed-family block lists.
- CLI: `--reverse`, `--total`, and `--json` target summaries.
- Criterion benchmarks for parsing, containment, decomposition, subnetting,
  exclusion, and aggregation.

## [0.1.0]

Initial release.

### Added

- `Ipv4Cidr` / `Ipv6Cidr` and the family-agnostic `IpCidr` for CIDR blocks:
  parsing, network/broadcast/netmask, address and host counts, containment, and
  host/address iterators (with IPv4 `/31` and `/32` conventions).
- `Ipv4Range` / `Ipv6Range` and `IpRange` for inclusive address ranges, with
  last-octet shorthand for IPv4 (`192.168.1.1-50`).
- `IpSet`, a single entry point that parses CIDR blocks, ranges, and bare
  addresses and enumerates their hosts.
- `ParseError` covering empty, malformed, bad-address, bad-prefix,
  mixed-family, and start-after-end inputs.
- `cidr-utils` CLI: list hosts, `--all`, `--count`, `--info`, `--contains`,
  `--limit`, and stdin input via `-`.
- Optional `serde` feature deriving `Serialize`/`Deserialize` on the public
  types.

[Unreleased]: https://github.com/yabowarcherio/cidr-utils/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yabowarcherio/cidr-utils/releases/tag/v0.1.0
