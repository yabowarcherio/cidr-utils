# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- O(1) `nth_address(index)` on `Ipv4Range`, `Ipv6Range`, `IpRange`, and
  `IpSet`. Lets callers sample inside a huge target without iterating.
- `supernet_at(new_prefix)` on `Ipv4Cidr`, `Ipv6Cidr`, and `IpCidr` —
  climbs to the smallest enclosing block of a specific prefix length in one
  step instead of repeated `supernet()` calls.
- `intersection(other)` on `Ipv4Range`, `Ipv6Range`, `IpRange`, and `IpSet`
  — the overlap of two ranges is itself a single contiguous range, so the
  result is returned as one. `IpSet::intersection` always yields a range
  (the overlap rarely lands on an aligned CIDR boundary).
- `exclude(other)` on `Ipv4Range`, `Ipv6Range`, and `IpRange` — the
  range-shaped sibling of the CIDR-shaped `Ipv4Cidr::exclude`. Returns up
  to two pieces (left, right, both, or empty). Mismatched address families
  return the original range unchanged.
- `Ipv4Cidr::vlsm_allocate(host_needs)` — variable-length subnet masking.
  Allocates a sub-block per request, sized to the smallest prefix that
  holds the requested host count. Allocations are placed largest-first
  inside the parent; the return preserves input order. Returns `None` if
  the requests cannot fit.
- `aggregate_max_prefix(cidrs, v4_max, v6_max)` runs the standard aggregator
  but refuses to merge into a block shorter than the given prefix length.
  Useful when downstream consumers can't handle large aggregates.
- CLI `--supernet PREFIX` prints the enclosing block of length `PREFIX` for
  each CIDR target. Exits 2 on range targets or when the requested prefix
  is longer than the target's prefix.
- CLI `--vlsm N,N,...` allocates sub-blocks for each comma-separated host
  count inside each IPv4 CIDR target. Exits 2 on IPv6 / range targets and
  when the requested host counts cannot fit.
- CLI `--intersect TARGET` prints the overlap of each input target with
  `TARGET`. Disjoint targets are dropped silently.

## [0.2.0]

### Added

- `Ipv6Cidr` predicates: `is_unique_local` (RFC 4193 `fc00::/7`),
  `is_link_local` (RFC 4291 §2.4 `fe80::/10`), `is_documentation`
  (RFC 3849 `2001:db8::/32`).
- `IpCidr` predicates routing to the underlying family: `is_loopback`,
  `is_multicast`, `is_private`, `is_link_local`, `is_documentation`.
- `Ipv4Cidr::mask_to_prefix_len` / `Ipv6Cidr::mask_to_prefix_len` and
  `wildcard_mask` on both family-specific types and `IpCidr`.
- `IpCidr::is_host`, `IpCidr::is_default` predicates for the trivial extremes.
- `IpSet::contains_set`, `IpSet::overlaps`, `IpSet::is_address`.
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

[Unreleased]: https://github.com/yabowarcherio/cidr-utils/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/yabowarcherio/cidr-utils/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yabowarcherio/cidr-utils/releases/tag/v0.1.0
