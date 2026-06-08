# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
