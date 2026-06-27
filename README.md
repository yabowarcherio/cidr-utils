# cidr-utils

[![CI](https://github.com/yabowarcherio/cidr-utils/actions/workflows/ci.yml/badge.svg)](https://github.com/yabowarcherio/cidr-utils/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Parse, enumerate, and test **IPv4 and IPv6** CIDR blocks and address ranges.
Pure integer math over the standard-library address types — no DNS, no sockets,
no allocation in the hot paths. Library **and** CLI.

- **CIDR blocks** — `192.168.1.0/24`, `2001:db8::/32`
- **Ranges** — `192.168.1.1-192.168.1.50`, with last-octet shorthand `192.168.1.1-50`
- **Single addresses** — `10.0.0.5`
- Network / broadcast / netmask, host & address counts, containment tests
- Host enumeration that respects IPv4 network/broadcast conventions (incl. `/31`, `/32`)

## Install

```sh
# CLI
cargo install cidr-utils

# Library
cargo add cidr-utils
```

For a slim library-only dependency without the CLI stack:

```toml
[dependencies]
cidr-utils = { version = "0.1", default-features = false }
```

## Usage (CLI)

```text
cidr-utils [OPTIONS] <TARGET>...

Arguments:
  <TARGET>...  CIDR blocks, ranges, or addresses. Use `-` to read from stdin.

Options:
  -c, --count            Print the number of addresses instead of listing them
  -i, --info             Print a summary (network, broadcast, mask, class, ...)
  -a, --all              Include network/broadcast when listing (IPv4 blocks)
  -l, --limit <N>        Stop after listing N addresses per target (0 = no limit)
      --contains <IP>    Print which targets contain IP; exit 0 if any, else 1
      --cidrs            Print each target as its minimal set of CIDR blocks
      --aggregate        Merge all targets into the minimal set of CIDR blocks
      --split <PREFIX>   Split each target into sub-blocks of this prefix length
  -h, --help             Print help
  -V, --version
```

List the usable hosts in a subnet (network and broadcast are skipped):

```sh
$ cidr-utils 192.168.1.0/30
192.168.1.1
192.168.1.2
```

Summarize a block:

```sh
$ cidr-utils --info 192.168.1.0/24
192.168.1.0/24
  network:   192.168.1.0
  broadcast: 192.168.1.255
  netmask:   255.255.255.0
  prefix:    /24
  addresses: 256
  hosts:     254
```

Ranges, shorthand, counts, and membership:

```sh
cidr-utils 10.0.0.1-10.0.0.50      # explicit range
cidr-utils 10.0.0.1-50             # last-octet shorthand
cidr-utils --count 10.0.0.0/8      # 16777216
cidr-utils --contains 10.1.2.3 10.0.0.0/8   # prints the matching target
```

**Exit codes:** `0` success · `1` `--contains` matched nothing · `2` a target
failed to parse.

## Usage (library)

```rust
use cidr_utils::IpSet;

// One entry point for every target shape.
let net: IpSet = "192.168.1.0/30".parse().unwrap();
assert_eq!(net.count(), 4);

// `.hosts()` drops the network and broadcast addresses for IPv4 blocks.
let hosts: Vec<_> = net.hosts().map(|a| a.to_string()).collect();
assert_eq!(hosts, ["192.168.1.1", "192.168.1.2"]);

// Ranges and bare addresses parse the same way.
let range: IpSet = "10.0.0.1-5".parse().unwrap();
assert_eq!(range.count(), 5);
```

When you know the address family, the concrete types expose the full surface:

```rust
use cidr_utils::Ipv4Cidr;
use std::net::Ipv4Addr;

let block: Ipv4Cidr = "192.168.0.0/24".parse().unwrap();
assert_eq!(block.network(), Ipv4Addr::new(192, 168, 0, 0));
assert_eq!(block.broadcast(), Ipv4Addr::new(192, 168, 0, 255));
assert_eq!(block.netmask(), Ipv4Addr::new(255, 255, 255, 0));
assert_eq!(block.host_count(), 254);
assert!(block.contains(Ipv4Addr::new(192, 168, 0, 50)));
```

`Ipv6Cidr`, `Ipv4Range`, `Ipv6Range`, and the family-agnostic `IpCidr` /
`IpRange` / `IpSet` enums round out the API. Enable the `serde` feature to
derive `Serialize`/`Deserialize` on all of them.

## More capabilities

```rust
use cidr_utils::{Ipv4Cidr, Ipv4Range};

// Walk the block hierarchy.
let block: Ipv4Cidr = "192.168.1.0/24".parse().unwrap();
assert_eq!(block.subnets(26).count(), 4);
assert_eq!(block.supernet().unwrap(), "192.168.1.0/23".parse().unwrap());

// Decompose an arbitrary range into aligned CIDR blocks.
let r: Ipv4Range = "192.168.1.0-192.168.1.130".parse().unwrap();
let cidrs: Vec<_> = r.to_cidrs().iter().map(|c| c.to_string()).collect();
assert_eq!(cidrs, ["192.168.1.0/25", "192.168.1.128/31", "192.168.1.130/32"]);

// Merge a messy list of blocks into the minimal set.
let blocks: Vec<Ipv4Cidr> = ["10.0.0.0/25", "10.0.0.128/25", "10.0.1.0/24"]
    .iter().map(|s| s.parse().unwrap()).collect();
let merged: Vec<_> = Ipv4Cidr::aggregate(&blocks).iter().map(|c| c.to_string()).collect();
assert_eq!(merged, ["10.0.0.0/23"]);

// Classify and inspect.
assert!("10.0.0.0/8".parse::<Ipv4Cidr>().unwrap().is_private());
assert_eq!(block.wildcard().to_string(), "0.0.0.255");
```

Subtract, split, and index blocks:

```rust
use cidr_utils::Ipv4Cidr;

// CIDR subtraction: what's left of a /24 after removing a /26?
let block: Ipv4Cidr = "10.0.0.0/24".parse().unwrap();
let hole: Ipv4Cidr = "10.0.0.64/26".parse().unwrap();
let rest: Vec<_> = block.exclude(&hole).iter().map(|c| c.to_string()).collect();
assert_eq!(rest, ["10.0.0.0/26", "10.0.0.128/25"]);

// Halve a block, count subnets without enumerating, index in O(1).
let (lo, hi) = block.split().unwrap();
assert_eq!((lo.to_string(), hi.to_string()),
           ("10.0.0.0/25".into(), "10.0.0.128/25".into()));
assert_eq!(block.subnet_count(28), 16);
assert_eq!(block.nth_address(10).unwrap().to_string(), "10.0.0.10");
```

Address iterators are double-ended, so you can walk a block from the top:

```rust
use cidr_utils::Ipv4Cidr;
let c: Ipv4Cidr = "10.0.0.0/30".parse().unwrap();
let top = c.addresses().next_back().unwrap();
assert_eq!(top.to_string(), "10.0.0.3");
```

The CLI exposes the same: `--cidrs` (decompose), `--aggregate` (merge),
`--split <PREFIX>` (subnet), `--exclude <CIDR>` (subtract), `--reverse`,
`--total`, `--json`, and `--info` (with wildcard mask and address class).

Set algebra and supernet:

```rust
use cidr_utils::{aggregate_max_prefix, IpCidr, IpSet, Ipv4Cidr};

// Climb to a specific enclosing block in one step.
let c: Ipv4Cidr = "10.20.30.0/24".parse().unwrap();
assert_eq!(c.supernet_at(16).unwrap().to_string(), "10.20.0.0/16");

// Overlap of two targets (always a range).
let a: IpSet = "10.0.0.0/24".parse().unwrap();
let b: IpSet = "10.0.0.128/26".parse().unwrap();
let i = a.intersection(&b).unwrap();
assert_eq!(i.count(), 64);

// Aggregate, but never produce a block shorter than /23.
let inputs: Vec<IpCidr> = ["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
    .iter().map(|s| s.parse().unwrap()).collect();
let capped = aggregate_max_prefix(&inputs, 23, 0);
assert_eq!(capped.len(), 2); // two /23s, not one /22
```

VLSM allocator:

```rust
use cidr_utils::Ipv4Cidr;
let parent: Ipv4Cidr = "192.168.1.0/24".parse().unwrap();
let allocs = parent.vlsm_allocate(&[60, 30, 12, 4]).unwrap();
assert_eq!(allocs[0].prefix_len(), 26);
assert_eq!(allocs[3].prefix_len(), 29);
```

From the CLI:

```sh
cidr-utils --supernet 16 10.20.30.0/24
cidr-utils --intersect 10.0.0.128/26 10.0.0.0/24
cidr-utils --vlsm 60,30,12,4 192.168.1.0/24
```

## Design notes

- **No networking.** This crate is pure address arithmetic; it never resolves
  names or touches a socket. That makes it safe to use in build scripts and
  hot loops.
- **Canonical blocks.** Constructing a CIDR masks off the host bits, so
  `192.168.1.77/24` and `192.168.1.0/24` compare equal.
- **Counts are `u128`.** Address counts saturate to `u128::MAX` only for the
  IPv6 `/0`, whose true size (`2^128`) does not fit.
- **`#![forbid(unsafe_code)]`.**

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at
your option.
