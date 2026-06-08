# Contributing to cidr-utils

Thanks for taking the time to contribute! This is a small, focused crate, so
the bar is mostly "keep it pure, correct, and well-tested."

## Getting started

```sh
git clone https://github.com/yabowarcherio/cidr-utils
cd cidr-utils
cargo test
```

You need a recent stable Rust toolchain (see `rust-version` in
[`Cargo.toml`](Cargo.toml) for the minimum supported version, MSRV).

## Before you open a PR

Please make sure the following all pass locally — CI runs the same checks:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --no-default-features        # library-only must still build
cargo deny check                         # licenses & advisories (if installed)
```

## Guidelines

- **No networking, ever.** This crate is pure address arithmetic. Do not add a
  dependency or code path that resolves names or opens sockets.
- **No `unsafe`.** The crate sets `#![forbid(unsafe_code)]`; keep it that way.
- **Add a test** for any behavior change. Edge cases worth covering: `/0`,
  `/31`, `/32`, the IPv6 `/0` count saturation, range shorthand, and
  mixed-family errors.
- **Mind both families.** Logic shared between IPv4 and IPv6 lives in the
  `define_cidr!` / `define_range!` macros; family-specific behavior (IPv4
  broadcast, host conventions) is written by hand alongside.
- **Document public items.** `missing_docs` is a warning; keep the API
  documented.

## Reporting bugs

Open an issue with the input you used, what you expected, and what happened.
A failing parse or an off-by-one in enumeration is always worth a report.

## Code of Conduct

Be kind and constructive. We follow the spirit of the
[Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct).
