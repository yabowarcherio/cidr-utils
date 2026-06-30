//! Command-line interface for `cidr-utils`.
//!
//! ```text
//! cidr-utils 192.168.1.0/24
//! cidr-utils --count 10.0.0.0/8
//! cidr-utils --info 192.168.1.0/30
//! cidr-utils --contains 192.168.1.5 192.168.1.0/24
//! ```

use std::io::{self, BufRead, Write};
use std::net::IpAddr;
use std::process::ExitCode;
use std::str::FromStr;

use cidr_utils::{IpCidr, IpSet, Ipv4Cidr, Ipv6Cidr};
use clap::Parser;

/// Parse, enumerate, and test IPv4/IPv6 CIDR blocks and address ranges.
#[derive(Parser, Debug)]
#[command(
    name = "cidr-utils",
    version,
    about,
    long_about = None,
    after_help = "TARGETs may be a CIDR block (192.168.1.0/24), a range \
                  (192.168.1.1-50), or a bare address. Use `-` to read targets \
                  from stdin, one per line."
)]
struct Cli {
    /// CIDR blocks, ranges, or addresses. Use `-` to read from stdin.
    #[arg(value_name = "TARGET", required = true)]
    targets: Vec<String>,

    /// Print the number of addresses instead of listing them.
    #[arg(short, long, conflicts_with_all = ["info", "contains"])]
    count: bool,

    /// Print a summary (network, broadcast, mask, count) for each target.
    #[arg(short, long, conflicts_with_all = ["count", "contains"])]
    info: bool,

    /// Include the network and broadcast addresses when listing (IPv4 blocks).
    #[arg(short, long)]
    all: bool,

    /// Stop after listing this many addresses per target (0 = no limit).
    #[arg(short, long, value_name = "N", default_value_t = 0)]
    limit: u64,

    /// Test whether the given address is contained in any target, then exit.
    #[arg(long, value_name = "IP")]
    contains: Option<IpAddr>,

    /// Print each target as its minimal set of aligned CIDR blocks.
    #[arg(long, conflicts_with_all = ["count", "info", "contains"])]
    cidrs: bool,

    /// Merge all targets into the minimal equivalent set of CIDR blocks.
    #[arg(long, conflicts_with_all = ["count", "info", "contains", "cidrs"])]
    aggregate: bool,

    /// Split each target into sub-blocks of this prefix length.
    #[arg(long, value_name = "PREFIX", conflicts_with_all = ["count", "info", "contains", "cidrs", "aggregate"])]
    split: Option<u8>,

    /// Subtract this CIDR block from each target, printing the remaining blocks.
    #[arg(long, value_name = "CIDR", conflicts_with_all = ["count", "info", "contains", "cidrs", "aggregate", "split"])]
    exclude: Option<IpCidr>,

    /// Print the enclosing CIDR block of length PREFIX for each target's
    /// underlying CIDR. Targets that are ranges (or whose underlying prefix
    /// is shorter) are skipped with a stderr note.
    #[arg(long, value_name = "PREFIX", conflicts_with_all = ["count", "info", "contains", "cidrs", "aggregate", "split", "exclude"])]
    supernet: Option<u8>,

    /// Allocate sub-blocks satisfying these comma-separated host-count
    /// requirements, packed largest-first into each IPv4 CIDR target. Output
    /// is one block per line, allocations grouped per target.
    #[arg(long, value_name = "N,N,...", conflicts_with_all = ["count", "info", "contains", "cidrs", "aggregate", "split", "exclude", "supernet"])]
    vlsm: Option<String>,

    /// Intersect this CIDR/range/address with each target, printing the
    /// overlap as `FIRST-LAST` (one line per target). Disjoint targets are
    /// dropped silently.
    #[arg(long, value_name = "TARGET", conflicts_with_all = ["count", "info", "contains", "cidrs", "aggregate", "split", "exclude", "supernet", "vlsm"])]
    intersect: Option<String>,

    /// List addresses from highest to lowest instead of lowest to highest.
    #[arg(short, long)]
    reverse: bool,

    /// Print the total number of addresses across all targets, then exit.
    #[arg(long, conflicts_with_all = ["count", "info", "contains", "cidrs", "aggregate", "split", "exclude"])]
    total: bool,

    /// Emit a JSON summary (kind, family, first, last, count, cidrs) per target.
    #[arg(long, conflicts_with_all = ["count", "info", "contains", "cidrs", "aggregate", "split", "exclude", "total"])]
    json: bool,
}

/// Expand the target list, replacing a `-` with lines read from stdin.
fn collect_targets(args: &[String]) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    for a in args {
        if a == "-" {
            for line in io::stdin().lock().lines() {
                let line = line?;
                let t = line.trim();
                if !t.is_empty() && !t.starts_with('#') {
                    out.push(t.to_string());
                }
            }
        } else {
            out.push(a.clone());
        }
    }
    Ok(out)
}

/// A short label describing where an IPv4 block sits in the address space.
fn ipv4_class(c: &Ipv4Cidr) -> &'static str {
    if c.is_private() {
        "private"
    } else if c.is_loopback() {
        "loopback"
    } else if c.is_link_local() {
        "link-local"
    } else if c.is_documentation() {
        "documentation"
    } else if c.is_multicast() {
        "multicast"
    } else {
        "global"
    }
}

/// Print the per-target summary used by `--info`.
fn print_info(out: &mut impl Write, target: &str, set: &IpSet) {
    let _ = writeln!(out, "{target}");
    match set {
        IpSet::Cidr(IpCidr::V4(c)) => {
            let _ = writeln!(out, "  network:   {}", c.network());
            let _ = writeln!(out, "  broadcast: {}", c.broadcast());
            let _ = writeln!(out, "  netmask:   {}", c.netmask());
            let _ = writeln!(out, "  wildcard:  {}", c.wildcard());
            let _ = writeln!(out, "  prefix:    /{}", c.prefix_len());
            let _ = writeln!(out, "  addresses: {}", c.address_count());
            let _ = writeln!(out, "  hosts:     {}", c.host_count());
            let _ = writeln!(out, "  class:     {}", ipv4_class(c));
        }
        IpSet::Cidr(IpCidr::V6(c)) => {
            let _ = writeln!(out, "  network:   {}", c.network());
            let _ = writeln!(out, "  last:      {}", c.last_address());
            let _ = writeln!(out, "  prefix:    /{}", c.prefix_len());
            let _ = writeln!(out, "  addresses: {}", c.address_count());
        }
        IpSet::Range(r) => {
            let _ = writeln!(out, "  start:     {}", r.start());
            let _ = writeln!(out, "  end:       {}", r.end());
            let _ = writeln!(out, "  addresses: {}", r.count());
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let targets = match collect_targets(&cli.targets) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("cidr-utils: failed to read stdin: {e}");
            return ExitCode::from(2);
        }
    };

    // Parse every target up front so a bad one fails fast with exit code 2.
    let mut parsed = Vec::with_capacity(targets.len());
    for t in &targets {
        match IpSet::from_str(t) {
            Ok(set) => parsed.push((t.as_str(), set)),
            Err(e) => {
                eprintln!("cidr-utils: {t:?}: {e}");
                return ExitCode::from(2);
            }
        }
    }

    let stdout = io::stdout();
    let mut out = stdout.lock();

    if let Some(needle) = cli.contains {
        let mut any = false;
        for (t, set) in &parsed {
            if set.contains(needle) {
                let _ = writeln!(out, "{t}");
                any = true;
            }
        }
        return if any {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }

    if cli.info {
        for (t, set) in &parsed {
            print_info(&mut out, t, set);
        }
        return ExitCode::SUCCESS;
    }

    if cli.count {
        for (_, set) in &parsed {
            let _ = writeln!(out, "{}", set.count());
        }
        return ExitCode::SUCCESS;
    }

    if cli.total {
        let sum: u128 = parsed.iter().map(|(_, set)| set.count()).sum();
        let _ = writeln!(out, "{sum}");
        return ExitCode::SUCCESS;
    }

    if cli.json {
        let arr: Vec<serde_json::Value> = parsed
            .iter()
            .map(|(t, set)| {
                serde_json::json!({
                    "target": t,
                    "kind": if set.is_cidr() { "cidr" } else { "range" },
                    "family": if set.first().is_ipv4() { "v4" } else { "v6" },
                    "first": set.first().to_string(),
                    "last": set.last().to_string(),
                    // Count is a string: a u128 can exceed JSON's safe integers.
                    "count": set.count().to_string(),
                    "cidrs": set.to_cidrs().iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                })
            })
            .collect();
        let _ = writeln!(out, "{}", serde_json::to_string_pretty(&arr).unwrap());
        return ExitCode::SUCCESS;
    }

    if cli.cidrs {
        for (_, set) in &parsed {
            for cidr in set.to_cidrs() {
                let _ = writeln!(out, "{cidr}");
            }
        }
        return ExitCode::SUCCESS;
    }

    if cli.aggregate {
        // Split by family, aggregate each, then print v4 blocks before v6.
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        for (_, set) in &parsed {
            for cidr in set.to_cidrs() {
                match cidr {
                    IpCidr::V4(c) => v4.push(c),
                    IpCidr::V6(c) => v6.push(c),
                }
            }
        }
        for c in Ipv4Cidr::aggregate(&v4) {
            let _ = writeln!(out, "{c}");
        }
        for c in Ipv6Cidr::aggregate(&v6) {
            let _ = writeln!(out, "{c}");
        }
        return ExitCode::SUCCESS;
    }

    if let Some(prefix) = cli.split {
        for (_, set) in &parsed {
            for cidr in set.to_cidrs() {
                match cidr {
                    IpCidr::V4(c) => {
                        for sub in c.subnets(prefix) {
                            let _ = writeln!(out, "{sub}");
                        }
                    }
                    IpCidr::V6(c) => {
                        for sub in c.subnets(prefix) {
                            let _ = writeln!(out, "{sub}");
                        }
                    }
                }
            }
        }
        return ExitCode::SUCCESS;
    }

    if let Some(hole) = cli.exclude {
        for (_, set) in &parsed {
            for cidr in set.to_cidrs() {
                for remaining in cidr.exclude(&hole) {
                    let _ = writeln!(out, "{remaining}");
                }
            }
        }
        return ExitCode::SUCCESS;
    }

    if let Some(spec) = &cli.intersect {
        let other = match IpSet::from_str(spec) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("cidr-utils: bad --intersect target {spec:?}: {e}");
                return ExitCode::from(2);
            }
        };
        for (_, set) in &parsed {
            if let Some(overlap) = set.intersection(&other) {
                let _ = writeln!(out, "{}-{}", overlap.first(), overlap.last());
            }
        }
        return ExitCode::SUCCESS;
    }

    if let Some(spec) = &cli.vlsm {
        // Parse "60,30,12,6" into a Vec<u32>.
        let needs: Result<Vec<u32>, _> = spec.split(',').map(|s| s.trim().parse::<u32>()).collect();
        let needs = match needs {
            Ok(v) if !v.is_empty() => v,
            Ok(_) => {
                eprintln!("cidr-utils: --vlsm requires at least one host count");
                return ExitCode::from(2);
            }
            Err(e) => {
                eprintln!("cidr-utils: bad --vlsm spec {spec:?}: {e}");
                return ExitCode::from(2);
            }
        };
        let mut bad = false;
        for (target, set) in &parsed {
            let Some(IpCidr::V4(parent)) = set.as_cidr() else {
                eprintln!("cidr-utils: {target}: --vlsm requires an IPv4 CIDR target");
                bad = true;
                continue;
            };
            match parent.vlsm_allocate(&needs) {
                Some(allocs) => {
                    for c in allocs {
                        let _ = writeln!(out, "{c}");
                    }
                }
                None => {
                    eprintln!("cidr-utils: {target}: requested host counts don't fit");
                    bad = true;
                }
            }
        }
        return if bad {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        };
    }

    if let Some(prefix) = cli.supernet {
        let mut bad = false;
        for (target, set) in &parsed {
            let Some(c) = set.as_cidr() else {
                eprintln!("cidr-utils: {target}: --supernet requires a CIDR target");
                bad = true;
                continue;
            };
            match c.supernet_at(prefix) {
                Some(s) => {
                    let _ = writeln!(out, "{s}");
                }
                None => {
                    eprintln!(
                        "cidr-utils: {target}: prefix /{prefix} is longer than /{}",
                        c.prefix_len()
                    );
                    bad = true;
                }
            }
        }
        return if bad {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        };
    }

    // Default: list addresses, one per line.
    for (_, set) in &parsed {
        let base = if cli.all {
            set.addresses()
        } else {
            set.hosts()
        };
        let iter: Box<dyn Iterator<Item = IpAddr>> = if cli.reverse {
            Box::new(base.rev())
        } else {
            Box::new(base)
        };
        for (printed, addr) in iter.enumerate() {
            if cli.limit != 0 && printed as u64 >= cli.limit {
                break;
            }
            if writeln!(out, "{addr}").is_err() {
                // Broken pipe (e.g. piped into `head`): stop quietly.
                return ExitCode::SUCCESS;
            }
        }
    }

    ExitCode::SUCCESS
}
