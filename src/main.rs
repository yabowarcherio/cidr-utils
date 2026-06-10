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

use cidr_utils::{IpCidr, IpSet};
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

/// Print the per-target summary used by `--info`.
fn print_info(out: &mut impl Write, target: &str, set: &IpSet) {
    let _ = writeln!(out, "{target}");
    match set {
        IpSet::Cidr(IpCidr::V4(c)) => {
            let _ = writeln!(out, "  network:   {}", c.network());
            let _ = writeln!(out, "  broadcast: {}", c.broadcast());
            let _ = writeln!(out, "  netmask:   {}", c.netmask());
            let _ = writeln!(out, "  prefix:    /{}", c.prefix_len());
            let _ = writeln!(out, "  addresses: {}", c.address_count());
            let _ = writeln!(out, "  hosts:     {}", c.host_count());
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

    if cli.cidrs {
        for (_, set) in &parsed {
            for cidr in set.to_cidrs() {
                let _ = writeln!(out, "{cidr}");
            }
        }
        return ExitCode::SUCCESS;
    }

    // Default: list addresses, one per line.
    for (_, set) in &parsed {
        let iter = if cli.all {
            set.addresses()
        } else {
            set.hosts()
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
