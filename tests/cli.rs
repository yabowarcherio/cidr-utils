//! Black-box tests for the `cidr-utils` binary.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cidr-utils"))
}

#[test]
fn lists_hosts_by_default() {
    let out = bin().arg("192.168.1.0/30").output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<_> = s.lines().collect();
    assert_eq!(lines, vec!["192.168.1.1", "192.168.1.2"]);
}

#[test]
fn all_flag_includes_network_and_broadcast() {
    let out = bin().args(["--all", "192.168.1.0/30"]).output().unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    assert_eq!(s.lines().count(), 4);
}

#[test]
fn count_flag_prints_number() {
    let out = bin().args(["--count", "10.0.0.0/8"]).output().unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    assert_eq!(s.trim(), "16777216");
}

#[test]
fn range_shorthand_works() {
    let out = bin().arg("10.0.0.1-3").output().unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    assert_eq!(s.lines().count(), 3);
}

#[test]
fn limit_caps_output() {
    let out = bin()
        .args(["--limit", "5", "10.0.0.0/24"])
        .output()
        .unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    assert_eq!(s.lines().count(), 5);
}

#[test]
fn contains_hit_exits_zero() {
    let out = bin()
        .args(["--contains", "192.168.1.5", "192.168.1.0/24"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("192.168.1.0/24"));
}

#[test]
fn contains_miss_exits_one() {
    let out = bin()
        .args(["--contains", "8.8.8.8", "192.168.1.0/24"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn bad_target_exits_two() {
    let out = bin().arg("not-a-network").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn info_reports_broadcast() {
    let out = bin().args(["--info", "192.168.1.0/24"]).output().unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("broadcast: 192.168.1.255"));
    assert!(s.contains("hosts:     254"));
}

#[test]
fn cidrs_flag_decomposes_range() {
    let out = bin()
        .args(["--cidrs", "10.0.0.0-10.0.0.130"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<_> = s.lines().collect();
    assert_eq!(lines, vec!["10.0.0.0/25", "10.0.0.128/31", "10.0.0.130/32"]);
}

#[test]
fn aggregate_flag_merges_targets() {
    let out = bin()
        .args(["--aggregate", "10.0.0.0/25", "10.0.0.128/25", "10.0.1.0/24"])
        .output()
        .unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    assert_eq!(s.lines().collect::<Vec<_>>(), vec!["10.0.0.0/23"]);
}

#[test]
fn split_flag_emits_subnets() {
    let out = bin()
        .args(["--split", "26", "192.168.1.0/24"])
        .output()
        .unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<_> = s.lines().collect();
    assert_eq!(
        lines,
        vec![
            "192.168.1.0/26",
            "192.168.1.64/26",
            "192.168.1.128/26",
            "192.168.1.192/26",
        ]
    );
}

#[test]
fn info_reports_wildcard_and_class() {
    let out = bin().args(["--info", "10.0.0.0/8"]).output().unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    assert!(s.contains("wildcard:  0.255.255.255"));
    assert!(s.contains("class:     private"));
}

#[test]
fn exclude_flag_subtracts_block() {
    let out = bin()
        .args(["--exclude", "10.0.0.0/25", "10.0.0.0/24"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    assert_eq!(s.lines().collect::<Vec<_>>(), vec!["10.0.0.128/25"]);
}

#[test]
fn reverse_flag_lists_descending() {
    let out = bin()
        .args(["--reverse", "192.168.1.0/30"])
        .output()
        .unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<_> = s.lines().collect();
    // Hosts of /30 are .1 and .2; reversed -> .2 then .1.
    assert_eq!(lines, vec!["192.168.1.2", "192.168.1.1"]);
}

#[test]
fn total_flag_sums_addresses() {
    let out = bin()
        .args(["--total", "10.0.0.0/24", "10.0.1.0/24"])
        .output()
        .unwrap();
    let s = String::from_utf8(out.stdout).unwrap();
    assert_eq!(s.trim(), "512");
}

#[test]
fn vlsm_flag_packs_classic_layout() {
    let out = bin()
        .args(["--vlsm", "60,30,12,4", "192.168.1.0/24"])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr={:?}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8(out.stdout).unwrap();
    let lines: Vec<&str> = s.lines().collect();
    assert_eq!(lines.len(), 4);
    // Each line is a CIDR; check the prefix length of each.
    let prefixes: Vec<u8> = lines
        .iter()
        .map(|l| l.split('/').next_back().unwrap().parse().unwrap())
        .collect();
    assert_eq!(prefixes, vec![26, 27, 28, 29]);
}

#[test]
fn vlsm_flag_rejects_overcommit() {
    // /29 has 8 addresses — two /29 requests can't fit.
    let out = bin()
        .args(["--vlsm", "6,6", "10.0.0.0/29"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("don't fit"), "stderr: {err}");
}

#[test]
fn vlsm_flag_rejects_ipv6_target() {
    let out = bin()
        .args(["--vlsm", "1", "2001:db8::/32"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("IPv4 CIDR"), "stderr: {err}");
}

#[test]
fn supernet_flag_climbs_to_named_prefix() {
    let out = bin()
        .args(["--supernet", "16", "10.20.30.0/24"])
        .output()
        .unwrap();
    assert!(out.status.success(), "stderr={:?}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8(out.stdout).unwrap();
    assert_eq!(s.trim(), "10.20.0.0/16");
}

#[test]
fn supernet_flag_rejects_longer_prefix() {
    let out = bin()
        .args(["--supernet", "25", "10.20.30.0/24"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("longer"), "stderr: {err}");
}

#[test]
fn supernet_flag_rejects_range_target() {
    let out = bin()
        .args(["--supernet", "16", "10.0.0.1-10.0.0.5"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(err.contains("requires a CIDR"), "stderr: {err}");
}

#[test]
fn json_flag_emits_summary() {
    let out = bin().args(["--json", "10.0.0.0/30"]).output().unwrap();
    assert!(out.status.success());
    let s = String::from_utf8(out.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(v[0]["kind"], "cidr");
    assert_eq!(v[0]["family"], "v4");
    assert_eq!(v[0]["count"], "4");
    assert_eq!(v[0]["first"], "10.0.0.0");
    assert_eq!(v[0]["last"], "10.0.0.3");
}
