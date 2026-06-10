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
