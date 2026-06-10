//! Round-trip tests for the optional `serde` feature.
#![cfg(feature = "serde")]

use cidr_utils::{IpCidr, IpRange, IpSet, Ipv4Cidr};

#[test]
fn ipv4_cidr_json_round_trip() {
    let c: Ipv4Cidr = "192.168.1.0/24".parse().unwrap();
    let json = serde_json::to_string(&c).unwrap();
    let back: Ipv4Cidr = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn ipcidr_json_round_trip() {
    let c: IpCidr = "2001:db8::/32".parse().unwrap();
    let back: IpCidr = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
    assert_eq!(c, back);
}

#[test]
fn iprange_json_round_trip() {
    let r: IpRange = "10.0.0.1-10.0.0.9".parse().unwrap();
    let back: IpRange = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
    assert_eq!(r, back);
}

#[test]
fn ipset_json_round_trip() {
    let s: IpSet = "192.168.0.0/30".parse().unwrap();
    let back: IpSet = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
    assert_eq!(s, back);
}
