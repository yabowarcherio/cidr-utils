//! Library integration tests for `cidr-utils`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use cidr_utils::{IpCidr, IpRange, IpSet, Ipv4Cidr, Ipv4Range, Ipv6Cidr, ParseError};

// --- IPv4 CIDR ------------------------------------------------------------

#[test]
fn ipv4_cidr_basic_accessors() {
    let c: Ipv4Cidr = "192.168.1.0/24".parse().unwrap();
    assert_eq!(c.network(), Ipv4Addr::new(192, 168, 1, 0));
    assert_eq!(c.broadcast(), Ipv4Addr::new(192, 168, 1, 255));
    assert_eq!(c.netmask(), Ipv4Addr::new(255, 255, 255, 0));
    assert_eq!(c.last_address(), c.broadcast());
    assert_eq!(c.prefix_len(), 24);
    assert_eq!(c.address_count(), 256);
    assert_eq!(c.host_count(), 254);
}

#[test]
fn ipv4_cidr_masks_host_bits() {
    // A non-canonical address is normalized to its network on construction.
    let c: Ipv4Cidr = "192.168.1.77/24".parse().unwrap();
    assert_eq!(c.network(), Ipv4Addr::new(192, 168, 1, 0));
    assert_eq!(c, "192.168.1.0/24".parse().unwrap());
}

#[test]
fn ipv4_cidr_contains() {
    let c: Ipv4Cidr = "10.0.0.0/8".parse().unwrap();
    assert!(c.contains(Ipv4Addr::new(10, 1, 2, 3)));
    assert!(!c.contains(Ipv4Addr::new(11, 0, 0, 1)));
}

#[test]
fn ipv4_hosts_excludes_network_and_broadcast() {
    let c: Ipv4Cidr = "192.168.1.0/30".parse().unwrap();
    let hosts: Vec<_> = c.hosts().collect();
    assert_eq!(
        hosts,
        vec![Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(192, 168, 1, 2)]
    );
}

#[test]
fn ipv4_addresses_includes_all() {
    let c: Ipv4Cidr = "192.168.1.0/30".parse().unwrap();
    assert_eq!(c.addresses().count(), 4);
}

#[test]
fn ipv4_slash31_and_slash32() {
    let p2p: Ipv4Cidr = "10.0.0.0/31".parse().unwrap();
    assert_eq!(p2p.host_count(), 2);
    assert_eq!(p2p.hosts().count(), 2);

    let host: Ipv4Cidr = "10.0.0.5/32".parse().unwrap();
    assert_eq!(host.host_count(), 1);
    assert_eq!(
        host.hosts().collect::<Vec<_>>(),
        vec![Ipv4Addr::new(10, 0, 0, 5)]
    );
    assert_eq!(host.broadcast(), Ipv4Addr::new(10, 0, 0, 5));
}

#[test]
fn ipv4_slash0_counts_whole_space() {
    let all: Ipv4Cidr = "0.0.0.0/0".parse().unwrap();
    assert_eq!(all.address_count(), 1u128 << 32);
    assert_eq!(all.netmask(), Ipv4Addr::new(0, 0, 0, 0));
    assert!(all.contains(Ipv4Addr::new(8, 8, 8, 8)));
}

// --- IPv6 CIDR ------------------------------------------------------------

#[test]
fn ipv6_cidr_basics() {
    let c: Ipv6Cidr = "2001:db8::/120".parse().unwrap();
    assert_eq!(c.prefix_len(), 120);
    assert_eq!(c.address_count(), 256);
    assert!(c.contains("2001:db8::ff".parse::<Ipv6Addr>().unwrap()));
    assert!(!c.contains("2001:db8::1:0".parse::<Ipv6Addr>().unwrap()));
}

#[test]
fn ipv6_slash0_saturates_count() {
    let all: Ipv6Cidr = "::/0".parse().unwrap();
    assert_eq!(all.address_count(), u128::MAX);
}

// --- Ranges ---------------------------------------------------------------

#[test]
fn ipv4_range_full_and_shorthand() {
    let full: Ipv4Range = "192.168.1.1-192.168.1.50".parse().unwrap();
    let short: Ipv4Range = "192.168.1.1-50".parse().unwrap();
    assert_eq!(full, short);
    assert_eq!(full.count(), 50);
    assert_eq!(full.start(), Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(full.end(), Ipv4Addr::new(192, 168, 1, 50));
    assert!(full.contains(Ipv4Addr::new(192, 168, 1, 25)));
    assert!(!full.contains(Ipv4Addr::new(192, 168, 1, 51)));
}

#[test]
fn ipv4_range_iter_is_inclusive() {
    let r: Ipv4Range = "10.0.0.1-10.0.0.3".parse().unwrap();
    let addrs: Vec<_> = r.iter().collect();
    assert_eq!(
        addrs,
        vec![
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 3),
        ]
    );
}

#[test]
fn range_start_after_end_is_error() {
    let err = "10.0.0.5-10.0.0.1".parse::<Ipv4Range>().unwrap_err();
    assert_eq!(err, ParseError::StartAfterEnd);
}

#[test]
fn iprange_rejects_mixed_families() {
    let v4: IpAddr = "1.2.3.4".parse().unwrap();
    let v6: IpAddr = "::1".parse().unwrap();
    assert_eq!(IpRange::new(v4, v6).unwrap_err(), ParseError::MixedFamilies);
}

// --- IpSet (top-level entry point) ---------------------------------------

#[test]
fn ipset_parses_all_three_forms() {
    let cidr: IpSet = "192.168.0.0/24".parse().unwrap();
    let range: IpSet = "192.168.0.10-20".parse().unwrap();
    let single: IpSet = "192.168.0.5".parse().unwrap();

    assert_eq!(cidr.count(), 256);
    assert_eq!(range.count(), 11);
    assert_eq!(single.count(), 1);

    assert!(matches!(cidr, IpSet::Cidr(_)));
    assert!(matches!(range, IpSet::Range(_)));
    assert!(matches!(single, IpSet::Cidr(_)));
}

#[test]
fn ipset_hosts_vs_addresses() {
    let set: IpSet = "192.168.1.0/30".parse().unwrap();
    assert_eq!(set.hosts().count(), 2);
    assert_eq!(set.addresses().count(), 4);
}

#[test]
fn ipset_single_host_yields_itself() {
    let set: IpSet = "10.0.0.42".parse().unwrap();
    let hosts: Vec<_> = set.hosts().collect();
    assert_eq!(hosts, vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42))]);
}

#[test]
fn ipset_contains() {
    let set: IpSet = "10.0.0.0/24".parse().unwrap();
    assert!(set.contains("10.0.0.99".parse().unwrap()));
    assert!(!set.contains("10.0.1.0".parse().unwrap()));
    // Wrong family never matches.
    assert!(!set.contains("::1".parse().unwrap()));
}

// --- Display round-trips and errors --------------------------------------

#[test]
fn display_round_trips() {
    for s in ["192.168.1.0/24", "2001:db8::/32"] {
        let c: IpCidr = s.parse().unwrap();
        assert_eq!(c.to_string(), s);
    }
    let r: IpRange = "10.0.0.1-10.0.0.5".parse().unwrap();
    assert_eq!(r.to_string(), "10.0.0.1-10.0.0.5");
}

#[test]
fn parse_errors_are_typed() {
    assert_eq!("".parse::<IpSet>().unwrap_err(), ParseError::Empty);
    assert!(matches!(
        "10.0.0.0/99".parse::<Ipv4Cidr>().unwrap_err(),
        ParseError::BadPrefix(_)
    ));
    assert!(matches!(
        "999.0.0.0/8".parse::<Ipv4Cidr>().unwrap_err(),
        ParseError::BadAddr(_)
    ));
}

// --- Subnetting -----------------------------------------------------------

#[test]
fn supernet_walks_up_one_bit() {
    let c: Ipv4Cidr = "192.168.1.128/25".parse().unwrap();
    let parent = c.supernet().unwrap();
    assert_eq!(parent, "192.168.1.0/24".parse().unwrap());
    // A /0 has no parent.
    assert!("0.0.0.0/0"
        .parse::<Ipv4Cidr>()
        .unwrap()
        .supernet()
        .is_none());
}

#[test]
fn subnets_splits_into_children() {
    let c: Ipv4Cidr = "192.168.1.0/24".parse().unwrap();
    let kids: Vec<Ipv4Cidr> = c.subnets(26).collect();
    assert_eq!(kids.len(), 4);
    assert_eq!(kids[0], "192.168.1.0/26".parse().unwrap());
    assert_eq!(kids[1], "192.168.1.64/26".parse().unwrap());
    assert_eq!(kids[2], "192.168.1.128/26".parse().unwrap());
    assert_eq!(kids[3], "192.168.1.192/26".parse().unwrap());
}

#[test]
fn subnets_same_prefix_is_self() {
    let c: Ipv4Cidr = "10.0.0.0/8".parse().unwrap();
    let kids: Vec<_> = c.subnets(8).collect();
    assert_eq!(kids, vec![c]);
}

#[test]
fn subnets_invalid_prefix_is_empty() {
    let c: Ipv4Cidr = "10.0.0.0/8".parse().unwrap();
    assert_eq!(c.subnets(4).count(), 0); // shorter than self
    assert_eq!(c.subnets(33).count(), 0); // out of range
}

#[test]
fn subnets_ipv6() {
    let c: Ipv6Cidr = "2001:db8::/32".parse().unwrap();
    assert_eq!(c.subnets(34).count(), 4);
}

#[test]
fn subnet_supernet_predicates() {
    let big: Ipv4Cidr = "10.0.0.0/8".parse().unwrap();
    let small: Ipv4Cidr = "10.1.2.0/24".parse().unwrap();
    assert!(big.contains_subnet(&small));
    assert!(big.is_supernet_of(&small));
    assert!(small.is_subnet_of(&big));
    assert!(!small.is_supernet_of(&big));

    let other: Ipv4Cidr = "11.0.0.0/24".parse().unwrap();
    assert!(!big.contains_subnet(&other));

    // A block always contains itself.
    assert!(big.contains_subnet(&big));
}

#[test]
fn overlaps_detects_intersection() {
    let a: Ipv4Cidr = "10.0.0.0/24".parse().unwrap();
    let nested: Ipv4Cidr = "10.0.0.128/25".parse().unwrap();
    let disjoint: Ipv4Cidr = "10.0.1.0/24".parse().unwrap();
    assert!(a.overlaps(&nested));
    assert!(nested.overlaps(&a));
    assert!(!a.overlaps(&disjoint));
    assert!(a.overlaps(&a));
}

#[test]
fn cidrs_sort_by_network_then_prefix() {
    let mut v: Vec<Ipv4Cidr> = ["10.0.0.0/24", "10.0.0.0/25", "10.0.0.0/8", "192.168.0.0/16"]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
    v.sort();
    let got: Vec<String> = v.iter().map(|c| c.to_string()).collect();
    assert_eq!(
        got,
        vec!["10.0.0.0/8", "10.0.0.0/24", "10.0.0.0/25", "192.168.0.0/16"]
    );
}

#[test]
fn wildcard_and_host_bounds() {
    let c: Ipv4Cidr = "192.168.1.0/24".parse().unwrap();
    assert_eq!(c.wildcard(), Ipv4Addr::new(0, 0, 0, 255));
    assert_eq!(c.first_host(), Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(c.last_host(), Ipv4Addr::new(192, 168, 1, 254));

    // /32: first and last host are the address itself.
    let h: Ipv4Cidr = "10.0.0.5/32".parse().unwrap();
    assert_eq!(h.first_host(), Ipv4Addr::new(10, 0, 0, 5));
    assert_eq!(h.last_host(), Ipv4Addr::new(10, 0, 0, 5));
    assert_eq!(h.wildcard(), Ipv4Addr::new(0, 0, 0, 0));
}

#[test]
fn parses_dotted_netmask_form() {
    let from_mask: Ipv4Cidr = "192.168.1.0/255.255.255.0".parse().unwrap();
    assert_eq!(from_mask, "192.168.1.0/24".parse().unwrap());

    let slash30: Ipv4Cidr = "10.0.0.0/255.255.255.252".parse().unwrap();
    assert_eq!(slash30.prefix_len(), 30);

    // A non-contiguous mask is rejected.
    assert!(matches!(
        "10.0.0.0/255.0.255.0".parse::<Ipv4Cidr>().unwrap_err(),
        ParseError::BadPrefix(_)
    ));
}

#[test]
fn ipv4_classification() {
    let private: Ipv4Cidr = "10.0.0.0/8".parse().unwrap();
    assert!(private.is_private());
    assert!(!private.is_loopback());

    assert!("127.0.0.0/8".parse::<Ipv4Cidr>().unwrap().is_loopback());
    assert!("169.254.0.0/16"
        .parse::<Ipv4Cidr>()
        .unwrap()
        .is_link_local());
    assert!("224.0.0.0/4".parse::<Ipv4Cidr>().unwrap().is_multicast());
    assert!("192.0.2.0/24"
        .parse::<Ipv4Cidr>()
        .unwrap()
        .is_documentation());
    assert!(!"8.8.8.0/24".parse::<Ipv4Cidr>().unwrap().is_private());
}

#[test]
fn ipv6_classification() {
    assert!("ff00::/8".parse::<Ipv6Cidr>().unwrap().is_multicast());
    assert!("::1/128".parse::<Ipv6Cidr>().unwrap().is_loopback());
    assert!("::/128".parse::<Ipv6Cidr>().unwrap().is_unspecified());
    assert!(!"2001:db8::/32".parse::<Ipv6Cidr>().unwrap().is_multicast());
}

#[test]
fn ipcidr_enum_surface() {
    let a: IpCidr = "10.0.0.0/8".parse().unwrap();
    let b: IpCidr = "10.1.2.0/24".parse().unwrap();
    assert!(a.contains_subnet(&b));
    assert!(a.overlaps(&b));
    assert_eq!(a.netmask(), "255.0.0.0".parse::<IpAddr>().unwrap());
    assert_eq!(
        b.supernet().unwrap(),
        "10.1.2.0/23".parse::<IpCidr>().unwrap()
    );

    // Cross-family comparisons are always false.
    let v6: IpCidr = "2001:db8::/32".parse().unwrap();
    assert!(!a.contains_subnet(&v6));
    assert!(!a.overlaps(&v6));
}

#[test]
fn range_to_cidrs_covers_exactly() {
    let r: Ipv4Range = "192.168.1.0-192.168.1.130".parse().unwrap();
    let cidrs = r.to_cidrs();
    // Reconstruct the covered address count and check it matches the range.
    let covered: u128 = cidrs.iter().map(|c| c.address_count()).sum();
    assert_eq!(covered, r.count());
    // Blocks must be non-overlapping and ascending.
    for w in cidrs.windows(2) {
        assert!(!w[0].overlaps(&w[1]));
        assert!(w[0] < w[1]);
    }
}

#[test]
fn range_to_cidrs_aligned_block_is_single() {
    let r: Ipv4Range = "10.0.0.0-10.0.0.255".parse().unwrap();
    let cidrs = r.to_cidrs();
    assert_eq!(cidrs.len(), 1);
    assert_eq!(cidrs[0], "10.0.0.0/24".parse().unwrap());
}

#[test]
fn range_to_cidrs_whole_space() {
    let r: Ipv4Range = "0.0.0.0-255.255.255.255".parse().unwrap();
    let cidrs = r.to_cidrs();
    assert_eq!(cidrs, vec!["0.0.0.0/0".parse().unwrap()]);
}

#[test]
fn aggregate_merges_siblings_and_contained() {
    let blocks: Vec<Ipv4Cidr> = ["10.0.0.0/25", "10.0.0.128/25", "10.0.0.0/24", "10.0.1.0/24"]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
    let merged = Ipv4Cidr::aggregate(&blocks);
    assert_eq!(merged, vec!["10.0.0.0/23".parse().unwrap()]);
}

#[test]
fn aggregate_keeps_disjoint_blocks() {
    let blocks: Vec<Ipv4Cidr> = ["10.0.0.0/24", "192.168.0.0/24"]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
    let merged = Ipv4Cidr::aggregate(&blocks);
    assert_eq!(merged.len(), 2);
}

#[test]
fn aggregate_empty_is_empty() {
    assert!(Ipv4Cidr::aggregate(&[]).is_empty());
}

#[test]
fn address_iter_size_hint_is_exact_for_ipv4() {
    let c: Ipv4Cidr = "10.0.0.0/24".parse().unwrap();
    assert_eq!(c.addresses().size_hint(), (256, Some(256)));
    // /0 has 2^32 addresses, which still fits usize on 64-bit targets.
    let all: Ipv4Cidr = "0.0.0.0/0".parse().unwrap();
    assert_eq!(
        all.addresses().size_hint(),
        (1usize << 32, Some(1usize << 32))
    );
}

#[test]
fn address_iter_size_hint_saturates_for_huge_ipv6() {
    let all: Ipv6Cidr = "::/0".parse().unwrap();
    let (lower, upper) = all.addresses().size_hint();
    assert_eq!(lower, usize::MAX);
    assert_eq!(upper, None);
}

#[test]
fn ipv6_range_to_cidrs_covers_exactly() {
    use cidr_utils::Ipv6Range;
    let r: Ipv6Range = "2001:db8::-2001:db8::1ff".parse().unwrap();
    let cidrs = r.to_cidrs();
    let covered: u128 = cidrs.iter().map(|c| c.address_count()).sum();
    assert_eq!(covered, r.count());
    for w in cidrs.windows(2) {
        assert!(w[0] < w[1]);
    }
}

#[test]
fn ipv6_range_to_cidrs_whole_space() {
    use cidr_utils::Ipv6Range;
    let r: Ipv6Range = "::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
        .parse()
        .unwrap();
    assert_eq!(r.to_cidrs(), vec!["::/0".parse().unwrap()]);
}

#[test]
fn iprange_to_cidrs_is_family_aware() {
    let v4: IpRange = "10.0.0.0-10.0.0.255".parse().unwrap();
    let c4 = v4.to_cidrs();
    assert_eq!(c4, vec!["10.0.0.0/24".parse::<IpCidr>().unwrap()]);
    assert!(c4.iter().all(|c| c.is_ipv4()));
}

#[test]
fn ipset_to_cidrs() {
    let cidr: IpSet = "10.0.0.0/24".parse().unwrap();
    assert_eq!(cidr.to_cidrs().len(), 1);

    let range: IpSet = "10.0.0.0-10.0.0.130".parse().unwrap();
    let cidrs = range.to_cidrs();
    let covered: u128 = cidrs.iter().map(|c| c.address_count()).sum();
    assert_eq!(covered, range.count());
}
