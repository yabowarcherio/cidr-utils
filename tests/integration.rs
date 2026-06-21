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

#[test]
fn ipv6_aggregate_merges_siblings() {
    let blocks: Vec<Ipv6Cidr> = ["2001:db8::/33", "2001:db8:8000::/33"]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
    let merged = Ipv6Cidr::aggregate(&blocks);
    assert_eq!(merged, vec!["2001:db8::/32".parse().unwrap()]);
}

#[test]
fn ipset_first_and_last() {
    let cidr: IpSet = "192.168.1.0/24".parse().unwrap();
    assert_eq!(cidr.first(), "192.168.1.0".parse::<IpAddr>().unwrap());
    assert_eq!(cidr.last(), "192.168.1.255".parse::<IpAddr>().unwrap());

    let range: IpSet = "10.0.0.5-10.0.0.9".parse().unwrap();
    assert_eq!(range.first(), "10.0.0.5".parse::<IpAddr>().unwrap());
    assert_eq!(range.last(), "10.0.0.9".parse::<IpAddr>().unwrap());
}

// --- Reverse iteration ----------------------------------------------------

#[test]
fn addresses_iterate_in_reverse() {
    let c: Ipv4Cidr = "192.168.1.0/30".parse().unwrap();
    let rev: Vec<_> = c.addresses().rev().collect();
    assert_eq!(
        rev,
        vec![
            Ipv4Addr::new(192, 168, 1, 3),
            Ipv4Addr::new(192, 168, 1, 2),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 0),
        ]
    );
}

#[test]
fn double_ended_meets_in_middle() {
    let c: Ipv4Cidr = "10.0.0.0/29".parse().unwrap(); // 8 addresses
    let mut it = c.addresses();
    let first = it.next().unwrap();
    let last = it.next_back().unwrap();
    assert_eq!(first, Ipv4Addr::new(10, 0, 0, 0));
    assert_eq!(last, Ipv4Addr::new(10, 0, 0, 7));
    // The remaining six are yielded without duplication or omission.
    assert_eq!(it.count(), 6);
}

#[test]
fn hosts_reverse_excludes_network_broadcast() {
    let c: Ipv4Cidr = "192.168.1.0/29".parse().unwrap();
    let fwd: Vec<_> = c.hosts().collect();
    let mut rev: Vec<_> = c.hosts().rev().collect();
    rev.reverse();
    assert_eq!(fwd, rev);
}

// --- CIDR subtraction -----------------------------------------------------

#[test]
fn exclude_removes_subnet() {
    let block: Ipv4Cidr = "10.0.0.0/24".parse().unwrap();
    let hole: Ipv4Cidr = "10.0.0.64/26".parse().unwrap();
    let rest = block.exclude(&hole);
    // The remainder must cover exactly the block minus the hole.
    let covered: u128 = rest.iter().map(|c| c.address_count()).sum();
    assert_eq!(covered, block.address_count() - hole.address_count());
    // None of the remainder overlaps the hole.
    assert!(rest.iter().all(|c| !c.overlaps(&hole)));
    // And it is sorted.
    assert!(rest.windows(2).all(|w| w[0] < w[1]));
}

#[test]
fn exclude_disjoint_returns_self() {
    let block: Ipv4Cidr = "10.0.0.0/24".parse().unwrap();
    let other: Ipv4Cidr = "10.0.1.0/24".parse().unwrap();
    assert_eq!(block.exclude(&other), vec![block]);
}

#[test]
fn exclude_self_is_empty() {
    let block: Ipv4Cidr = "10.0.0.0/24".parse().unwrap();
    assert!(block.exclude(&block).is_empty());
}

#[test]
fn exclude_single_host_from_slash24() {
    let block: Ipv4Cidr = "192.168.1.0/24".parse().unwrap();
    let host: Ipv4Cidr = "192.168.1.50/32".parse().unwrap();
    let rest = block.exclude(&host);
    // Removing one host from a /24 leaves 8 blocks (/25../32).
    assert_eq!(rest.len(), 8);
    let covered: u128 = rest.iter().map(|c| c.address_count()).sum();
    assert_eq!(covered, 255);
}

#[test]
fn ipcidr_exclude_delegates_and_guards_family() {
    let block: IpCidr = "10.0.0.0/24".parse().unwrap();
    let hole: IpCidr = "10.0.0.0/25".parse().unwrap();
    let rest = block.exclude(&hole);
    assert_eq!(rest, vec!["10.0.0.128/25".parse::<IpCidr>().unwrap()]);

    // Cross-family removes nothing.
    let v6: IpCidr = "2001:db8::/32".parse().unwrap();
    assert_eq!(block.exclude(&v6), vec![block]);
}

#[test]
fn nth_address_indexes_block() {
    let c: Ipv4Cidr = "192.168.1.0/24".parse().unwrap();
    assert_eq!(c.nth_address(0), Some(Ipv4Addr::new(192, 168, 1, 0)));
    assert_eq!(c.nth_address(50), Some(Ipv4Addr::new(192, 168, 1, 50)));
    assert_eq!(c.nth_address(255), Some(Ipv4Addr::new(192, 168, 1, 255)));
    assert_eq!(c.nth_address(256), None);
    // Agrees with iteration.
    assert_eq!(c.nth_address(42), c.addresses().nth(42));
}

#[test]
fn nth_address_ipv6() {
    let c: Ipv6Cidr = "2001:db8::/120".parse().unwrap();
    assert_eq!(c.nth_address(255), c.addresses().next_back());
    assert_eq!(c.nth_address(256), None);
}

#[test]
fn split_halves_a_block() {
    let c: Ipv4Cidr = "10.0.0.0/24".parse().unwrap();
    let (lo, hi) = c.split().unwrap();
    assert_eq!(lo, "10.0.0.0/25".parse().unwrap());
    assert_eq!(hi, "10.0.0.128/25".parse().unwrap());
    // The two halves exactly partition the parent.
    assert_eq!(lo.address_count() + hi.address_count(), c.address_count());
    assert!(!lo.overlaps(&hi));

    // A single host cannot be split.
    assert!("10.0.0.1/32".parse::<Ipv4Cidr>().unwrap().split().is_none());
}

#[test]
fn subnet_count_matches_iteration() {
    let c: Ipv4Cidr = "10.0.0.0/16".parse().unwrap();
    assert_eq!(c.subnet_count(24), 256);
    assert_eq!(c.subnet_count(24), c.subnets(24).count() as u128);
    assert_eq!(c.subnet_count(16), 1); // same prefix
    assert_eq!(c.subnet_count(8), 0); // shorter
    assert_eq!(c.subnet_count(33), 0); // out of range
}

#[test]
fn ipcidr_iterates_addresses_and_hosts() {
    let c: IpCidr = "192.168.1.0/30".parse().unwrap();
    assert_eq!(c.addresses().count(), 4);
    assert_eq!(c.hosts().count(), 2);
    let first = c.addresses().next().unwrap();
    assert_eq!(first, "192.168.1.0".parse::<IpAddr>().unwrap());
}

#[test]
fn iprange_iterates_addresses() {
    let r: IpRange = "10.0.0.1-10.0.0.4".parse().unwrap();
    let v: Vec<_> = r.addresses().collect();
    assert_eq!(v.len(), 4);
    assert_eq!(v[0], "10.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(v[3], "10.0.0.4".parse::<IpAddr>().unwrap());
}

#[test]
fn ranges_sort_by_start_then_end() {
    let mut v: Vec<Ipv4Range> = ["10.0.0.5-10", "10.0.0.1-3", "10.0.0.1-9"]
        .iter()
        .map(|s| s.parse().unwrap())
        .collect();
    v.sort();
    let got: Vec<String> = v.iter().map(|r| r.to_string()).collect();
    assert_eq!(
        got,
        vec![
            "10.0.0.1-10.0.0.3",
            "10.0.0.1-10.0.0.9",
            "10.0.0.5-10.0.0.10"
        ]
    );
}

#[test]
fn ipset_predicates() {
    let single: IpSet = "10.0.0.5".parse().unwrap();
    assert!(single.is_single() && single.is_cidr() && !single.is_range());

    let block: IpSet = "10.0.0.0/24".parse().unwrap();
    assert!(!block.is_single() && block.is_cidr());

    let range: IpSet = "10.0.0.1-10".parse().unwrap();
    assert!(range.is_range() && !range.is_cidr() && !range.is_single());
}

#[test]
fn ipset_iterates_in_reverse() {
    let set: IpSet = "10.0.0.0/30".parse().unwrap();
    let rev: Vec<_> = set.addresses().rev().collect();
    assert_eq!(rev[0], "10.0.0.3".parse::<IpAddr>().unwrap());
    assert_eq!(rev[3], "10.0.0.0".parse::<IpAddr>().unwrap());
    // size_hint is forwarded (exact for IPv4).
    assert_eq!(set.addresses().size_hint(), (4, Some(4)));
}

#[test]
fn free_aggregate_handles_mixed_families() {
    let blocks: Vec<IpCidr> = [
        "10.0.0.0/25",
        "10.0.0.128/25",
        "2001:db8::/33",
        "2001:db8:8000::/33",
    ]
    .iter()
    .map(|s| s.parse().unwrap())
    .collect();
    let merged = cidr_utils::aggregate(&blocks);
    assert_eq!(merged.len(), 2);
    assert_eq!(merged[0], "10.0.0.0/24".parse::<IpCidr>().unwrap());
    assert_eq!(merged[1], "2001:db8::/32".parse::<IpCidr>().unwrap());
}

#[test]
fn range_overlaps_and_contains() {
    let a: Ipv4Range = "10.0.0.1-10.0.0.20".parse().unwrap();
    let b: Ipv4Range = "10.0.0.10-10.0.0.30".parse().unwrap();
    let inside: Ipv4Range = "10.0.0.5-10.0.0.8".parse().unwrap();
    let disjoint: Ipv4Range = "10.0.0.50-10.0.0.60".parse().unwrap();
    assert!(a.overlaps(&b));
    assert!(!a.overlaps(&disjoint));
    assert!(a.contains_range(&inside));
    assert!(!a.contains_range(&b));

    // IpRange delegation + family guard.
    let ra: IpRange = IpRange::V4(a);
    let rb: IpRange = IpRange::V4(b);
    assert!(ra.overlaps(&rb));
    let v6: IpRange = "::1-::5".parse().unwrap();
    assert!(!ra.overlaps(&v6));
}

#[test]
fn ipset_as_cidr_as_range() {
    let cidr: IpSet = "10.0.0.0/24".parse().unwrap();
    assert!(cidr.as_cidr().is_some());
    assert!(cidr.as_range().is_none());

    let range: IpSet = "10.0.0.1-10".parse().unwrap();
    assert!(range.as_range().is_some());
    assert!(range.as_cidr().is_none());
}

#[test]
fn ipcidr_nth_address() {
    let c: IpCidr = "192.168.1.0/24".parse().unwrap();
    assert_eq!(
        c.nth_address(10),
        Some("192.168.1.10".parse::<IpAddr>().unwrap())
    );
    assert_eq!(c.nth_address(256), None);
}

#[test]
fn ipcidr_split_and_subnet_count() {
    let c: IpCidr = "10.0.0.0/24".parse().unwrap();
    let (lo, hi) = c.split().unwrap();
    assert_eq!(lo, "10.0.0.0/25".parse::<IpCidr>().unwrap());
    assert_eq!(hi, "10.0.0.128/25".parse::<IpCidr>().unwrap());
    assert_eq!(c.subnet_count(26), 4);
}

#[test]
fn exclude_then_aggregate_reconstructs_block() {
    let block: Ipv4Cidr = "10.0.0.0/24".parse().unwrap();
    // For every sub-block prefix and position, removing it and adding it back
    // (via aggregate) must reproduce the original /24 exactly.
    for prefix in 25..=32u8 {
        let step = 1u32 << (32 - prefix);
        let mut base = 0u32;
        while base < 256 {
            let hole =
                Ipv4Cidr::new(std::net::Ipv4Addr::new(10, 0, 0, base as u8), prefix).unwrap();
            let mut pieces = block.exclude(&hole);
            pieces.push(hole);
            let merged = Ipv4Cidr::aggregate(&pieces);
            assert_eq!(merged, vec![block], "prefix={prefix} base={base}");
            base += step;
        }
    }
}

#[test]
fn iprange_contains_range_delegation() {
    let outer: IpRange = "10.0.0.1-10.0.0.100".parse().unwrap();
    let inner: IpRange = "10.0.0.10-10.0.0.20".parse().unwrap();
    assert!(outer.contains_range(&inner));
    assert!(!inner.contains_range(&outer));
    let v6: IpRange = "::1-::5".parse().unwrap();
    assert!(!outer.contains_range(&v6));
}

#[test]
fn ipv6_unique_local_range() {
    use cidr_utils::Ipv6Cidr;
    let ula: Ipv6Cidr = "fd00::/8".parse().unwrap();
    assert!(ula.is_unique_local());
    let ula_low: Ipv6Cidr = "fc00::/8".parse().unwrap();
    assert!(ula_low.is_unique_local());
    let outside: Ipv6Cidr = "2001::/16".parse().unwrap();
    assert!(!outside.is_unique_local());
}

#[test]
fn ipv6_link_local_range() {
    use cidr_utils::Ipv6Cidr;
    let ll: Ipv6Cidr = "fe80::/10".parse().unwrap();
    assert!(ll.is_link_local());
    let outside: Ipv6Cidr = "2001::/16".parse().unwrap();
    assert!(!outside.is_link_local());
    // fec0:: is not link-local (it's the deprecated site-local).
    let sl: Ipv6Cidr = "fec0::/10".parse().unwrap();
    assert!(!sl.is_link_local());
}

#[test]
fn ipv6_documentation_range() {
    use cidr_utils::Ipv6Cidr;
    let doc: Ipv6Cidr = "2001:db8::/32".parse().unwrap();
    assert!(doc.is_documentation());
    let outside: Ipv6Cidr = "2001:db9::/32".parse().unwrap();
    assert!(!outside.is_documentation());
}

#[test]
fn ipset_contains_set_and_overlaps() {
    use cidr_utils::IpSet;
    let big: IpSet = "10.0.0.0/24".parse().unwrap();
    let small: IpSet = "10.0.0.10-10.0.0.20".parse().unwrap();
    let outside: IpSet = "10.0.1.0/24".parse().unwrap();
    let single: IpSet = "10.0.0.5".parse().unwrap();
    assert!(big.contains_set(&small));
    assert!(!small.contains_set(&big));
    assert!(big.contains_set(&single));
    assert!(single.is_address());
    assert!(big.overlaps(&small));
    assert!(!big.overlaps(&outside));
    let touching_a: IpSet = "10.0.0.0/25".parse().unwrap();
    let touching_b: IpSet = "10.0.0.128/25".parse().unwrap();
    assert!(!touching_a.overlaps(&touching_b));
}

#[test]
fn mask_to_prefix_len_round_trips() {
    use cidr_utils::{Ipv4Cidr, Ipv6Cidr};
    use std::net::{Ipv4Addr, Ipv6Addr};

    assert_eq!(
        Ipv4Cidr::mask_to_prefix_len(Ipv4Addr::new(255, 255, 255, 0)),
        Some(24)
    );
    assert_eq!(
        Ipv4Cidr::mask_to_prefix_len(Ipv4Addr::new(255, 255, 0, 0)),
        Some(16)
    );
    // Non-contiguous mask.
    assert_eq!(
        Ipv4Cidr::mask_to_prefix_len(Ipv4Addr::new(255, 0, 255, 0)),
        None
    );

    let v6: Ipv6Addr = "ffff:ffff:ffff:ffff::".parse().unwrap();
    assert_eq!(Ipv6Cidr::mask_to_prefix_len(v6), Some(64));
}

#[test]
fn wildcard_mask_inverts_netmask() {
    use cidr_utils::Ipv4Cidr;
    use std::net::Ipv4Addr;
    let c: Ipv4Cidr = "192.168.1.0/24".parse().unwrap();
    assert_eq!(c.wildcard_mask(), Ipv4Addr::new(0, 0, 0, 255));
}

#[test]
fn ipcidr_predicates_route_to_family() {
    use cidr_utils::IpCidr;
    let v4_priv: IpCidr = "10.0.0.0/8".parse().unwrap();
    assert!(v4_priv.is_private());
    let v4_doc: IpCidr = "192.0.2.0/24".parse().unwrap();
    assert!(v4_doc.is_documentation());
    let v4_ll: IpCidr = "169.254.0.0/16".parse().unwrap();
    assert!(v4_ll.is_link_local());

    let v6_ula: IpCidr = "fd00::/8".parse().unwrap();
    assert!(v6_ula.is_private());
    let v6_doc: IpCidr = "2001:db8::/32".parse().unwrap();
    assert!(v6_doc.is_documentation());
    let v6_ll: IpCidr = "fe80::/10".parse().unwrap();
    assert!(v6_ll.is_link_local());

    let v4_lo: IpCidr = "127.0.0.0/8".parse().unwrap();
    assert!(v4_lo.is_loopback());
    let v4_mc: IpCidr = "224.0.0.0/4".parse().unwrap();
    assert!(v4_mc.is_multicast());
}

#[test]
fn ipv4_range_nth_address_matches_iterator() {
    use cidr_utils::Ipv4Range;
    let r: Ipv4Range = "10.0.0.1-10.0.0.20".parse().unwrap();
    let v: Vec<_> = r.iter().collect();
    for (i, want) in v.iter().enumerate() {
        assert_eq!(r.nth_address(i as u128).unwrap(), *want, "idx {i}");
    }
    assert_eq!(r.nth_address(v.len() as u128), None);
}

#[test]
fn ipv6_range_nth_address_indexes_in_bounds() {
    use cidr_utils::Ipv6Range;
    use std::net::Ipv6Addr;
    let r: Ipv6Range = "2001:db8::1-2001:db8::5".parse().unwrap();
    assert_eq!(r.nth_address(0).unwrap(), Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    assert_eq!(r.nth_address(4).unwrap(), Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5));
    assert_eq!(r.nth_address(5), None);
}

#[test]
fn ipset_nth_address_works_on_cidr_and_range() {
    use cidr_utils::IpSet;
    use std::net::IpAddr;
    let block: IpSet = "192.168.0.0/30".parse().unwrap();
    assert_eq!(block.nth_address(0).unwrap(), "192.168.0.0".parse::<IpAddr>().unwrap());
    assert_eq!(block.nth_address(3).unwrap(), "192.168.0.3".parse::<IpAddr>().unwrap());
    assert_eq!(block.nth_address(4), None);

    let range: IpSet = "10.0.0.5-10.0.0.8".parse().unwrap();
    assert_eq!(range.nth_address(0).unwrap(), "10.0.0.5".parse::<IpAddr>().unwrap());
    assert_eq!(range.nth_address(3).unwrap(), "10.0.0.8".parse::<IpAddr>().unwrap());
    assert_eq!(range.nth_address(4), None);
}

#[test]
fn iprange_nth_address_delegates_to_family() {
    use cidr_utils::{IpRange, Ipv4Range};
    use std::net::IpAddr;
    let r4: Ipv4Range = "10.0.0.10-10.0.0.20".parse().unwrap();
    let ip: IpRange = IpRange::V4(r4);
    assert_eq!(ip.nth_address(5).unwrap(), IpAddr::V4(r4.nth_address(5).unwrap()));
}

#[test]
fn ipv4_supernet_at_climbs_to_named_prefix() {
    use cidr_utils::Ipv4Cidr;
    let c: Ipv4Cidr = "10.20.30.0/24".parse().unwrap();
    let s: Ipv4Cidr = c.supernet_at(16).unwrap();
    assert_eq!(s.to_string(), "10.20.0.0/16");
    let z: Ipv4Cidr = c.supernet_at(0).unwrap();
    assert_eq!(z.to_string(), "0.0.0.0/0");
}

#[test]
fn ipv4_supernet_at_self_is_self() {
    use cidr_utils::Ipv4Cidr;
    let c: Ipv4Cidr = "10.20.30.0/24".parse().unwrap();
    assert_eq!(c.supernet_at(24).unwrap(), c);
}

#[test]
fn ipv4_supernet_at_longer_prefix_is_none() {
    use cidr_utils::Ipv4Cidr;
    let c: Ipv4Cidr = "10.20.30.0/24".parse().unwrap();
    assert!(c.supernet_at(25).is_none());
    assert!(c.supernet_at(32).is_none());
}

#[test]
fn ipv6_supernet_at_truncates_lower_bits() {
    use cidr_utils::Ipv6Cidr;
    let c: Ipv6Cidr = "2001:db8:1234::/48".parse().unwrap();
    let s: Ipv6Cidr = c.supernet_at(32).unwrap();
    assert_eq!(s.to_string(), "2001:db8::/32");
}

#[test]
fn ipv4_range_exclude_disjoint_returns_self() {
    use cidr_utils::Ipv4Range;
    let a: Ipv4Range = "10.0.0.0-10.0.0.10".parse().unwrap();
    let b: Ipv4Range = "10.0.1.0-10.0.1.10".parse().unwrap();
    let out = a.exclude(&b);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].to_string(), "10.0.0.0-10.0.0.10");
}

#[test]
fn ipv4_range_exclude_fully_covering_returns_empty() {
    use cidr_utils::Ipv4Range;
    let a: Ipv4Range = "10.0.0.5-10.0.0.10".parse().unwrap();
    let b: Ipv4Range = "10.0.0.0-10.0.0.20".parse().unwrap();
    assert!(a.exclude(&b).is_empty());
}

#[test]
fn ipv4_range_exclude_middle_returns_two_pieces() {
    use cidr_utils::Ipv4Range;
    let a: Ipv4Range = "10.0.0.0-10.0.0.100".parse().unwrap();
    let b: Ipv4Range = "10.0.0.40-10.0.0.60".parse().unwrap();
    let out = a.exclude(&b);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].to_string(), "10.0.0.0-10.0.0.39");
    assert_eq!(out[1].to_string(), "10.0.0.61-10.0.0.100");
}

#[test]
fn ipv4_range_exclude_left_overlap_returns_right_piece() {
    use cidr_utils::Ipv4Range;
    let a: Ipv4Range = "10.0.0.20-10.0.0.100".parse().unwrap();
    let b: Ipv4Range = "10.0.0.0-10.0.0.50".parse().unwrap();
    let out = a.exclude(&b);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].to_string(), "10.0.0.51-10.0.0.100");
}

#[test]
fn iprange_exclude_mismatched_family_returns_self() {
    use cidr_utils::{IpRange, Ipv4Range, Ipv6Range};
    use std::str::FromStr;
    let a = IpRange::V4(Ipv4Range::from_str("10.0.0.0-10.0.0.5").unwrap());
    let b = IpRange::V6(Ipv6Range::from_str("2001:db8::-2001:db8::5").unwrap());
    let out = a.exclude(&b);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0], a);
}

#[test]
fn ipv4_range_intersection_clips_overlap() {
    use cidr_utils::Ipv4Range;
    let a: Ipv4Range = "10.0.0.0-10.0.0.100".parse().unwrap();
    let b: Ipv4Range = "10.0.0.50-10.0.0.200".parse().unwrap();
    let i = a.intersection(&b).unwrap();
    assert_eq!(i.to_string(), "10.0.0.50-10.0.0.100");
    assert_eq!(i.count(), 51);
}

#[test]
fn ipv4_range_intersection_disjoint_is_none() {
    use cidr_utils::Ipv4Range;
    let a: Ipv4Range = "10.0.0.0-10.0.0.10".parse().unwrap();
    let b: Ipv4Range = "10.0.1.0-10.0.1.10".parse().unwrap();
    assert!(a.intersection(&b).is_none());
}

#[test]
fn iprange_intersection_mismatched_family_is_none() {
    use cidr_utils::{IpRange, Ipv4Range, Ipv6Range};
    use std::str::FromStr;
    let a = IpRange::V4(Ipv4Range::from_str("10.0.0.0-10.0.0.5").unwrap());
    let b = IpRange::V6(Ipv6Range::from_str("2001:db8::-2001:db8::5").unwrap());
    assert!(a.intersection(&b).is_none());
}

#[test]
fn ipset_intersection_cidr_with_cidr_returns_range() {
    use cidr_utils::IpSet;
    let a: IpSet = "10.0.0.0/24".parse().unwrap();
    let b: IpSet = "10.0.0.128/26".parse().unwrap();
    let i = a.intersection(&b).unwrap();
    assert_eq!(i.first().to_string(), "10.0.0.128");
    assert_eq!(i.last().to_string(), "10.0.0.191");
    assert_eq!(i.count(), 64);
}

#[test]
fn ipset_intersection_disjoint_is_none() {
    use cidr_utils::IpSet;
    let a: IpSet = "10.0.0.0/24".parse().unwrap();
    let b: IpSet = "10.0.1.0/24".parse().unwrap();
    assert!(a.intersection(&b).is_none());
}

#[test]
fn ipset_intersection_with_self_is_self_range_shape() {
    use cidr_utils::IpSet;
    let a: IpSet = "192.168.0.0/30".parse().unwrap();
    let i = a.intersection(&a).unwrap();
    assert_eq!(i.first(), a.first());
    assert_eq!(i.last(), a.last());
}

#[test]
fn ipcidr_supernet_at_routes_to_family() {
    use cidr_utils::IpCidr;
    let v4: IpCidr = "10.20.30.0/24".parse().unwrap();
    assert_eq!(v4.supernet_at(16).unwrap().to_string(), "10.20.0.0/16");
    let v6: IpCidr = "2001:db8:abcd::/48".parse().unwrap();
    assert_eq!(v6.supernet_at(32).unwrap().to_string(), "2001:db8::/32");
    // Longer-than-self is None for both families.
    assert!(v4.supernet_at(25).is_none());
    assert!(v6.supernet_at(49).is_none());
}
