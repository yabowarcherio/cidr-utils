//! Microbenchmarks for the hot paths: parsing, containment, and decomposition.

use std::net::Ipv4Addr;

use cidr_utils::{IpSet, Ipv4Cidr, Ipv4Range};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_parse(c: &mut Criterion) {
    c.bench_function("parse cidr", |b| {
        b.iter(|| black_box("192.168.1.0/24").parse::<Ipv4Cidr>().unwrap())
    });
    c.bench_function("parse range shorthand", |b| {
        b.iter(|| black_box("192.168.1.1-200").parse::<Ipv4Range>().unwrap())
    });
    c.bench_function("parse ipset", |b| {
        b.iter(|| black_box("10.0.0.0/8").parse::<IpSet>().unwrap())
    });
}

fn bench_contains(c: &mut Criterion) {
    let block: Ipv4Cidr = "10.0.0.0/8".parse().unwrap();
    let addr = Ipv4Addr::new(10, 11, 12, 13);
    c.bench_function("contains", |b| {
        b.iter(|| black_box(&block).contains(black_box(addr)))
    });
}

fn bench_to_cidrs(c: &mut Criterion) {
    let range: Ipv4Range = "10.0.0.5-10.0.250.123".parse().unwrap();
    c.bench_function("range to_cidrs", |b| {
        b.iter(|| black_box(&range).to_cidrs())
    });
}

criterion_group!(benches, bench_parse, bench_contains, bench_to_cidrs);
criterion_main!(benches);
