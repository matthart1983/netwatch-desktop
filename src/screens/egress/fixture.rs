//! A populated egress state shaped like mock 2i: two ruled processes (one
//! drifting), one unruled process with an ECH flow, and two quiet ones.
use crate::backend::EgressSnapshot;
use netwatch::collectors::egress::{
    EgressDest, EgressPolicy, EgressProfile, ProcessRule, RecentViolation, Verdict,
};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime};

type Profiles<'a> = Vec<(&'a str, Vec<(&'a str, EgressDest, Verdict)>)>;

#[allow(clippy::too_many_arguments)]
fn dest(
    sni: Option<&str>,
    asn: Option<&str>,
    ip: &str,
    port: u16,
    first_ago: u64,
    last_ago: u64,
    bytes_in: u64,
    bytes_out: u64,
    ech: bool,
) -> EgressDest {
    let now = SystemTime::now();
    EgressDest {
        sni: sni.map(str::to_string),
        asn_org: asn.map(str::to_string),
        port,
        last_ip: ip.into(),
        ech,
        first_seen: now - Duration::from_secs(first_ago),
        last_seen: now - Duration::from_secs(last_ago),
        count: first_ago.min(840),
        bytes_out,
        bytes_in,
        activity: (0..40u64)
            .map(|i| (bytes_out / 40).max(1) * (1 + (i * 7 + port as u64) % 5))
            .collect::<VecDeque<u64>>(),
    }
}

pub fn snapshot() -> EgressSnapshot {
    const D: u64 = 86_400;
    let mb = 1_000_000;
    let profiles: Profiles = vec![
        (
            "curl",
            vec![
                (
                    "api.github.com",
                    dest(
                        Some("api.github.com"),
                        Some("GITHUB"),
                        "140.82.112.5",
                        443,
                        4 * D,
                        8,
                        410 * mb,
                        mb,
                        false,
                    ),
                    Verdict::Sni,
                ),
                (
                    "AS36459 · github",
                    dest(
                        None,
                        Some("AS36459 · github"),
                        "",
                        443,
                        2 * D,
                        120,
                        200 * mb,
                        mb,
                        false,
                    ),
                    Verdict::Asn("AS36459 · github".into()),
                ),
                (
                    "10.88.0.3",
                    dest(
                        None,
                        None,
                        "10.88.0.3",
                        80,
                        3600,
                        8,
                        610 * mb,
                        2 * mb,
                        false,
                    ),
                    Verdict::Ip,
                ),
            ],
        ),
        (
            "node",
            vec![
                (
                    "registry.npmjs.org",
                    dest(
                        Some("registry.npmjs.org"),
                        None,
                        "104.16.24.34",
                        443,
                        2 * D,
                        120,
                        31 * mb,
                        mb,
                        false,
                    ),
                    Verdict::Sni,
                ),
                (
                    "203.0.113.9",
                    dest(
                        None,
                        Some("AS64496 · example-net"),
                        "203.0.113.9",
                        443,
                        120,
                        4,
                        420_000,
                        mb,
                        false,
                    ),
                    Verdict::Drift,
                ),
            ],
        ),
        (
            "firefox",
            vec![
                (
                    "www.cloudflare.com",
                    dest(
                        Some("www.cloudflare.com"),
                        None,
                        "104.16.123.96",
                        443,
                        4 * D,
                        60,
                        820 * mb,
                        20 * mb,
                        false,
                    ),
                    Verdict::NoRule,
                ),
                (
                    "104.16.0.1",
                    dest(None, None, "104.16.0.1", 443, D, 9, 120 * mb, 8 * mb, true),
                    Verdict::NoRule,
                ),
            ],
        ),
        (
            "systemd-resolved",
            vec![(
                "1.1.1.1",
                dest(None, None, "1.1.1.1", 53, 4 * D, 1, 75 * mb, 75 * mb, false),
                Verdict::NoRule,
            )],
        ),
    ];
    let mut e = EgressSnapshot {
        policy_path: dirs::config_dir().map(|d| d.join("netwatch").join("egress-policy.toml")),
        policy_mode: Some(0o644),
        has_policy: true,
        cooldown_secs: 300,
        ..Default::default()
    };
    let now = SystemTime::now();
    for (process, dests) in profiles {
        let mut map = HashMap::new();
        let mut rule = ProcessRule::default();
        for (label, d, verdict) in dests {
            match &d.sni {
                Some(s) => rule.allow_sni.push(s.clone()),
                None if !d.last_ip.is_empty() => rule.allow_ip.push(d.last_ip.clone()),
                None => rule.allow_asn.extend(d.asn_org.clone()),
            }
            if !rule.allow_ports.contains(&d.port) {
                rule.allow_ports.push(d.port);
            }
            e.verdicts
                .insert((process.to_string(), label.to_string(), d.port), verdict);
            map.insert((label.to_string(), d.port), d);
        }
        rule.allow_sni.sort();
        rule.allow_ip.sort();
        rule.allow_ports.sort();
        e.promotable.insert(process.to_string(), rule);
        e.profiles.push(EgressProfile {
            process: process.into(),
            dests: map,
            last_seen: now,
        });
    }
    e.policy = Some(EgressPolicy {
        strict: false,
        process: [
            (
                "curl".to_string(),
                ProcessRule {
                    allow_sni: vec!["api.github.com".into()],
                    allow_asn: vec!["AS36459 · github".into()],
                    allow_ip: vec!["10.88.0.3".into()],
                    allow_ports: vec![80, 443],
                    ..Default::default()
                },
            ),
            (
                "node".to_string(),
                ProcessRule {
                    allow_sni: vec!["registry.npmjs.org".into()],
                    allow_ports: vec![443],
                    ..Default::default()
                },
            ),
        ]
        .into(),
        ..Default::default()
    });
    e.recent.push(RecentViolation {
        process: "node".into(),
        dest: "203.0.113.9".into(),
        port: 443,
        reason: "203.0.113.9 not in allowlist".into(),
        when: now - Duration::from_secs(110),
    });
    e
}
