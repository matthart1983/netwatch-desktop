//! Pure figures behind the stats tab: packet-ring folding (protocol tree,
//! remotes), windowed interface byte counts, and the rtt distribution.
use crate::backend::Snapshot;
use netwatch::collectors::packets::CapturedPacket;
use netwatch::dpi::AppProtocol;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Window {
    M5,
    M15,
    #[default]
    Session,
}

impl Window {
    pub const ALL: [Window; 3] = [Window::M5, Window::M15, Window::Session];
    pub fn label(self) -> &'static str {
        match self {
            Window::M5 => "5m",
            Window::M15 => "15m",
            Window::Session => "session",
        }
    }
    pub fn secs(self) -> Option<f64> {
        match self {
            Window::M5 => Some(300.0),
            Window::M15 => Some(900.0),
            Window::Session => None,
        }
    }
    pub fn from_label(label: &str) -> Option<Window> {
        Window::ALL.into_iter().find(|w| w.label() == label)
    }
    pub fn step(self, delta: isize) -> Window {
        let i = Window::ALL.iter().position(|w| *w == self).unwrap_or(0) as isize;
        Window::ALL[(i + delta).rem_euclid(Window::ALL.len() as isize) as usize]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Unit {
    #[default]
    Bytes,
    Frames,
}

impl Unit {
    pub fn label(self) -> &'static str {
        match self {
            Unit::Bytes => "bytes",
            Unit::Frames => "frames",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Amount {
    pub bytes: u64,
    pub frames: u64,
}

impl Amount {
    pub fn add(&mut self, bytes: u64) {
        self.bytes += bytes;
        self.frames += 1;
    }
    pub fn get(self, unit: Unit) -> u64 {
        match unit {
            Unit::Bytes => self.bytes,
            Unit::Frames => self.frames,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    Tcp,
    Udp,
    Other,
}

impl Family {
    pub fn label(self) -> &'static str {
        match self {
            Family::Tcp => "tcp",
            Family::Udp => "udp",
            Family::Other => "other",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Branch {
    pub total: Amount,
    /// Child label → amount, sorted by bytes descending when folded.
    pub children: Vec<(String, Amount)>,
}

impl Branch {
    pub fn sorted_children(&self, unit: Unit) -> Vec<(String, Amount)> {
        let mut c = self.children.clone();
        c.sort_by(|a, b| b.1.get(unit).cmp(&a.1.get(unit)).then(a.0.cmp(&b.0)));
        c
    }
}

/// Everything folded from the packet ring for one window.
#[derive(Clone, Debug, Default)]
pub struct Ring {
    /// Packets held in the ring (any age).
    pub held: usize,
    /// Packets inside the window.
    pub in_window: Amount,
    pub tcp: Branch,
    pub udp: Branch,
    pub other: Branch,
    /// Remote ip → amount, largest first by bytes.
    pub remotes: Vec<(String, Amount)>,
    /// Packet timestamps are not wall-clock (seeded or replayed capture), so
    /// the window is measured back from the newest packet.
    pub relative_clock: bool,
}

impl Ring {
    pub fn branch(&self, family: Family) -> &Branch {
        match family {
            Family::Tcp => &self.tcp,
            Family::Udp => &self.udp,
            Family::Other => &self.other,
        }
    }
}

const L4_NAMES: [&str; 11] = [
    "tcp",
    "udp",
    "icmp",
    "icmpv6",
    "arp",
    "igmp",
    "gre",
    "ospf",
    "sctp",
    "ipv6-encap",
    "unknown",
];
const TCP_L7: [&str; 9] = [
    "tls",
    "http",
    "ssh",
    "mqtt",
    "ftp",
    "bittorrent",
    "smtp",
    "imap",
    "rdp",
];
const UDP_L7: [&str; 10] = [
    "dns", "quic", "ntp", "dhcp", "ssdp", "stun", "snmp", "llmnr", "netbios", "mdns",
];

pub fn app_label(p: &AppProtocol) -> &'static str {
    match p {
        AppProtocol::Tls { .. } => "tls",
        AppProtocol::Http { .. } => "http",
        AppProtocol::Dns { .. } => "dns",
        AppProtocol::Ssh { .. } => "ssh",
        AppProtocol::Quic { .. } => "quic",
        AppProtocol::Mqtt { .. } => "mqtt",
        AppProtocol::Stun { .. } => "stun",
        AppProtocol::BitTorrent { .. } => "bittorrent",
        AppProtocol::NetBios { .. } => "netbios",
        AppProtocol::Snmp { .. } => "snmp",
        AppProtocol::Ssdp { .. } => "ssdp",
        AppProtocol::Ftp { .. } => "ftp",
        AppProtocol::Llmnr { .. } => "llmnr",
        AppProtocol::Dhcp { .. } => "dhcp",
        AppProtocol::Ntp { .. } => "ntp",
    }
}

/// The l4 family and, when decoded, the l7 label of one captured packet.
/// For `other` the label is the protocol name itself (icmp, arp…).
pub fn classify(p: &CapturedPacket) -> (Family, Option<String>) {
    let proto = p.protocol.to_lowercase();
    let l7 = p
        .app_protocol
        .as_ref()
        .map(|a| app_label(a).to_string())
        .or_else(|| {
            (!L4_NAMES.contains(&proto.as_str()) && !proto.starts_with("proto("))
                .then(|| proto.clone())
        });
    let detail = |prefix: &str| p.details.iter().any(|d| d.starts_with(prefix));
    let family = if p.tcp_flags.is_some() || detail("TCP:") || proto == "tcp" {
        Family::Tcp
    } else if detail("UDP:") || proto == "udp" {
        Family::Udp
    } else if let Some(l7) = &l7 {
        if TCP_L7.contains(&l7.as_str()) {
            Family::Tcp
        } else if UDP_L7.contains(&l7.as_str()) {
            Family::Udp
        } else {
            Family::Other
        }
    } else {
        Family::Other
    };
    match family {
        Family::Other => (Family::Other, Some(proto)),
        f => (f, l7),
    }
}

fn strip_prefix_len(ip: &str) -> String {
    ip.split('/').next().unwrap_or(ip).to_string()
}

pub fn local_ips(s: &Snapshot) -> HashSet<String> {
    let mut set: HashSet<String> = ["127.0.0.1", "::1"].iter().map(|s| s.to_string()).collect();
    for i in s.interface_info.iter() {
        set.extend(i.ipv4.as_deref().map(strip_prefix_len));
        set.extend(i.ipv6.as_deref().map(strip_prefix_len));
    }
    set
}

/// The remote side of a packet: whichever end is not local; when neither
/// (or both) is local, the end on the lower (service) port.
pub fn remote_of<'a>(p: &'a CapturedPacket, local: &HashSet<String>) -> Option<&'a str> {
    let src_local = local.contains(&p.src_ip);
    let dst_local = local.contains(&p.dst_ip);
    match (src_local, dst_local) {
        (true, false) => Some(&p.dst_ip),
        (false, true) => Some(&p.src_ip),
        (true, true) => None,
        (false, false) => match (p.src_port, p.dst_port) {
            (Some(s), Some(d)) if s < d => Some(&p.src_ip),
            _ => Some(&p.dst_ip),
        },
    }
}

/// Wall-clock nanoseconds sit well past 2001; seeded captures count from 0.
const WALL_CLOCK_NS: u64 = 1_000_000_000_000_000_000;

pub fn fold_ring(
    packets: &[CapturedPacket],
    window_secs: Option<f64>,
    now_ns: u64,
    local: &HashSet<String>,
) -> Ring {
    let mut ring = Ring {
        held: packets.len(),
        ..Default::default()
    };
    let newest = packets.iter().map(|p| p.timestamp_ns).max().unwrap_or(0);
    ring.relative_clock = !packets.is_empty() && newest < WALL_CLOCK_NS;
    let cutoff = window_secs.map(|w| {
        let reference = if ring.relative_clock { newest } else { now_ns };
        reference.saturating_sub((w * 1e9) as u64)
    });
    let mut children: HashMap<(Family, String), Amount> = HashMap::new();
    let mut remotes: HashMap<&str, Amount> = HashMap::new();
    for p in packets {
        if cutoff.is_some_and(|c| p.timestamp_ns < c) {
            continue;
        }
        let len = p.length as u64;
        ring.in_window.add(len);
        let (family, label) = classify(p);
        match family {
            Family::Tcp => ring.tcp.total.add(len),
            Family::Udp => ring.udp.total.add(len),
            Family::Other => ring.other.total.add(len),
        }
        if let Some(label) = label {
            children.entry((family, label)).or_default().add(len);
        }
        if let Some(remote) = remote_of(p, local) {
            remotes.entry(remote).or_default().add(len);
        }
    }
    for ((family, label), amount) in children {
        let branch = match family {
            Family::Tcp => &mut ring.tcp,
            Family::Udp => &mut ring.udp,
            Family::Other => &mut ring.other,
        };
        branch.children.push((label, amount));
    }
    ring.remotes = remotes
        .into_iter()
        .map(|(ip, a)| (ip.to_string(), a))
        .collect();
    ring.remotes
        .sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes).then(a.0.cmp(&b.0)));
    ring
}

/// Bytes moved over non-loopback interfaces in the last `secs`, integrated
/// from the per-tick rate histories. Returns (rx, tx, seconds covered).
pub fn window_bytes(s: &Snapshot, secs: f64) -> (u64, u64, f64) {
    let mut rx = 0.0;
    let mut tx = 0.0;
    let mut covered: f64 = 0.0;
    for i in s.interfaces.iter().filter(|i| !is_loopback(&i.name)) {
        let Some(latest) = i.sample_times.back().copied() else {
            continue;
        };
        let mut previous: Option<std::time::Instant> = None;
        let mut span = 0.0;
        for ((at, r), t) in i.sample_times.iter().zip(&i.rx_history).zip(&i.tx_history) {
            let age = latest.saturating_duration_since(*at).as_secs_f64();
            let dt = previous
                .map(|p| at.saturating_duration_since(p).as_secs_f64())
                .unwrap_or(s.sample_interval);
            previous = Some(*at);
            if age >= secs {
                continue;
            }
            rx += *r as f64 * dt;
            tx += *t as f64 * dt;
            span += dt;
        }
        covered = covered.max(span);
    }
    (rx as u64, tx as u64, covered.min(secs))
}

pub fn is_loopback(name: &str) -> bool {
    name == "lo" || name == "lo0"
}

/// Element-wise sum of non-loopback rx/tx histories, aligned at the newest
/// sample, limited to `secs` seconds when given.
pub fn summed_history(s: &Snapshot, secs: Option<f64>) -> (Vec<f64>, Vec<f64>) {
    let per_tick = s.sample_interval.max(0.1);
    let mut rx: Vec<f64> = Vec::new();
    let mut tx: Vec<f64> = Vec::new();
    for i in s.interfaces.iter().filter(|i| !is_loopback(&i.name)) {
        let n = i.rx_history.len().min(i.tx_history.len());
        let keep = secs.map_or(n, |w| n.min((w / per_tick).ceil() as usize));
        if rx.len() < keep {
            let pad = keep - rx.len();
            rx.splice(0..0, std::iter::repeat_n(0.0, pad));
            tx.splice(0..0, std::iter::repeat_n(0.0, pad));
        }
        let len = rx.len();
        for k in 0..keep {
            rx[len - 1 - k] += i.rx_history[n - 1 - k] as f64;
            tx[len - 1 - k] += i.tx_history[n - 1 - k] as f64;
        }
    }
    (rx, tx)
}

/// Folds `values` into `bars` means; fewer samples than bars are
/// right-aligned one bar per sample with gaps before them.
pub fn fold_bars(values: &[f64], bars: usize) -> Vec<Option<f64>> {
    if bars == 0 {
        return Vec::new();
    }
    if values.len() <= bars {
        let mut out = vec![None; bars - values.len()];
        out.extend(values.iter().map(|v| Some(*v)));
        return out;
    }
    let per = values.len() as f64 / bars as f64;
    (0..bars)
        .map(|i| {
            let a = (i as f64 * per) as usize;
            let b = (((i + 1) as f64 * per) as usize).clamp(a + 1, values.len());
            Some(values[a..b].iter().sum::<f64>() / (b - a) as f64)
        })
        .collect()
}

/// Exact rtt samples in milliseconds and the name of their source. The three
/// handshake sources observe the same streams, so only one is used: the
/// per-host history (it outlives stream eviction), then live streams, then
/// socket handshakes.
pub fn rtt_samples(s: &Snapshot) -> (Vec<f64>, &'static str) {
    let history: Vec<f64> = s.rtt_history.values().flatten().copied().collect();
    if !history.is_empty() {
        return (history, "tcp handshakes");
    }
    let streams: Vec<f64> = s
        .packets
        .streams
        .lock()
        .map(|t| {
            t.snapshot_handshake_rtts()
                .into_values()
                .map(|us| us / 1000.0)
                .collect()
        })
        .unwrap_or_default();
    if !streams.is_empty() {
        return (streams, "tcp handshakes");
    }
    let sockets: Vec<f64> = s
        .connections
        .iter()
        .filter_map(|c| c.handshake_rtt_us.map(|us| us / 1000.0))
        .collect();
    let source = if sockets.is_empty() {
        "tcp handshakes"
    } else {
        "socket handshakes"
    };
    (sockets, source)
}

pub const AXIS_MIN_MS: f64 = 0.1;
pub const AXIS_MAX_MS: f64 = 300.0;
pub const BINS: usize = 24;

pub fn axis_fraction(ms: f64) -> f64 {
    let lo = AXIS_MIN_MS.log10();
    let hi = AXIS_MAX_MS.log10();
    ((ms.max(AXIS_MIN_MS).log10() - lo) / (hi - lo)).clamp(0.0, 1.0)
}

pub fn bin_of(ms: f64) -> usize {
    ((axis_fraction(ms) * BINS as f64) as usize).min(BINS - 1)
}

/// Lower edge of a bin in ms.
pub fn bin_floor(bin: usize) -> f64 {
    let lo = AXIS_MIN_MS.log10();
    let hi = AXIS_MAX_MS.log10();
    10f64.powf(lo + (hi - lo) * bin as f64 / BINS as f64)
}

/// DNS latency bucket edges from `DnsAnalytics::latency_buckets`.
const DNS_EDGES: [(f64, f64); 8] = [
    (AXIS_MIN_MS, 5.0),
    (5.0, 10.0),
    (10.0, 25.0),
    (25.0, 50.0),
    (50.0, 100.0),
    (100.0, 250.0),
    (250.0, 500.0),
    (500.0, 1000.0),
];

/// Histogram counts per log bin: exact samples land in their bin; DNS
/// bucket counts are spread evenly over the bins their range covers.
pub fn histogram(samples: &[f64], dns: &[u64; 8]) -> Vec<f64> {
    let mut bins = vec![0.0; BINS];
    for ms in samples {
        bins[bin_of(*ms)] += 1.0;
    }
    for ((lo, hi), count) in DNS_EDGES.iter().zip(dns) {
        if *count == 0 {
            continue;
        }
        let first = bin_of(*lo);
        let last = bin_of(hi * 0.999).max(first);
        let share = *count as f64 / (last - first + 1) as f64;
        for b in &mut bins[first..=last] {
            *b += share;
        }
    }
    bins
}

/// Nearest-rank percentile over sorted samples.
pub fn percentile(sorted: &[f64], q: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = ((q * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    Some(sorted[rank - 1])
}

pub fn ms_label(ms: f64) -> String {
    if ms < 10.0 {
        format!("{ms:.1}ms")
    } else {
        format!("{ms:.0}ms")
    }
}

/// Splits a count for hero display: `3.1` + `M`.
pub fn split_count(n: u64) -> (String, &'static str) {
    if n >= 1_000_000_000 {
        (format!("{:.1}", n as f64 / 1e9), "B")
    } else if n >= 1_000_000 {
        (format!("{:.1}", n as f64 / 1e6), "M")
    } else if n >= 100_000 {
        (format!("{}", n / 1000), "k")
    } else if n >= 10_000 {
        (format!("{:.1}", n as f64 / 1e3), "k")
    } else {
        (grouped(n), "")
    }
}

pub fn split_bytes(n: u64) -> (String, &'static str) {
    let b = n as f64;
    if b >= 1e9 {
        (format!("{:.1}", b / 1e9), "GB")
    } else if b >= 1e6 {
        (format!("{:.1}", b / 1e6), "MB")
    } else if b >= 1e3 {
        (format!("{:.1}", b / 1e3), "KB")
    } else {
        (n.to_string(), "B")
    }
}

/// `1,842`.
pub fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub fn share(part: u64, whole: u64) -> Option<f64> {
    (whole > 0).then(|| part as f64 * 100.0 / whole as f64)
}

/// `98%` above ten, `1.7%` below.
pub fn pct_text(pct: f64) -> String {
    if pct >= 10.0 {
        format!("{pct:.0}%")
    } else {
        format!("{pct:.1}%")
    }
}

pub fn amount_text(value: u64, unit: Unit) -> String {
    match unit {
        Unit::Bytes => crate::format::bytes_total(value),
        Unit::Frames => super::super::compact_count(value),
    }
}
