//! Pure packet-list logic: the filtered, annotated row set, the l7 reading
//! for the info column, expert finding labels, filter diagnostics and
//! per-stream statistics. Nothing here touches egui or a lock.
use netwatch::collectors::packets::{
    matches_packet, CapturedPacket, ExpertSeverity, FilterExpr, Stream, StreamProtocol,
    TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_PSH, TCP_FLAG_RST, TCP_FLAG_SYN,
};
use netwatch::dpi::AppProtocol;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

/// Expert severity as the gutter shows it; `Chat` has no dot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sev {
    Note,
    Warn,
    Error,
}

impl Sev {
    pub fn word(self) -> &'static str {
        match self {
            Sev::Note => "note",
            Sev::Warn => "warn",
            Sev::Error => "error",
        }
    }
}

/// What the list narrows to (`x`, or a navigator finding row).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum Narrow {
    #[default]
    Off,
    AllFindings,
    Finding(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Row {
    pub id: u64,
    pub time: String,
    pub src: String,
    pub dst: String,
    pub proto: String,
    pub len: u32,
    pub info: String,
    pub finding: Option<(Sev, String)>,
    pub decrypted: bool,
    pub stream: Option<u32>,
}

/// One rebuild of the list over the ring.
#[derive(Clone, Debug, Default)]
pub struct Built {
    pub rows: Vec<Row>,
    pub total: usize,
    /// Packets matching the display filter, before narrowing.
    pub matched: usize,
    pub errors: usize,
    pub warns: usize,
    pub notes: usize,
    pub decrypted: usize,
    /// (severity, label) → count over the matched packets.
    pub findings: BTreeMap<(String, Sev), usize>,
    /// Info text for bookmarked packets still in the ring.
    pub bookmark_labels: BTreeMap<u64, String>,
}

impl Built {
    pub fn index_of(&self, id: u64) -> Option<usize> {
        self.rows.binary_search_by_key(&id, |r| r.id).ok()
    }
    pub fn expert_meta(&self) -> String {
        let mut parts = Vec::new();
        if self.errors > 0 {
            parts.push(format!("{} error", self.errors));
        }
        if self.warns > 0 {
            parts.push(format!("{} warn", self.warns));
        }
        if self.notes > 0 {
            parts.push(format!("{} note", self.notes));
        }
        if parts.is_empty() {
            "expert: none".into()
        } else {
            format!("expert: {}", parts.join(" "))
        }
    }
}

/// Derived facts that need the whole ring, not one packet.
#[derive(Default)]
struct Annotations {
    /// packet id → id of the earlier segment it resends.
    retransmit_of: HashMap<u64, u64>,
    /// DNS reply id → milliseconds since its query.
    dns_ms: HashMap<u64, f64>,
}

fn carries_payload(p: &CapturedPacket) -> bool {
    match p.tcp_flags {
        Some(f) if f & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST) != 0 => false,
        Some(f) => f & TCP_FLAG_PSH != 0 || !p.payload_text.is_empty(),
        None => false,
    }
}

fn endpoint(ip: &str, port: Option<u16>) -> String {
    match port {
        Some(port) if ip.contains(':') => format!("[{ip}]:{port}"),
        Some(port) => format!("{ip}:{port}"),
        None => ip.to_string(),
    }
}

fn is_dns(p: &CapturedPacket) -> bool {
    p.protocol.eq_ignore_ascii_case("dns")
        || matches!(p.app_protocol, Some(AppProtocol::Dns { .. }))
}

fn annotate(packets: &[CapturedPacket]) -> Annotations {
    let mut out = Annotations::default();
    // Same judgement as the stream ladder: a sequence number resent in the
    // same direction on a payload-carrying segment is a retransmission.
    let mut seen: HashMap<(u32, bool, u32), u64> = HashMap::new();
    let mut queries: HashMap<u32, VecDeque<u64>> = HashMap::new();
    for p in packets {
        let Some(stream) = p.stream_index else {
            continue;
        };
        let forward = (p.src_ip.as_str(), p.src_port) < (p.dst_ip.as_str(), p.dst_port);
        if let (Some(seq), true) = (p.tcp_seq, carries_payload(p)) {
            match seen.get(&(stream, forward, seq)) {
                Some(first) => {
                    out.retransmit_of.insert(p.id, *first);
                }
                None => {
                    seen.insert((stream, forward, seq), p.id);
                }
            }
        }
        if is_dns(p) {
            if p.src_port == Some(53) {
                if let Some(q) = queries.get_mut(&stream).and_then(|q| q.pop_front()) {
                    out.dns_ms
                        .insert(p.id, p.timestamp_ns.saturating_sub(q) as f64 / 1e6);
                }
            } else {
                queries.entry(stream).or_default().push_back(p.timestamp_ns);
            }
        }
    }
    out
}

/// The expert finding a packet represents, if the crate or the ring flags it.
pub fn finding(p: &CapturedPacket, retransmit: bool) -> Option<(Sev, String)> {
    if retransmit {
        return Some((Sev::Warn, "retransmission".into()));
    }
    let sev = match p.expert {
        ExpertSeverity::Chat => return None,
        ExpertSeverity::Note => Sev::Note,
        ExpertSeverity::Warn => Sev::Warn,
        ExpertSeverity::Error => Sev::Error,
    };
    let info = p.info.to_lowercase();
    let flags = p.tcp_flags.unwrap_or(0);
    let label = if flags & TCP_FLAG_RST != 0 {
        "reset"
    } else if flags & TCP_FLAG_FIN != 0 {
        "teardown"
    } else if info.contains("win=0 ") || info.contains("win=0,") {
        "window full"
    } else if is_dns(p) {
        if sev == Sev::Note {
            "dns reply"
        } else {
            "dns error"
        }
    } else if info.contains("unreachable") {
        "unreachable"
    } else if info.contains("time exceeded") {
        "time exceeded"
    } else if info.contains("redirect") {
        "icmp redirect"
    } else if info.contains("server hello") {
        "server hello"
    } else if p.protocol.eq_ignore_ascii_case("http") {
        "http error"
    } else {
        sev.word()
    };
    Some((sev, label.into()))
}

/// `1.8 ms`, `62 ms`, `1.2 s`.
pub fn ms(v: f64) -> String {
    if v >= 1000.0 {
        format!("{:.1} s", v / 1000.0)
    } else if v >= 10.0 {
        format!("{v:.0} ms")
    } else {
        format!("{v:.1} ms")
    }
}

pub fn qtype_name(qtype: u16) -> String {
    match qtype {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        64 => "SVCB".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        n => format!("type{n}"),
    }
}

/// The l7 reading of a flow's classification (the crate's summary is
/// private; this is the desktop's lowercase, `·`-joined version).
pub fn l7_summary(ap: &AppProtocol) -> String {
    let join =
        |parts: Vec<Option<String>>| parts.into_iter().flatten().collect::<Vec<_>>().join(" · ");
    match ap {
        AppProtocol::Tls {
            sni,
            alpn,
            ech,
            ja4,
        } => join(vec![
            Some("tls".into()),
            sni.as_ref().map(|s| format!("sni {s}")),
            alpn.as_ref().map(|a| a.to_string()),
            ja4.as_ref().map(|j| format!("ja4 {j}")),
            ech.then(|| "ech".into()),
        ]),
        AppProtocol::Quic { sni, ech, ja4 } => join(vec![
            Some("quic".into()),
            sni.as_ref().map(|s| format!("sni {s}")),
            ja4.as_ref().map(|j| format!("ja4q {j}")),
            ech.then(|| "ech".into()),
        ]),
        AppProtocol::Http {
            method,
            host,
            path,
            status,
        } => match status {
            Some(code) => format!("http {code}"),
            None => format!(
                "{method} {}{}",
                host.as_deref().unwrap_or(""),
                path.as_deref().unwrap_or("")
            )
            .trim()
            .to_string(),
        },
        AppProtocol::Dns {
            qname,
            qtype,
            rcode,
        } => match rcode {
            Some(rc) => format!(
                "{} {qname} · {}",
                qtype_name(*qtype),
                netwatch::dpi::dns::rcode_label(*rc).to_lowercase()
            ),
            None => format!("{} {qname} · query", qtype_name(*qtype)),
        },
        AppProtocol::Ssh { version } => format!("ssh {version}"),
        AppProtocol::Mqtt { client_id } => join(vec![
            Some("mqtt".into()),
            client_id.as_ref().map(|c| format!("client {c}")),
        ]),
        AppProtocol::Stun { message_type } => format!("stun {message_type}"),
        AppProtocol::BitTorrent { info_hash } => join(vec![
            Some("bittorrent".into()),
            info_hash.as_ref().map(|h| format!("info_hash {h}")),
        ]),
        AppProtocol::NetBios { service } => format!("netbios {service}"),
        AppProtocol::Snmp { version, community } => join(vec![
            Some(format!("snmp {version}")),
            community.as_ref().map(|c| format!("community {c}")),
        ]),
        AppProtocol::Ssdp { method, target } => {
            join(vec![Some(format!("ssdp {method}")), target.clone()])
        }
        AppProtocol::Ftp { command } => format!("ftp {command}"),
        AppProtocol::Llmnr { qname, qtype } => format!("llmnr {} {qname}", qtype_name(*qtype)),
        AppProtocol::Dhcp { op } => match op {
            1 => "dhcp request".into(),
            2 => "dhcp reply".into(),
            n => format!("dhcp op {n}"),
        },
        AppProtocol::Ntp { version, mode } => format!("ntp v{version} mode {mode}"),
    }
}

/// `syn`, `syn·ack`, `fin·ack`, `rst`, `psh·ack`, `ack`.
pub fn flag_words(flags: u8) -> String {
    let mut words = Vec::new();
    for (bit, word) in [
        (TCP_FLAG_SYN, "syn"),
        (TCP_FLAG_FIN, "fin"),
        (TCP_FLAG_RST, "rst"),
        (TCP_FLAG_PSH, "psh"),
        (TCP_FLAG_ACK, "ack"),
    ] {
        if flags & bit != 0 {
            words.push(word);
        }
    }
    words.join("·")
}

/// The crate's info line without the `src:port → dst:port` prefix the list
/// already shows in its own columns.
pub fn strip_endpoints(info: &str) -> String {
    let trimmed = info.trim();
    if let Some((left, right)) = trimmed.split_once(" → ") {
        if !left.contains(' ') {
            let rest = right.split_once(' ').map(|(_, r)| r).unwrap_or("");
            return rest.trim().to_string();
        }
    }
    trimmed.to_string()
}

/// A short reading of HTTP/2 or HTTP/1 decrypted bytes for the info column.
pub fn plaintext_reading(bytes: &[u8], alpn: Option<&str>) -> Option<String> {
    if let Some(frames) = super::decode::h2_frames(bytes, alpn) {
        let first = frames.first()?;
        return Some(format!("h2 {} · stream {}", first.kind, first.stream));
    }
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(200)]);
    let line = text.lines().next()?.trim();
    (!line.is_empty() && line.chars().all(|c| !c.is_control()))
        .then(|| line.chars().take(80).collect())
}

fn info_text(p: &CapturedPacket, notes: &Annotations) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(first) = notes.retransmit_of.get(&p.id) {
        parts.push(format!("retransmission of #{first}"));
    }
    let flags = p.tcp_flags.unwrap_or(0);
    let control = flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST) != 0;
    let bare = strip_endpoints(&p.info);
    let lower = bare.to_lowercase();
    match (&p.app_protocol, &p.decrypted_plaintext) {
        (Some(ap @ AppProtocol::Tls { alpn, .. }), Some(plain)) => {
            parts.push("application data · decrypted".into());
            if let Some(reading) = plaintext_reading(plain, alpn.as_deref()) {
                parts.push(reading);
            }
            let _ = ap;
        }
        (_, Some(plain)) => {
            parts.push("decrypted".into());
            if let Some(reading) = plaintext_reading(plain, None) {
                parts.push(reading);
            }
        }
        (Some(ap @ (AppProtocol::Tls { .. } | AppProtocol::Quic { .. })), None) if !control => {
            if lower.contains("client hello") {
                parts.push("client hello".into());
            } else if lower.contains("server hello") {
                parts.push("server hello".into());
            } else if lower.contains("application data") {
                parts.push("application data".into());
            } else if matches!(ap, AppProtocol::Quic { .. }) && lower.contains("initial") {
                parts.push("initial".into());
            }
            parts.push(l7_summary(ap));
        }
        (Some(ap), None) if !control => parts.push(l7_summary(ap)),
        _ => {
            if !bare.is_empty() {
                parts.push(bare);
            } else if p.tcp_flags.is_some() {
                let mut text = flag_words(flags);
                if let Some(seq) = p.tcp_seq {
                    text.push_str(&format!(" · seq {seq}"));
                }
                parts.push(text);
            } else {
                parts.push(p.protocol.to_lowercase());
            }
        }
    }
    if let Some(v) = notes.dns_ms.get(&p.id) {
        parts.push(ms(*v));
    }
    parts.join(" · ")
}

/// `tls 1.3` when the stream's negotiated suite says so, else the crate's
/// protocol name in lowercase.
pub fn proto_label(p: &CapturedPacket, suites: &HashMap<u32, u16>) -> String {
    let proto = p.protocol.to_lowercase();
    if proto == "tls" {
        if let Some(suite) = p.stream_index.and_then(|i| suites.get(&i)) {
            return format!("tls {}", tls_version(*suite));
        }
    }
    proto
}

/// TLS 1.3 suites live in 0x13xx; anything else negotiated is ≤ 1.2.
pub fn tls_version(suite: u16) -> &'static str {
    if suite >> 8 == 0x13 {
        "1.3"
    } else {
        "≤1.2"
    }
}

pub fn build(
    packets: &[CapturedPacket],
    expr: Option<&FilterExpr>,
    narrow: &Narrow,
    bookmarks: &BTreeSet<u64>,
    suites: &HashMap<u32, u16>,
) -> Built {
    let notes = annotate(packets);
    let mut out = Built {
        total: packets.len(),
        ..Default::default()
    };
    for p in packets {
        if expr.is_some_and(|e| !matches_packet(e, p)) {
            if bookmarks.contains(&p.id) {
                out.bookmark_labels.insert(p.id, info_text(p, &notes));
            }
            continue;
        }
        out.matched += 1;
        let finding = finding(p, notes.retransmit_of.contains_key(&p.id));
        if let Some((sev, label)) = &finding {
            match sev {
                Sev::Error => out.errors += 1,
                Sev::Warn => out.warns += 1,
                Sev::Note => out.notes += 1,
            }
            *out.findings.entry((label.clone(), *sev)).or_default() += 1;
        }
        let decrypted = p.decrypted_plaintext.is_some();
        if decrypted {
            out.decrypted += 1;
        }
        let keep = match narrow {
            Narrow::Off => true,
            Narrow::AllFindings => finding.is_some(),
            Narrow::Finding(label) => finding.as_ref().is_some_and(|(_, l)| l == label),
        };
        let info = info_text(p, &notes);
        if bookmarks.contains(&p.id) {
            out.bookmark_labels.insert(p.id, info.clone());
        }
        if !keep {
            continue;
        }
        out.rows.push(Row {
            id: p.id,
            time: p.timestamp.clone(),
            src: endpoint(&p.src_ip, p.src_port),
            dst: endpoint(&p.dst_ip, p.dst_port),
            proto: proto_label(p, suites),
            len: p.length,
            info,
            finding,
            decrypted,
            stream: p.stream_index,
        });
    }
    out.rows.sort_by_key(|r| r.id);
    out
}

// ------------------------------------------------------------ filters

/// Why `text` does not parse, in the field's error colour. None when it
/// parses (or is empty).
pub fn filter_error(text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() || netwatch::collectors::packets::parse_filter(text).is_some() {
        return None;
    }
    if text.matches('"').count() % 2 == 1 || text.matches('\'').count() % 2 == 1 {
        return Some("unclosed quote".into());
    }
    let tokens: Vec<&str> = text.split_whitespace().collect();
    let is_op = |t: &str| t.eq_ignore_ascii_case("and") || t.eq_ignore_ascii_case("or");
    if let Some(first) = tokens.first() {
        if is_op(first) {
            return Some(format!(
                "`{}` needs a term on its left",
                first.to_lowercase()
            ));
        }
    }
    if let Some(last) = tokens.last() {
        if is_op(last) || last.eq_ignore_ascii_case("not") || *last == "!" {
            return Some(format!("expression ends after `{}`", last.to_lowercase()));
        }
    }
    for (i, t) in tokens.iter().enumerate() {
        let lower = t.to_lowercase();
        for flag in ["ech:", "decrypted:"] {
            if let Some(v) = lower.strip_prefix(flag) {
                if v != "true" && v != "false" {
                    return Some(format!("{flag} takes true or false"));
                }
            }
        }
        if lower == "port"
            && tokens
                .get(i + 1)
                .is_none_or(|n| n.parse::<u16>().is_err() && *n != "==")
        {
            return Some("port needs a number 0–65535".into());
        }
        if lower == "stream" && tokens.get(i + 1).is_none_or(|n| n.parse::<u32>().is_err()) {
            return Some("stream needs a number".into());
        }
        if (lower == "ip.src" || lower == "ip.dst") && tokens.get(i + 1) != Some(&"==") {
            return Some(format!("{lower} needs == <address>"));
        }
    }
    Some("terms need and / or between them".into())
}

/// A navigator or drill filter as a display-filter expression.
pub fn filter_expression(filter: &crate::shell::Filter) -> Option<String> {
    use crate::shell::Filter;
    match filter {
        Filter::Display(e) => Some(e.trim().to_string()),
        Filter::Stream(n) => Some(format!("stream {n}")),
        Filter::Host(host) => {
            let host = host.trim();
            // `ip:port` (IPv4) or `[v6]:port`.
            let (addr, port) = match host.rsplit_once(':') {
                Some((a, p))
                    if p.parse::<u16>().is_ok() && (!a.contains(':') || a.starts_with('[')) =>
                {
                    (a.trim_matches(|c| c == '[' || c == ']'), Some(p))
                }
                _ => (host, None),
            };
            let is_ip = addr.parse::<std::net::IpAddr>().is_ok();
            let port = port.map(|p| format!(" and port {p}")).unwrap_or_default();
            Some(if is_ip && !addr.contains(':') {
                format!("{addr}{port}")
            } else if is_ip {
                format!("contains \"{addr}\"{port}")
            } else {
                // `and` binds tighter than `or`, and the language has no
                // parentheses, so the port clause is repeated per side.
                format!("host:{addr}{port} or sni:{addr}{port}")
            })
        }
        Filter::Process { .. } | Filter::Iface(_) => None,
    }
}

// ------------------------------------------------------------ streams

/// The per-packet facts a stream summary needs, copied out of the ring.
#[derive(Clone, Debug)]
pub struct Lite {
    pub id: u64,
    pub ns: u64,
    pub src: (String, u16),
    pub payload: bool,
    pub decrypted: bool,
    pub dns_reply: Option<bool>,
}

impl Lite {
    pub fn of(p: &CapturedPacket) -> Self {
        Self {
            id: p.id,
            ns: p.timestamp_ns,
            src: (p.src_ip.clone(), p.src_port.unwrap_or(0)),
            payload: carries_payload(p) || (p.tcp_flags.is_none() && !p.raw_bytes.is_empty()),
            decrypted: p.decrypted_plaintext.is_some(),
            dns_reply: is_dns(p).then_some(p.src_port == Some(53)),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DnsStats {
    pub queries: usize,
    pub replies: usize,
    pub p50: Option<f64>,
    pub p95: Option<f64>,
}

#[derive(Clone, Debug)]
pub struct StreamInfo {
    pub index: u32,
    pub udp: bool,
    /// Initiator first when known; otherwise the key's order.
    pub client: (String, u16),
    pub server: (String, u16),
    pub client_is_a: bool,
    pub packets: u32,
    /// Direction chips name the endpoints as shown: a is the client
    /// (initiator), b the server — not the tracker's lexical key order.
    pub ids_ab: Vec<u64>,
    pub ids_ba: Vec<u64>,
    pub bytes_ab: u64,
    pub bytes_ba: u64,
    pub retrans: u32,
    pub handshake_ms: Option<f64>,
    pub app: Option<AppProtocol>,
    pub suite: Option<u16>,
    pub decrypted: bool,
    pub keylog_without_hello: bool,
    pub first_ns: u64,
    pub last_ns: u64,
    /// Request → first response byte, milliseconds, oldest first.
    pub gaps: Vec<f64>,
    pub dns: Option<DnsStats>,
    pub ja4_flows: usize,
}

impl StreamInfo {
    pub fn ja4(&self) -> Option<&str> {
        match &self.app {
            Some(AppProtocol::Tls { ja4, .. }) | Some(AppProtocol::Quic { ja4, .. }) => {
                ja4.as_deref()
            }
            _ => None,
        }
    }
    pub fn encrypted(&self) -> bool {
        matches!(
            self.app,
            Some(AppProtocol::Tls { .. }) | Some(AppProtocol::Quic { .. })
        )
    }
}

pub fn percentile(sorted: &[f64], q: f64) -> Option<f64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted.get(rank).copied()
}

pub fn summarize(lites: &[Lite], stream: &Stream, ja4_flows: usize) -> StreamInfo {
    let a = stream.key.addr_a.clone();
    let b = stream.key.addr_b.clone();
    let mut sorted: Vec<&Lite> = lites.iter().collect();
    sorted.sort_by_key(|l| l.ns);
    let initiator = stream
        .initiator
        .clone()
        .or_else(|| sorted.first().map(|l| l.src.clone()));
    let client_is_a = initiator.as_ref().is_none_or(|i| *i == a);
    let (client, server) = if client_is_a {
        (a.clone(), b)
    } else {
        (b, a.clone())
    };

    let mut ids_ab = Vec::new();
    let mut ids_ba = Vec::new();
    let mut gaps = Vec::new();
    let mut pending: Option<u64> = None;
    let mut dns = DnsStats::default();
    let mut dns_pending: VecDeque<u64> = VecDeque::new();
    let mut dns_ms = Vec::new();
    for l in &sorted {
        if l.src == client {
            ids_ab.push(l.id);
        } else {
            ids_ba.push(l.id);
        }
        let from_client = l.src == client;
        if l.payload {
            if from_client {
                pending.get_or_insert(l.ns);
            } else if let Some(req) = pending.take() {
                gaps.push(l.ns.saturating_sub(req) as f64 / 1e6);
            }
        }
        match l.dns_reply {
            Some(false) => {
                dns.queries += 1;
                dns_pending.push_back(l.ns);
            }
            Some(true) => {
                dns.replies += 1;
                if let Some(q) = dns_pending.pop_front() {
                    dns_ms.push(l.ns.saturating_sub(q) as f64 / 1e6);
                }
            }
            None => {}
        }
    }
    dns_ms.sort_by(f64::total_cmp);
    dns.p50 = percentile(&dns_ms, 0.5);
    dns.p95 = percentile(&dns_ms, 0.95);
    let is_dns = dns.queries + dns.replies > 0;
    let decrypted =
        lites.iter().any(|l| l.decrypted) || stream.segments.iter().any(|s| s.decrypted.is_some());
    StreamInfo {
        index: stream.index,
        udp: stream.key.protocol == StreamProtocol::Udp,
        client,
        server,
        client_is_a,
        packets: stream.packet_count.max(lites.len() as u32),
        ids_ab,
        ids_ba,
        bytes_ab: if client_is_a {
            stream.total_bytes_a_to_b
        } else {
            stream.total_bytes_b_to_a
        },
        bytes_ba: if client_is_a {
            stream.total_bytes_b_to_a
        } else {
            stream.total_bytes_a_to_b
        },
        retrans: stream.retransmits_a_to_b + stream.retransmits_b_to_a,
        handshake_ms: stream.handshake.as_ref().and_then(|h| h.total_ms()),
        app: stream.app_protocol.clone(),
        suite: stream.tls_cipher_suite,
        decrypted,
        keylog_without_hello: stream.tls_decrypt_disabled && stream.tls_client_random.is_none(),
        first_ns: sorted.first().map(|l| l.ns).unwrap_or(0),
        last_ns: sorted.last().map(|l| l.ns).unwrap_or(0),
        gaps,
        dns: is_dns.then_some(dns),
        ja4_flows,
    }
}

/// One line of prose under the plot, built only from measured values.
pub fn stream_prose(info: &StreamInfo, baseline_ms: Option<f64>) -> String {
    if let Some(dns) = &info.dns {
        let mut text = format!("{} queries, {} replies", dns.queries, dns.replies);
        match (dns.p50, dns.p95) {
            (Some(p50), Some(p95)) => {
                text.push_str(&format!("; p50 {} · p95 {}", ms(p50), ms(p95)))
            }
            _ => text.push_str("; no answered query in the ring"),
        }
        match baseline_ms {
            Some(base) => text.push_str(&format!(" vs resolver baseline {}.", ms(base))),
            None => text.push_str("; resolver baseline still learning."),
        }
        return text;
    }
    let lead = match (info.handshake_ms, info.udp) {
        (Some(h), _) => format!("tcp handshake {}", ms(h)),
        (None, true) => "udp flow, no handshake".into(),
        (None, false) => "handshake predates capture".into(),
    };
    match (info.gaps.first(), info.gaps.last()) {
        (Some(first), Some(last)) if info.gaps.len() > 1 => format!(
            "{lead}; first response {} after its request, latest {} over {} exchanges.",
            ms(*first),
            ms(*last),
            info.gaps.len()
        ),
        (Some(first), _) => format!("{lead}; first response {} after its request.", ms(*first)),
        _ => format!("{lead}; no request/response exchange in the ring yet."),
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub fn packet(id: u64, src: (&str, u16), dst: (&str, u16), proto: &str) -> CapturedPacket {
        CapturedPacket {
            id,
            timestamp: format!("06:51:22.{id:03}"),
            src_ip: src.0.into(),
            dst_ip: dst.0.into(),
            src_host: None,
            dst_host: None,
            protocol: proto.into(),
            length: 66,
            src_port: Some(src.1),
            dst_port: Some(dst.1),
            info: String::new(),
            details: vec![],
            payload_text: String::new(),
            raw_hex: String::new(),
            raw_ascii: String::new(),
            raw_bytes: vec![],
            stream_index: Some(7),
            tcp_flags: None,
            tcp_seq: None,
            expert: ExpertSeverity::Chat,
            timestamp_ns: id * 1_000_000,
            app_protocol: None,
            decrypted_plaintext: None,
        }
    }

    #[test]
    fn retransmission_is_flagged_and_counted() {
        let c = ("10.0.0.2", 5000);
        let s = ("10.0.0.3", 443);
        let mut p1 = packet(1, c, s, "TCP");
        p1.tcp_flags = Some(TCP_FLAG_PSH | TCP_FLAG_ACK);
        p1.tcp_seq = Some(100);
        let mut p2 = packet(2, s, c, "TCP");
        p2.tcp_flags = Some(TCP_FLAG_ACK);
        p2.tcp_seq = Some(900);
        let mut p3 = p1.clone();
        p3.id = 3;
        let built = build(
            &[p1, p2, p3],
            None,
            &Narrow::Off,
            &BTreeSet::new(),
            &HashMap::new(),
        );
        assert_eq!(built.rows.len(), 3);
        assert_eq!(built.warns, 1);
        assert!(built.rows[2].info.starts_with("retransmission of #1"));
        assert_eq!(built.rows[1].info, "ack · seq 900");
        assert_eq!(
            built
                .findings
                .get(&("retransmission".to_string(), Sev::Warn)),
            Some(&1)
        );
        let narrowed = build(
            &built_packets(),
            None,
            &Narrow::AllFindings,
            &BTreeSet::new(),
            &HashMap::new(),
        );
        assert!(narrowed.rows.iter().all(|r| r.finding.is_some()));
    }

    fn built_packets() -> Vec<CapturedPacket> {
        let mut rst = packet(4, ("1.1.1.1", 1), ("2.2.2.2", 2), "TCP");
        rst.tcp_flags = Some(TCP_FLAG_RST);
        rst.expert = ExpertSeverity::Error;
        vec![packet(1, ("1.1.1.1", 1), ("2.2.2.2", 2), "TCP"), rst]
    }

    #[test]
    fn dns_reply_carries_latency_and_l7_reading() {
        let mut q = packet(10, ("10.0.0.2", 5353), ("169.254.1.1", 53), "DNS");
        q.app_protocol = Some(AppProtocol::Dns {
            qname: "api.github.com".into(),
            qtype: 1,
            rcode: None,
        });
        let mut r = packet(14, ("169.254.1.1", 53), ("10.0.0.2", 5353), "DNS");
        r.timestamp_ns = q.timestamp_ns + 62_000_000;
        r.app_protocol = Some(AppProtocol::Dns {
            qname: "api.github.com".into(),
            qtype: 1,
            rcode: Some(0),
        });
        r.expert = ExpertSeverity::Note;
        let built = build(
            &[q, r],
            None,
            &Narrow::Off,
            &BTreeSet::new(),
            &HashMap::new(),
        );
        assert_eq!(built.rows[0].info, "A api.github.com · query");
        assert!(built.rows[1].info.starts_with("A api.github.com · "));
        assert!(
            built.rows[1].info.ends_with("· 62 ms"),
            "{}",
            built.rows[1].info
        );
        assert_eq!(built.rows[1].finding, Some((Sev::Note, "dns reply".into())));
    }

    #[test]
    fn tls_summary_and_endpoint_stripping() {
        let ap = AppProtocol::Tls {
            sni: Some("ingest.internal".into()),
            alpn: Some("h2".into()),
            ech: true,
            ja4: Some("t13d".into()),
        };
        assert_eq!(
            l7_summary(&ap),
            "tls · sni ingest.internal · h2 · ja4 t13d · ech"
        );
        assert_eq!(
            strip_endpoints("10.0.0.1:5 → 10.0.0.2:443 [PSH, ACK] Seq=1"),
            "[PSH, ACK] Seq=1"
        );
        assert_eq!(strip_endpoints("Standard query A x"), "Standard query A x");
        assert_eq!(tls_version(0x1302), "1.3");
        assert_eq!(tls_version(0xc02f), "≤1.2");
    }

    #[test]
    fn filter_reasons_and_translation() {
        use crate::shell::Filter;
        assert_eq!(filter_error("tcp and port 443"), None);
        assert_eq!(filter_error(""), None);
        assert_eq!(
            filter_error("tcp and").as_deref(),
            Some("expression ends after `and`")
        );
        assert_eq!(
            filter_error("ech:maybe").as_deref(),
            Some("ech: takes true or false")
        );
        assert_eq!(
            filter_error("stream x").as_deref(),
            Some("stream needs a number")
        );
        assert_eq!(
            filter_error("foo bar").as_deref(),
            Some("terms need and / or between them")
        );
        assert_eq!(
            filter_expression(&Filter::Host("10.88.0.3".into())).as_deref(),
            Some("10.88.0.3")
        );
        assert_eq!(
            filter_expression(&Filter::Host("10.88.0.3:9000".into())).as_deref(),
            Some("10.88.0.3 and port 9000")
        );
        assert_eq!(
            filter_expression(&Filter::Stream(7)).as_deref(),
            Some("stream 7")
        );
        for f in [
            "10.88.0.3 and port 9000",
            "stream 7",
            "host:example.com or sni:example.com",
        ] {
            assert!(
                netwatch::collectors::packets::parse_filter(f).is_some(),
                "{f}"
            );
        }
        assert_eq!(
            filter_expression(&Filter::Host("example.com".into())).as_deref(),
            Some("host:example.com or sni:example.com")
        );
    }

    #[test]
    fn stream_summary_gaps_dns_and_prose() {
        use netwatch::collectors::packets::{StreamKey, TcpHandshake};
        let mut stream = Stream::new(
            7,
            StreamKey::new(StreamProtocol::Tcp, "10.0.0.2", 5000, "10.0.0.3", 443),
            0,
        );
        stream.initiator = Some(("10.0.0.2".into(), 5000));
        stream.handshake = Some(TcpHandshake {
            syn_ns: 0,
            syn_ack_ns: Some(1_000_000),
            ack_ns: Some(1_800_000),
        });
        let lite = |id: u64, ms: u64, from_client: bool| Lite {
            id,
            ns: ms * 1_000_000,
            src: if from_client {
                ("10.0.0.2".into(), 5000)
            } else {
                ("10.0.0.3".into(), 443)
            },
            payload: true,
            decrypted: false,
            dns_reply: None,
        };
        let lites = vec![
            lite(1, 10, true),
            lite(2, 22, false),
            lite(3, 30, true),
            lite(4, 214, false),
        ];
        let info = summarize(&lites, &stream, 3);
        assert_eq!(info.gaps, vec![12.0, 184.0]);
        assert_eq!(info.ids_ab, vec![1, 3]);
        assert_eq!(info.handshake_ms, Some(1.8));
        assert!(info.dns.is_none());
        let prose = stream_prose(&info, None);
        assert!(prose.starts_with("tcp handshake"), "{prose}");
        assert!(prose.contains("2 exchanges"));
        assert_eq!(percentile(&[1.0, 2.0, 3.0, 4.0, 100.0], 0.5), Some(3.0));
    }
}
