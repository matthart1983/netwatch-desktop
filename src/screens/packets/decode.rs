//! The layered decode: one layer per protocol, deepest last, with the byte
//! span each layer occupies in the frame when the headers let us derive it.
use netwatch::collectors::packets::CapturedPacket;
use netwatch::dpi::AppProtocol;
use std::ops::Range;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Wire,
    /// A layer whose payload was decrypted (tls/quic with a keylog).
    Decrypted,
    /// The decrypted application layer.
    L7,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Layer {
    pub name: String,
    pub summary: String,
    pub rows: Vec<(String, String)>,
    pub span: Option<Range<usize>>,
    pub kind: Kind,
}

/// Byte ranges of each header in an Ethernet frame, derived from the header
/// lengths the frame itself declares.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Offsets {
    pub ethernet: Option<Range<usize>>,
    pub network: Option<Range<usize>>,
    pub transport: Option<Range<usize>>,
    pub payload: Option<Range<usize>>,
}

fn be16(b: &[u8], at: usize) -> Option<usize> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]) as usize)
}

pub fn offsets(raw: &[u8]) -> Offsets {
    let mut out = Offsets::default();
    let Some(mut ethertype) = be16(raw, 12) else {
        return out;
    };
    let mut l2 = 14;
    if ethertype == 0x8100 {
        let Some(inner) = be16(raw, 16) else {
            return out;
        };
        ethertype = inner;
        l2 = 18;
    }
    if raw.len() < l2 {
        return out;
    }
    out.ethernet = Some(0..l2);
    let (proto, transport_start, end) = match ethertype {
        0x0800 => {
            let Some(&vihl) = raw.get(l2) else {
                return out;
            };
            let ihl = (vihl & 0x0f) as usize * 4;
            if vihl >> 4 != 4 || ihl < 20 || raw.len() < l2 + ihl {
                return out;
            }
            out.network = Some(l2..l2 + ihl);
            let total = be16(raw, l2 + 2).unwrap_or(0);
            let end = if total >= ihl {
                (l2 + total).min(raw.len())
            } else {
                raw.len()
            };
            (raw[l2 + 9], l2 + ihl, end)
        }
        0x86dd => {
            if raw.len() < l2 + 40 || raw[l2] >> 4 != 6 {
                return out;
            }
            out.network = Some(l2..l2 + 40);
            let payload = be16(raw, l2 + 4).unwrap_or(0);
            (raw[l2 + 6], l2 + 40, (l2 + 40 + payload).min(raw.len()))
        }
        0x0806 => {
            out.network = Some(l2..raw.len());
            return out;
        }
        _ => return out,
    };
    match proto {
        6 => {
            let Some(&off) = raw.get(transport_start + 12) else {
                return out;
            };
            let doff = (off >> 4) as usize * 4;
            if doff >= 20 && transport_start + doff <= end {
                out.transport = Some(transport_start..transport_start + doff);
                if transport_start + doff < end {
                    out.payload = Some(transport_start + doff..end);
                }
            }
        }
        17 => {
            if transport_start + 8 <= end {
                out.transport = Some(transport_start..transport_start + 8);
                if transport_start + 8 < end {
                    out.payload = Some(transport_start + 8..end);
                }
            }
        }
        1 | 58 if transport_start < end => out.transport = Some(transport_start..end),
        _ => {}
    }
    out
}

/// `Key: value, Key: [A, B]` → `key value · key a b`.
pub fn humanize(text: &str) -> String {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut current = String::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '[' | '(' => depth += 1,
            ']' | ')' => depth -= 1,
            _ => {}
        }
        if c == ',' && depth == 0 && chars.get(i + 1) == Some(&' ') {
            parts.push(std::mem::take(&mut current));
            i += 2;
            continue;
        }
        current.push(c);
        i += 1;
    }
    parts.push(current);
    parts
        .into_iter()
        .map(|part| {
            let part = part.replace(" (—)", "").replace(" -> ", " → ");
            match part.split_once(": ") {
                Some((k, v))
                    if k.len() <= 12 && k.chars().all(|c| c.is_alphabetic() || c == ' ') =>
                {
                    let v = v.trim();
                    let v = if v.starts_with('[') {
                        v.trim_matches(|c| c == '[' || c == ']')
                            .replace(", ", " ")
                            .to_lowercase()
                    } else {
                        v.to_string()
                    };
                    format!("{} {v}", k.to_lowercase())
                }
                _ => part,
            }
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

#[derive(Clone, Debug, PartialEq)]
pub struct H2Frame {
    pub kind: &'static str,
    pub stream: u32,
    pub len: usize,
    pub flags: Vec<&'static str>,
}

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// HTTP/2 frame headers in decrypted bytes. Only attempted when the flow
/// negotiated `h2` or the client preface is present, so arbitrary binary is
/// never dressed up as frames.
pub fn h2_frames(bytes: &[u8], alpn: Option<&str>) -> Option<Vec<H2Frame>> {
    let mut at = 0;
    if bytes.starts_with(H2_PREFACE) {
        at = H2_PREFACE.len();
    } else if alpn != Some("h2") {
        return None;
    }
    let mut frames = Vec::new();
    while at + 9 <= bytes.len() && frames.len() < 16 {
        let len =
            (bytes[at] as usize) << 16 | (bytes[at + 1] as usize) << 8 | bytes[at + 2] as usize;
        let ty = bytes[at + 3];
        let fl = bytes[at + 4];
        let stream =
            u32::from_be_bytes([bytes[at + 5], bytes[at + 6], bytes[at + 7], bytes[at + 8]])
                & 0x7fff_ffff;
        let kind = match ty {
            0 => "DATA",
            1 => "HEADERS",
            2 => "PRIORITY",
            3 => "RST_STREAM",
            4 => "SETTINGS",
            5 => "PUSH_PROMISE",
            6 => "PING",
            7 => "GOAWAY",
            8 => "WINDOW_UPDATE",
            9 => "CONTINUATION",
            _ => {
                return if frames.is_empty() {
                    None
                } else {
                    Some(frames)
                }
            }
        };
        if len > (1 << 24) - 1 {
            break;
        }
        let mut flags = Vec::new();
        if matches!(ty, 0 | 1) && fl & 0x1 != 0 {
            flags.push("end_stream");
        }
        if matches!(ty, 1 | 5 | 9) && fl & 0x4 != 0 {
            flags.push("end_headers");
        }
        if matches!(ty, 4 | 6) && fl & 0x1 != 0 {
            flags.push("ack");
        }
        frames.push(H2Frame {
            kind,
            stream,
            len,
            flags,
        });
        at += 9 + len;
    }
    (!frames.is_empty()).then_some(frames)
}

fn printable_ratio(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let sample = &bytes[..bytes.len().min(512)];
    sample
        .iter()
        .filter(|b| b.is_ascii_graphic() || matches!(b, b' ' | b'\r' | b'\n' | b'\t'))
        .count() as f32
        / sample.len() as f32
}

/// The decrypted application layer.
pub fn l7_layer(plain: &[u8], alpn: Option<&str>, span: Option<Range<usize>>) -> Layer {
    if let Some(frames) = h2_frames(plain, alpn) {
        let first = &frames[0];
        let mut summary = format!("{} · stream {}", first.kind, first.stream);
        for f in &first.flags {
            summary.push_str(&format!(" · {f}"));
        }
        let mut rows: Vec<(String, String)> = frames
            .iter()
            .map(|f| {
                let mut v = format!("stream {} · {} B", f.stream, f.len);
                for flag in &f.flags {
                    v.push_str(&format!(" · {flag}"));
                }
                (f.kind.to_string(), v)
            })
            .collect();
        if frames.iter().any(|f| f.kind == "HEADERS") {
            rows.push(("fields".into(), "hpack-compressed, not decoded here".into()));
        }
        return Layer {
            name: "http/2".into(),
            summary,
            rows,
            span,
            kind: Kind::L7,
        };
    }
    if printable_ratio(plain) > 0.85 {
        let text = String::from_utf8_lossy(plain);
        let mut lines = text.lines();
        let first = lines.next().unwrap_or("").trim().to_string();
        let http = first.contains("HTTP/1.");
        let mut rows = Vec::new();
        for line in lines.take(14) {
            if line.trim().is_empty() {
                break;
            }
            match line.split_once(':') {
                Some((k, v)) if http => rows.push((k.trim().to_lowercase(), v.trim().to_string())),
                _ => rows.push((String::new(), line.trim().to_string())),
            }
        }
        return Layer {
            name: if http {
                "http/1.1".into()
            } else {
                "plaintext".into()
            },
            summary: first.chars().take(120).collect(),
            rows,
            span,
            kind: Kind::L7,
        };
    }
    Layer {
        name: "plaintext".into(),
        summary: format!("{} B binary", plain.len()),
        rows: vec![],
        span,
        kind: Kind::L7,
    }
}

fn app_rows(ap: &AppProtocol) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    let mut put = |k: &str, v: Option<String>| {
        if let Some(v) = v {
            rows.push((k.to_string(), v));
        }
    };
    match ap {
        AppProtocol::Tls {
            sni,
            alpn,
            ech,
            ja4,
        } => {
            put("sni", sni.clone());
            put("alpn", alpn.clone());
            put("ja4", ja4.clone());
            put("ech", Some(if *ech { "yes" } else { "no" }.into()));
        }
        AppProtocol::Quic { sni, ech, ja4 } => {
            put("sni", sni.clone());
            put("ja4q", ja4.clone());
            put("ech", Some(if *ech { "yes" } else { "no" }.into()));
        }
        AppProtocol::Dns {
            qname,
            qtype,
            rcode,
        } => {
            put("qname", Some(qname.clone()));
            put("qtype", Some(super::model::qtype_name(*qtype)));
            put(
                "rcode",
                rcode.map(|r| netwatch::dpi::dns::rcode_label(r).to_lowercase()),
            );
        }
        AppProtocol::Http {
            method,
            host,
            path,
            status,
        } => {
            put("method", (!method.is_empty()).then(|| method.clone()));
            put("host", host.clone());
            put("path", path.clone());
            put("status", status.map(|s| s.to_string()));
        }
        _ => {}
    }
    rows
}

/// Rank of a details prefix in the layer order; None for app layers.
fn rank(prefix: &str) -> Option<u8> {
    match prefix {
        "Frame" => Some(0),
        "Ethernet" => Some(1),
        "IPv4" | "IPv6" | "ARP" => Some(2),
        "TCP" | "UDP" | "ICMP" | "ICMPv6" => Some(3),
        _ => None,
    }
}

/// The decode tree for one packet. `tls_version` names the tls layer when
/// the stream's negotiated suite is known.
pub fn layers(p: &CapturedPacket, tls_version: Option<&str>) -> Vec<Layer> {
    let framed = p.details.iter().any(|d| d.starts_with("Ethernet:"));
    let off = if framed {
        offsets(&p.raw_bytes)
    } else {
        Offsets::default()
    };
    let names_line = (p.src_host.is_some() || p.dst_host.is_some())
        .then(|| p.details.last().filter(|d| d.starts_with("DNS: ")))
        .flatten();
    let decrypted = p.decrypted_plaintext.is_some();
    let mut ranked: Vec<(u8, Layer)> = Vec::new();
    let mut names: Option<String> = None;
    for (i, line) in p.details.iter().enumerate() {
        if names_line.is_some_and(|n| std::ptr::eq(n, line)) && i + 1 == p.details.len() {
            names = line.strip_prefix("DNS: ").map(str::to_string);
            continue;
        }
        let (prefix, rest) = line.split_once(": ").unwrap_or((line.as_str(), ""));
        let (r, name, span, kind) = match rank(prefix) {
            Some(0) => (
                0,
                "frame".to_string(),
                framed.then_some(0..p.raw_bytes.len()),
                Kind::Wire,
            ),
            Some(1) => (1, "ethernet ii".into(), off.ethernet.clone(), Kind::Wire),
            Some(2) => (2, prefix.to_lowercase(), off.network.clone(), Kind::Wire),
            Some(_) => (3, prefix.to_lowercase(), off.transport.clone(), Kind::Wire),
            None => {
                let mut name = prefix.to_lowercase();
                if name == "tls" {
                    if let Some(v) = tls_version {
                        name = format!("tls {v}");
                    }
                }
                (
                    4,
                    name,
                    off.payload.clone(),
                    if decrypted {
                        Kind::Decrypted
                    } else {
                        Kind::Wire
                    },
                )
            }
        };
        let mut summary = humanize(rest);
        if r == 4 && decrypted {
            summary.push_str(" · decrypted (keylog)");
        }
        let mut rows = Vec::new();
        if r == 4 {
            if let Some(ap) = &p.app_protocol {
                rows = app_rows(ap);
            }
        }
        ranked.push((
            r,
            Layer {
                name,
                summary,
                rows,
                span,
                kind,
            },
        ));
    }
    if !ranked.iter().any(|(r, _)| *r == 4) {
        if let Some(ap) = &p.app_protocol {
            let summary = super::model::l7_summary(ap);
            let name = summary.split(" · ").next().unwrap_or("app").to_string();
            let name = match (name.as_str(), tls_version) {
                ("tls", Some(v)) => format!("tls {v}"),
                _ => name,
            };
            ranked.push((
                4,
                Layer {
                    name,
                    summary: if decrypted {
                        "application data · decrypted (keylog)".into()
                    } else {
                        summary
                            .split_once(" · ")
                            .map(|(_, r)| r.to_string())
                            .unwrap_or_default()
                    },
                    rows: app_rows(ap),
                    span: off.payload.clone(),
                    kind: if decrypted {
                        Kind::Decrypted
                    } else {
                        Kind::Wire
                    },
                },
            ));
        }
    }
    ranked.sort_by_key(|(r, _)| *r);
    let mut out: Vec<Layer> = ranked.into_iter().map(|(_, l)| l).collect();
    if let Some(names) = names {
        if let Some(ip) = out.iter_mut().find(|l| l.name.starts_with("ipv")) {
            ip.rows.push(("names".into(), names));
        }
    }
    if let Some(plain) = &p.decrypted_plaintext {
        let alpn = match &p.app_protocol {
            Some(AppProtocol::Tls { alpn, .. }) => alpn.as_deref(),
            _ => None,
        };
        out.push(l7_layer(plain, alpn, off.payload.clone()));
    }
    out
}

/// Text mode: decrypted plaintext when present, else the readable payload.
pub fn text_view(p: &CapturedPacket) -> String {
    if let Some(plain) = &p.decrypted_plaintext {
        return String::from_utf8_lossy(plain)
            .chars()
            .map(|c| {
                if c.is_control() && c != '\n' && c != '\t' {
                    '.'
                } else {
                    c
                }
            })
            .collect();
    }
    p.payload_text.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screens::packets::model::tests::packet;

    /// Ethernet + IPv4 (IHL 5) + TCP (data offset 8 → 32 bytes) + 10 B payload
    /// + 4 B Ethernet padding past the IP total length.
    pub fn frame() -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[12] = 0x08;
        let ip_total = 20 + 32 + 10;
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(ip_total as u16).to_be_bytes());
        ip[9] = 6;
        f.extend(ip);
        let mut tcp = vec![0u8; 32];
        tcp[12] = 8 << 4;
        f.extend(tcp);
        f.extend(b"GET / HTTP");
        f.extend([0u8; 4]);
        f
    }

    #[test]
    fn offsets_follow_declared_header_lengths() {
        let off = offsets(&frame());
        assert_eq!(off.ethernet, Some(0..14));
        assert_eq!(off.network, Some(14..34));
        assert_eq!(off.transport, Some(34..66));
        assert_eq!(off.payload, Some(66..76));
        assert_eq!(offsets(&[1, 2, 3]), Offsets::default());
        // A frame claiming IPv4 with a bad version nibble yields no network span.
        let mut bad = frame();
        bad[14] = 0x65;
        assert_eq!(offsets(&bad).network, None);
    }

    #[test]
    fn layers_order_deepest_last_and_carry_spans() {
        let mut p = packet(1187, ("10.88.0.4", 51122), ("10.88.0.3", 9000), "TLS");
        p.raw_bytes = frame();
        p.details = vec![
            "Frame: 80 bytes on wire".into(),
            "Ethernet: 52:54:00:8a:1f:c2 → 52:54:00:12:34:56, Type: IPv4 (0x0800)".into(),
            "IPv4: 10.88.0.4 → 10.88.0.3, TTL: 64, Proto: TCP (6), Len: 62".into(),
            "TCP: 51122 (—) → 9000 (—), Seq: 4131594, Flags: [PSH, ACK], Win: 502, Ack: 88120"
                .into(),
            "TLS: ingest.internal alpn=h2".into(),
        ];
        p.app_protocol = Some(AppProtocol::Tls {
            sni: Some("ingest.internal".into()),
            alpn: Some("h2".into()),
            ech: false,
            ja4: Some("t13d1516h2_8daaf615_b186095e".into()),
        });
        // HEADERS frame, stream 7, END_HEADERS, 3 byte block.
        p.decrypted_plaintext = Some(vec![0, 0, 3, 1, 4, 0, 0, 0, 7, 0x82, 0x86, 0x84]);
        let l = layers(&p, Some("1.3"));
        let names: Vec<_> = l.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(
            names,
            ["frame", "ethernet ii", "ipv4", "tcp", "tls 1.3", "http/2"]
        );
        assert_eq!(
            l[2].summary,
            "10.88.0.4 → 10.88.0.3 · ttl 64 · proto TCP (6) · len 62"
        );
        assert_eq!(
            l[3].summary,
            "51122 → 9000 · seq 4131594 · flags psh ack · win 502 · ack 88120"
        );
        assert_eq!(l[3].span, Some(34..66));
        assert_eq!(l[4].kind, Kind::Decrypted);
        assert_eq!(l[5].kind, Kind::L7);
        assert_eq!(l[5].summary, "HEADERS · stream 7 · end_headers");
        assert!(l[4].rows.iter().any(|(k, _)| k == "ja4"));
    }

    #[test]
    fn unframed_packets_get_no_spans() {
        let mut p = packet(3, ("10.0.0.2", 1), ("10.0.0.3", 443), "TCP");
        p.raw_bytes = vec![1; 40];
        p.details = vec![
            "TCP: 10.0.0.2:1 -> 10.0.0.3:443".into(),
            "Frame: 66 bytes on the wire".into(),
        ];
        let l = layers(&p, None);
        assert_eq!(l[0].name, "frame");
        assert_eq!(l[1].name, "tcp");
        assert!(l.iter().all(|l| l.span.is_none()));
    }

    #[test]
    fn h2_needs_alpn_or_preface_and_http1_is_text() {
        let bytes = [0, 0, 0, 4, 1, 0, 0, 0, 0];
        assert!(h2_frames(&bytes, None).is_none());
        assert_eq!(h2_frames(&bytes, Some("h2")).unwrap()[0].flags, vec!["ack"]);
        let l = l7_layer(
            b"POST /ingest HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n",
            None,
            None,
        );
        assert_eq!(l.name, "http/1.1");
        assert_eq!(
            l.rows[1],
            ("content-type".into(), "application/json".into())
        );
    }
}
