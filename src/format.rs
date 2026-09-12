//! Small display formatters shared by the dashboard and connections screens.

pub fn rate(bytes_per_sec: f64) -> String {
    if bytes_per_sec >= 1_000_000.0 {
        format!("{:.1} MB/s", bytes_per_sec / 1_000_000.0)
    } else if bytes_per_sec >= 1_000.0 {
        format!("{:.0} KB/s", bytes_per_sec / 1_000.0)
    } else if bytes_per_sec > 0.0 {
        format!("{bytes_per_sec:.0} B/s")
    } else {
        "—".to_string()
    }
}

pub fn bytes_total(bytes: u64) -> String {
    let b = bytes as f64;
    if b >= 1_000_000_000.0 {
        format!("{:.1} GB", b / 1_000_000_000.0)
    } else if b >= 1_000_000.0 {
        format!("{:.0} MB", b / 1_000_000.0)
    } else if b >= 1_000.0 {
        format!("{:.0} KB", b / 1_000.0)
    } else {
        format!("{bytes} B")
    }
}

pub fn rtt_ms(v: Option<f64>) -> String {
    match v {
        Some(v) => format!("{v:.1}ms"),
        None => "—".to_string(),
    }
}

pub fn rtt_us(v: Option<f64>) -> String {
    match v {
        Some(v) => format!("{:.1}ms", v / 1000.0),
        None => "—".to_string(),
    }
}

pub fn loss_pct(v: f64) -> String {
    format!("{v:.0}%")
}

pub fn opt_rate(v: Option<f64>) -> String {
    match v {
        Some(v) => rate(v),
        None => "—".to_string(),
    }
}
