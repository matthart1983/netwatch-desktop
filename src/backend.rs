//! Desktop adapter over the same application runtime used by the TUI.
//!
//! The runtime thread owns `App`. Once per tick it copies what the screens
//! read into an immutable [`Snapshot`]; bulky, append-only stores (the packet
//! ring and stream tracker) travel as shared handles instead of copies, so a
//! 5 000-packet ring is not cloned every second. Screens never mutate `App`:
//! they queue [`Command`]s, and every command reports one [`ActionResult`]
//! that the footer toast shows.
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use netwatch::app::{App, IfaceChangeEvent};
use netwatch::collectors::{
    connections::{Connection, TrackedConnection},
    egress::{
        EgressDest, EgressPolicy, EgressProfile, EgressProfiler, ProcessRule, RecentViolation,
        Verdict as EgressVerdict,
    },
    health::HealthStatus,
    network_intel::{Alert, DnsAnalytics},
    packets::{CapturedPacket, DnsCache, StreamTracker},
    process_bandwidth::ProcessBandwidth,
    tcp_info::{normalize_endpoint, FlowMap, TcpInfo},
    traceroute::TracerouteResult,
    traffic::InterfaceTraffic,
};
use netwatch::config::NetwatchConfig;
use netwatch::diagnose::issue::{Issue, Severity};
use netwatch::platform::InterfaceInfo;
use netwatch::runtime::{
    bootstrap::{self, SessionKind},
    capabilities::CapabilitySnapshot,
};

/// Per (process, pid) receive-rate history, newest last.
pub type ProcessHistory = HashMap<(String, Option<u32>), VecDeque<u64>>;

/// Shared handles to the capture stores. Reads take the lock briefly; the
/// packet list is append-only between `clear()` calls.
#[derive(Clone)]
pub struct PacketStore {
    pub packets: Arc<RwLock<Vec<CapturedPacket>>>,
    pub streams: Arc<Mutex<StreamTracker>>,
}
impl Default for PacketStore {
    fn default() -> Self {
        Self {
            packets: Default::default(),
            streams: Arc::new(Mutex::new(StreamTracker::new())),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct CaptureState {
    pub live: bool,
    pub requested: bool,
    pub error: Option<String>,
    pub bpf: Option<String>,
    pub received: u64,
    pub dropped: u64,
    pub rate_pps: u64,
    /// Up, non-loopback interfaces capture can move to (`i`).
    pub capturable: Vec<String>,
}

/// (process, destination label, port) → the profiler's verdict.
pub type EgressVerdicts = HashMap<(String, String, u16), EgressVerdict>;

#[derive(Clone, Default)]
pub struct EgressSnapshot {
    pub profiles: Vec<EgressProfile>,
    pub verdicts: EgressVerdicts,
    pub policy_path: Option<PathBuf>,
    pub policy: Option<EgressPolicy>,
    /// Unix permission bits of the policy file when it exists.
    pub policy_mode: Option<u32>,
    pub has_policy: bool,
    /// What promotion may write for each observed process: `promote_one`'s
    /// rule without its blocked destinations (see `without_blocked`).
    pub promotable: HashMap<String, ProcessRule>,
    pub recent: Vec<RecentViolation>,
    pub cooldown_secs: u64,
}

#[derive(Clone)]
pub struct DiagnoseSnapshot {
    /// Every tracked issue, including closed and suppressed ones.
    pub issues: Vec<Issue>,
    pub targets: Vec<netwatch::diagnose::targets::TargetObs>,
    pub running_tests: HashMap<String, Vec<String>>,
    pub episode_dir: Option<PathBuf>,
    /// Ids of open, unsuppressed issues in engine order.
    #[allow(dead_code)]
    pub primary: Vec<String>,
    pub coverage: netwatch::diagnose::coverage::Coverage,
    pub readiness: String,
    pub baselines_ready: bool,
    pub fingerprint: String,
    pub switched_network: bool,
    pub capability: netwatch::diagnose::issue::Capability,
    pub demo_banner: Option<String>,
    pub blocked: Option<String>,
    pub verdict_line: String,
    pub ai_enabled: bool,
    pub ai_narrative: Option<String>,
    /// (subject, metric, mean, sigma, samples, readiness label).
    pub baselines: Vec<(String, String, f64, f64, u32, String)>,
}

impl Default for DiagnoseSnapshot {
    fn default() -> Self {
        Self {
            issues: vec![],
            targets: vec![],
            running_tests: HashMap::new(),
            episode_dir: None,
            primary: vec![],
            coverage: Default::default(),
            readiness: String::new(),
            baselines_ready: false,
            fingerprint: String::new(),
            switched_network: false,
            capability: netwatch::diagnose::issue::Capability::None,
            demo_banner: None,
            blocked: None,
            verdict_line: String::new(),
            ai_enabled: false,
            ai_narrative: None,
            baselines: vec![],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionResult {
    pub seq: u64,
    pub ok: bool,
    pub text: String,
}

pub struct Snapshot {
    pub telemetry: Arc<crate::telemetry::Telemetry>,
    pub interface_up: HashMap<String, bool>,
    pub observed_at: Instant,
    pub baselines: [String; 3],
    pub socket_verdicts: HashMap<(String, String), netwatch::diagnose::detectors::SocketVerdict>,
    pub events: Vec<netwatch::diagnose::report::TimelineEvent>,
    pub recorder: netwatch::collectors::incident::RecorderState,
    pub interfaces: Arc<Vec<InterfaceTraffic>>,
    pub connections: Arc<Vec<Connection>>,
    pub health: Arc<HealthStatus>,
    pub tcp: Arc<FlowMap>,
    pub interface: String,
    pub link_bps: Option<u64>,
    pub sample_interval: f64,
    pub capture: String,
    pub capabilities: String,
    pub verdict: String,
    pub severity: Option<Severity>,
    pub coverage: String,
    pub issues: Vec<Issue>,

    // Workbench screens.
    pub demo: bool,
    pub session_started: Instant,
    pub hostname: String,
    pub gateway: Option<String>,
    pub dns_servers: Vec<String>,
    pub default_route: Option<String>,
    pub interface_info: Arc<Vec<InterfaceInfo>>,
    pub link_speeds: HashMap<String, u64>,
    pub iface_events: Arc<Vec<IfaceChangeEvent>>,
    pub capture_state: CaptureState,
    pub packets: PacketStore,
    pub dns_names: Option<DnsCache>,
    pub whois: Option<netwatch::collectors::whois::WhoisCache>,
    /// GeoIP lookups (offline database, or ip-api.com when `geoip_online`).
    /// `lookup` is cached; private addresses return `None`.
    pub geo: Option<netwatch::collectors::geo::GeoCache>,
    pub processes: Arc<Vec<ProcessBandwidth>>,
    pub process_rx_history: Arc<ProcessHistory>,
    pub rtt_history: Arc<HashMap<String, VecDeque<f64>>>,
    pub attribution: netwatch::collectors::attribution::Coverage,
    pub traceroute: Arc<TracerouteResult>,
    pub alerts: Arc<Vec<Alert>>,
    pub alert_history: Arc<Vec<Alert>>,
    pub tracked: Arc<Vec<TrackedConnection>>,
    /// No screen reads it since stats stopped mixing DNS buckets into the rtt plot.
    #[allow(dead_code)]
    pub dns_analytics: Arc<DnsAnalytics>,
    pub egress: Arc<EgressSnapshot>,
    pub config: Arc<NetwatchConfig>,
    pub config_path: Option<PathBuf>,
    pub capability: Arc<CapabilitySnapshot>,
    pub recorder_window: String,
    pub recorder_reason: Option<String>,
    pub diagnose: Arc<DiagnoseSnapshot>,
    /// `None` without a cache directory; exports then refuse.
    pub export_dir: Option<PathBuf>,
    /// The latest command outcome; `seq` changes once per command.
    pub action: Option<ActionResult>,
}

/// Where exports land: netwatch's `cache/netwatch/exports`, the directory
/// its sandbox grants. `None` without a cache directory (no HOME): exports
/// refuse rather than land somewhere shared such as /tmp.
pub fn export_dir() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("netwatch").join("exports"))
}

impl Snapshot {
    /// A snapshot with no measurements, for tests, fixtures and startup.
    pub fn empty() -> Self {
        Self {
            telemetry: Default::default(),
            interface_up: Default::default(),
            observed_at: Instant::now(),
            baselines: Default::default(),
            socket_verdicts: Default::default(),
            events: vec![],
            recorder: netwatch::collectors::incident::RecorderState::Off,
            interfaces: Arc::new(vec![]),
            connections: Arc::new(vec![]),
            health: netwatch::collectors::health::HealthProber::new().status(),
            tcp: Arc::new(FlowMap::new()),
            interface: "eth0".into(),
            link_bps: None,
            sample_interval: 1.0,
            capture: "unavailable".into(),
            capabilities: String::new(),
            verdict: String::new(),
            severity: None,
            coverage: String::new(),
            issues: vec![],
            demo: false,
            session_started: Instant::now(),
            hostname: String::new(),
            gateway: None,
            dns_servers: vec![],
            default_route: None,
            interface_info: Arc::new(vec![]),
            link_speeds: Default::default(),
            iface_events: Arc::new(vec![]),
            capture_state: CaptureState::default(),
            packets: PacketStore::default(),
            dns_names: None,
            whois: None,
            geo: None,
            processes: Arc::new(vec![]),
            process_rx_history: Default::default(),
            rtt_history: Default::default(),
            attribution: Default::default(),
            traceroute: Arc::new(TracerouteResult {
                reached: None,
                completed: None,
                completed_at: String::new(),
                target: String::new(),
                status: netwatch::collectors::traceroute::TracerouteStatus::Idle,
                hops: vec![],
            }),
            alerts: Arc::new(vec![]),
            alert_history: Arc::new(vec![]),
            tracked: Arc::new(vec![]),
            dns_analytics: Default::default(),
            egress: Default::default(),
            config: Arc::new(NetwatchConfig::default()),
            config_path: None,
            capability: Arc::new(CapabilitySnapshot {
                schema_version: 1,
                scope: "desktop".into(),
                platform: std::env::consts::OS.into(),
                interface: None,
                capabilities: vec![],
                protections: vec![],
                network_restricted: false,
                attribution_coverage: None,
            }),
            recorder_window: "5m".into(),
            recorder_reason: None,
            diagnose: Default::default(),
            export_dir: export_dir(),
            action: None,
        }
    }

    /// The latest result of the gateway, dns or internet probe.
    pub fn probe(&self, target: &str) -> crate::probe::Probe {
        crate::probe::Probe::of(&self.health, target, self.observed_at)
    }

    pub fn health_color(&self, target: &str) -> egui::Color32 {
        let prefix = match target {
            "gateway" => "gateway.",
            "dns" => "dns.",
            _ => "path.",
        };
        let state = self.probe(target).state;
        if !state.is_fresh() {
            return crate::theme::muted();
        }
        if let Some(severity) = self
            .issues
            .iter()
            .filter(|i| i.rule.starts_with(prefix))
            .map(|i| i.severity)
            .max()
        {
            return crate::theme::issue_color(Some(severity));
        }
        state.color()
    }

    fn from_app(app: &App) -> Self {
        let verdict = app.diagnose.engine.verdict(&app.diagnose.baselines);
        let health = app.health_prober.status();
        let targets = [
            health.completed.gateway_target.clone(),
            health.completed.dns_target.clone(),
            Some("internet".to_string()),
        ];
        let metrics = ["gateway.rtt", "dns.rtt_p50", "path.rtt"];
        let interface_info = Arc::new(app.interface_info.clone());
        let link_speeds = interface_info
            .iter()
            .filter_map(|i| {
                netwatch::platform::link_speed_bps(&i.name).map(|s| (i.name.clone(), s))
            })
            .collect();
        let capture_state = CaptureState {
            live: app.packet_collector.is_capturing(),
            requested: app.packet_collector.capture_requested(),
            error: app.packet_collector.get_error(),
            bpf: app.bpf_filter_active.clone(),
            received: app.packet_collector.stats.received(),
            dropped: app.packet_collector.stats.dropped(),
            rate_pps: app.packet_collector.stats.rate_pps(),
            capturable: capturable_interfaces(app),
        };
        let store = &app.diagnose.baselines;
        let diagnose = DiagnoseSnapshot {
            issues: app.diagnose.engine.issues().to_vec(),
            targets: app
                .diagnose
                .target_prober
                .fresh(&app.user_config.diagnose_targets)
                .0
                .into_iter()
                .map(|(_, obs)| obs)
                .collect(),
            running_tests: app
                .diagnose
                .engine
                .issues()
                .iter()
                .map(|i| (i.id.clone(), app.diagnose.tests.running_for(&i.id)))
                .collect(),
            episode_dir: app.diagnose.episode_dir.clone(),
            primary: app
                .diagnose
                .engine
                .primary()
                .into_iter()
                .map(|i| i.id.clone())
                .collect(),
            coverage: app.diagnose.engine.coverage().clone(),
            readiness: store.overall_readiness().label(),
            baselines_ready: store.overall_readiness().is_ready(),
            fingerprint: store.fingerprint().label(),
            switched_network: store.switched_network(),
            capability: app.diagnose.capability,
            demo_banner: app.diagnose.demo.as_ref().map(|d| d.banner()),
            blocked: app.diagnose.journal.blocked_reason().map(str::to_string),
            verdict_line: verdict.line(),
            ai_enabled: app.user_config.insights_enabled,
            ai_narrative: app
                .insights_collector
                .as_ref()
                .and_then(|c| c.latest_narrative()),
            baselines: targets
                .iter()
                .zip(metrics)
                .filter_map(|(subject, metric)| {
                    let subject = subject.as_deref()?;
                    store.get(subject, metric).map(|b| {
                        (
                            subject.to_string(),
                            metric.to_string(),
                            b.mean,
                            b.sigma(),
                            b.samples,
                            store.readiness(subject, metric).label(),
                        )
                    })
                })
                .collect(),
        };
        let egress = {
            let profiler = &app.egress_profiler;
            let profiles = profiler.snapshot();
            let (verdicts, promotable) = judge_egress(profiler, &profiles);
            let policy_path = netwatch::collectors::egress::default_policy_path();
            let policy_mode = policy_path.as_deref().and_then(file_mode);
            EgressSnapshot {
                policy: policy_path
                    .as_deref()
                    .filter(|p| p.exists())
                    .and_then(netwatch::collectors::egress::load_policy_file),
                policy_path,
                policy_mode,
                has_policy: profiler.has_policy(),
                promotable,
                recent: profiler.recent_violations().cloned().collect(),
                cooldown_secs: app.user_config.egress_violation_cooldown_secs,
                profiles,
                verdicts,
            }
        };
        Self {
            telemetry: Default::default(),
            interface_up: app
                .interface_info
                .iter()
                .map(|i| (i.name.clone(), i.is_up))
                .collect(),
            observed_at: Instant::now(),
            baselines: std::array::from_fn(|i| {
                targets[i]
                    .as_deref()
                    .map(|target| {
                        let readiness = store.readiness(target, metrics[i]);
                        store
                            .get(target, metrics[i])
                            .map(|b| {
                                format!(
                                    "base {:.1}ms · σ {:.1} · {}",
                                    b.mean,
                                    b.sigma(),
                                    readiness.label()
                                )
                            })
                            .unwrap_or_else(|| readiness.label())
                    })
                    .unwrap_or_else(|| "no baseline".into())
            }),
            socket_verdicts: app
                .connection_collector
                .connections()
                .iter()
                .filter_map(|c| {
                    app.diagnose
                        .sampler
                        .verdict_for(&c.local_addr, &c.remote_addr)
                        .map(|v| ((c.local_addr.clone(), c.remote_addr.clone()), v))
                })
                .collect(),
            events: netwatch::diagnose::controller::build_diagnose_report(app).timeline,
            recorder: app.incident_recorder.state(),
            interfaces: app.traffic.interfaces(),
            connections: app.connection_collector.connections(),
            health,
            tcp: app.tcp_info.snapshot(),
            interface: app.capture_interface.clone(),
            link_bps: app.link_speed_bps(),
            sample_interval: app.user_config.refresh_rate_ms.clamp(100, 5000) as f64 / 1000.0,
            capture: if app.packet_collector.is_capturing() {
                "capture live".into()
            } else {
                format!(
                    "counters only · {}",
                    app.packet_collector
                        .get_error()
                        .unwrap_or_else(|| "capture starting or unavailable".into())
                )
            },
            capabilities: CapabilitySnapshot::live(app).text(),
            verdict: verdict.line(),
            severity: verdict.severity(),
            coverage: app.diagnose.engine.coverage().label(),
            issues: app.diagnose.engine.primary().into_iter().cloned().collect(),
            demo: app.diagnose.is_demo(),
            session_started: app.session_started_at,
            hostname: app.config_collector.config.hostname.clone(),
            gateway: app.config_collector.config.gateway.clone(),
            dns_servers: app.config_collector.config.dns_servers.clone(),
            default_route: netwatch::platform::default_route_interface(),
            interface_info,
            link_speeds,
            iface_events: Arc::new(app.caches.iface_events.iter().cloned().collect()),
            capture_state,
            packets: PacketStore {
                packets: Arc::clone(&app.packet_collector.packets),
                streams: Arc::clone(&app.packet_collector.stream_tracker),
            },
            dns_names: Some(app.packet_collector.dns_cache.clone()),
            whois: Some(app.whois_cache.clone()),
            geo: app.ui.show_geo.then(|| app.geo_cache.clone()),
            processes: Arc::new(app.process_bandwidth.ranked().to_vec()),
            process_rx_history: Arc::new(app.caches.top_proc_rx_history.clone()),
            rtt_history: Arc::new(app.caches.rtt_history.clone()),
            attribution: app.connection_collector.coverage(),
            traceroute: Arc::new(
                app.traceroute_runner
                    .result
                    .lock()
                    .map(|r| r.clone())
                    .unwrap_or_else(|e| e.into_inner().clone()),
            ),
            alerts: Arc::new(app.network_intel.active_alerts().to_vec()),
            alert_history: Arc::new(app.network_intel.alert_history().iter().cloned().collect()),
            tracked: Arc::new(app.connection_timeline.tracked.clone()),
            dns_analytics: Arc::new(app.network_intel.dns_analytics()),
            egress: Arc::new(egress),
            config: Arc::new(app.user_config.clone()),
            config_path: NetwatchConfig::path(),
            capability: Arc::new(CapabilitySnapshot::live(app)),
            recorder_window: app.incident_recorder.window_label(),
            recorder_reason: app.incident_recorder.freeze_reason().map(str::to_string),
            diagnose: Arc::new(diagnose),
            export_dir: export_dir(),
            action: None,
        }
    }

    pub fn tcp_for(&self, conn: &Connection) -> Option<&TcpInfo> {
        self.tcp.get(&(
            normalize_endpoint(&conn.local_addr),
            normalize_endpoint(&conn.remote_addr),
        ))
    }

    /// The display name of `ip` when reverse DNS has resolved it.
    pub fn host_name(&self, ip: &str) -> Option<String> {
        self.dns_names.as_ref().and_then(|c| c.lookup(ip))
    }
}

/// Each observed destination's verdict, and what promotion may write for
/// each process.
fn judge_egress(
    profiler: &EgressProfiler,
    profiles: &[EgressProfile],
) -> (EgressVerdicts, HashMap<String, ProcessRule>) {
    let mut verdicts = HashMap::new();
    let mut promotable = HashMap::new();
    for profile in profiles {
        let mut dests = Vec::new();
        for ((label, port), dest) in &profile.dests {
            let verdict = profiler.verdict(&profile.process, dest);
            dests.push((dest, matches!(verdict, EgressVerdict::Blocked(_))));
            verdicts.insert((profile.process.clone(), label.clone(), *port), verdict);
        }
        if let Some(rule) = profiler
            .promote_one(&profile.process)
            .and_then(|rule| without_blocked(rule, &dests))
        {
            promotable.insert(profile.process.clone(), rule);
        }
    }
    (verdicts, promotable)
}

/// What promotion may write for one process: `promote_one`'s rule less
/// every entry that only blocked destinations contributed. Allowing a
/// blocked destination changes nothing while the block stands, would admit
/// it quietly once the block is lifted, and its port would widen the rule
/// for every other destination. `None` when nothing unblocked is left to
/// name, because a rule with no names or ports is unrestricted.
fn without_blocked(mut rule: ProcessRule, dests: &[(&EgressDest, bool)]) -> Option<ProcessRule> {
    if !dests.iter().any(|(_, blocked)| *blocked) {
        return Some(rule);
    }
    // Per side (0 unblocked, 1 blocked): the entries each destination gives
    // a promoted rule, as netwatch derives them: its sni, else its address,
    // else its AS; and its port.
    let mut sni: [HashSet<&str>; 2] = Default::default();
    let mut ip: [HashSet<&str>; 2] = Default::default();
    let mut asn: [HashSet<&str>; 2] = Default::default();
    let mut ports: [HashSet<u16>; 2] = Default::default();
    for (dest, blocked) in dests {
        let side = usize::from(*blocked);
        match (&dest.sni, dest.last_ip.as_str(), &dest.asn_org) {
            (Some(name), _, _) => sni[side].insert(name.as_str()),
            (None, "", Some(org)) => asn[side].insert(org.as_str()),
            (None, "", None) => false,
            (None, addr, _) => ip[side].insert(addr),
        };
        ports[side].insert(dest.port);
    }
    fn keep<T: Eq + std::hash::Hash>(sides: &[HashSet<T>; 2], value: T) -> bool {
        !sides[1].contains(&value) || sides[0].contains(&value)
    }
    let named = |r: &ProcessRule| {
        !(r.allow_sni.is_empty() && r.allow_ip.is_empty() && r.allow_asn.is_empty())
    };
    let had_names = named(&rule);
    rule.allow_sni.retain(|v| keep(&sni, v.as_str()));
    rule.allow_ip.retain(|v| keep(&ip, v.as_str()));
    rule.allow_asn.retain(|v| keep(&asn, v.as_str()));
    rule.allow_ports.retain(|p| keep(&ports, *p));
    (!rule.allow_ports.is_empty() && (named(&rule) || !had_names)).then_some(rule)
}

#[cfg(unix)]
fn file_mode(path: &std::path::Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}
#[cfg(not(unix))]
fn file_mode(_: &std::path::Path) -> Option<u32> {
    None
}

fn capturable_interfaces(app: &App) -> Vec<String> {
    app.interface_info
        .iter()
        .filter(|i| i.is_up && i.name != "lo" && i.name != "lo0")
        .map(|i| i.name.clone())
        .collect()
}

/// Everything a screen can ask the runtime to do. Each command produces one
/// [`ActionResult`]; writes name their path.
#[derive(Clone, Debug)]
pub enum Command {
    ToggleRecorder,
    ArmRecorder,
    DisarmRecorder,
    FreezeRecorder,
    ExportReport,
    ExportIncident,
    StartCapture,
    StopCapture,
    SetBpf(Option<String>),
    SetCaptureInterface(String),
    ClearCapture,
    /// Export these packet ids (the screen's filtered list) as pcap.
    ExportPcap {
        ids: Vec<u64>,
        label: String,
    },
    Whois(String),
    Traceroute(String),
    ExportConnections,
    /// Write a screen-built CSV table (interfaces, stats) to the export dir
    /// as `netwatch_{label}_{timestamp}.csv`.
    ExportCsv {
        label: String,
        csv: String,
    },
    ExportEgress,
    EgressWrite(Box<crate::egress_policy::Edit>),
    DiagnoseAck(String),
    DiagnoseMute(String),
    DiagnoseApply(String),
    DiagnoseTest {
        issue: String,
        test: String,
    },
    DiagnoseStepDone {
        issue: String,
        step: usize,
    },
    DiagnoseLabel {
        issue: String,
        cause: String,
    },
    /// Apply and persist the edited configuration.
    SaveConfig(Box<NetwatchConfig>),
}

pub struct Backend {
    snapshot: Arc<RwLock<Option<Arc<Snapshot>>>>,
    error: Arc<RwLock<Option<String>>>,
    stop: mpsc::Sender<()>,
    commands: mpsc::Sender<Command>,
    thread: Option<std::thread::JoinHandle<()>>,
    preview: Option<Instant>,
}

impl Backend {
    /// `demo` runs the real runtime with the Diagnose demo scenario and a
    /// seeded packet capture — the same `--demo` the TUI offers.
    /// `sandbox` overrides config.toml's `sandbox` for this session
    /// (`--no-sandbox`, `--sandbox-strict`, or a retry after a failed start).
    pub fn spawn_session(demo: bool, sandbox: Option<netwatch::sandbox::Mode>) -> Arc<Self> {
        let snapshot = Arc::new(RwLock::new(None));
        let error = Arc::new(RwLock::new(None));
        let (stop, stopped) = mpsc::channel();
        let (commands, pending) = mpsc::channel();
        let published = Arc::clone(&snapshot);
        let failed = Arc::clone(&error);
        let thread = std::thread::spawn(move || {
            let config = NetwatchConfig::load();
            let mode =
                sandbox.unwrap_or_else(|| netwatch::sandbox::Mode::from_config(&config.sandbox));
            let interval = Duration::from_millis(config.refresh_rate_ms.clamp(100, 5000));
            let mut app = App::prepare_with_config(config);
            // Sandbox applies to this runtime thread and its workers, leaving
            // the GUI thread free to open the display and graphics resources.
            let _workers = netwatch::sandbox::worker::SessionGuard;
            let kind = if demo {
                SessionKind::Demo
            } else {
                SessionKind::Daemon
            };
            if let Err(e) = bootstrap::start(&mut app, kind, mode) {
                *failed.write().unwrap() = Some(format!("Runtime startup failed: {e}"));
                app.packet_collector.stop_capture();
                return;
            }
            if demo {
                app.packet_collector.seed_demo_capture();
            }
            bootstrap::prime_collectors(&mut app);
            // Same one-shot trace the TUI starts, so topology has a path.
            app.traceroute_runner.run("1.1.1.1");
            let mut tracker = crate::telemetry::Tracker::default();
            let mut action: Option<ActionResult> = None;
            let mut seq = 0;
            loop {
                for command in pending.try_iter() {
                    seq += 1;
                    let outcome = run_command(&mut app, command);
                    action = Some(ActionResult {
                        seq,
                        ok: outcome.is_ok(),
                        text: outcome.unwrap_or_else(|e| e),
                    });
                }
                app.tcp_info.update();
                app.tick();
                let mut snapshot = Snapshot::from_app(&app);
                snapshot.telemetry = tracker.update(&snapshot);
                snapshot.action = action.clone();
                *published.write().unwrap() = Some(Arc::new(snapshot));
                match stopped.recv_timeout(interval) {
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    _ => break,
                }
            }
            app.packet_collector.stop_capture();
            app.egress_profiler.persist_now();
            app.shutdown_diagnose();
        });
        Arc::new(Self {
            snapshot,
            error,
            stop,
            commands,
            thread: Some(thread),
            preview: None,
        })
    }

    pub fn preview() -> Arc<Self> {
        let (stop, _) = mpsc::channel();
        let (commands, _) = mpsc::channel();
        Arc::new(Self {
            snapshot: Arc::new(RwLock::new(None)),
            error: Arc::new(RwLock::new(None)),
            stop,
            commands,
            thread: None,
            preview: Some(Instant::now()),
        })
    }
    pub fn command(&self, command: Command) -> Result<(), &'static str> {
        self.commands
            .send(command)
            .map_err(|_| "Actions unavailable in graph preview or stopped runtime")
    }
    pub fn snapshot(&self) -> Option<Arc<Snapshot>> {
        if let Some(epoch) = self.preview {
            let tick = epoch.elapsed().as_secs();
            let at = epoch + Duration::from_secs(tick);
            let mut current = self.snapshot.write().unwrap();
            if current
                .as_ref()
                .is_none_or(|s| s.interfaces[0].sample_times.back() != Some(&at))
            {
                *current = Some(Arc::new(crate::preview::snapshot(epoch, tick)));
            }
            return current.clone();
        }
        self.snapshot.read().unwrap().clone()
    }
    pub fn error(&self) -> Option<String> {
        self.error.read().unwrap().clone()
    }
}

impl Drop for Backend {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn timestamp() -> String {
    chrono::Local::now().format("%Y%m%d_%H%M%S").to_string()
}

/// The export directory, created 0700, or narrowed to 0700 when an older
/// desktop left it 0755. Everything written into it is 0600 too: exports
/// hold addresses, hostnames, process names and packet bytes.
fn ensure_export_dir() -> Result<PathBuf, String> {
    prepare_export_dir(export_dir())
}

fn prepare_export_dir(dir: Option<PathBuf>) -> Result<PathBuf, String> {
    let dir = dir.ok_or_else(|| {
        "✕ export failed · no cache directory to export into · set HOME".to_string()
    })?;
    netwatch::owner_only::create_dir_all(&dir)
        .map_err(|e| format!("✕ export failed · {} · {e}", dir.display()))?;
    Ok(dir)
}

/// Create `path` empty and 0600 for a netwatch writer that opens it with
/// `File::create`: that truncates the file and keeps its mode, where a file
/// the writer created itself would take the umask, usually 0644.
fn owner_only_file(path: &Path) -> std::io::Result<()> {
    netwatch::owner_only::create(path).map(drop)
}

fn export_pcap(
    dir: &Path,
    label: &str,
    stamp: &str,
    packets: &[CapturedPacket],
) -> Result<String, String> {
    let path = dir.join(format!("netwatch_{label}_{stamp}.pcap"));
    netwatch::collectors::packets::export_pcap(packets, &path.to_string_lossy())
        .map(|n| format!("✓ exported {} · {n} packets", path.display()))
        .map_err(|e| format!("✕ pcap export failed · {e}"))
}

fn export_connections(dir: &Path, stamp: &str, conns: &[Connection]) -> Result<String, String> {
    let json = dir.join(format!("connections_{stamp}.json"));
    let csv = dir.join(format!("connections_{stamp}.csv"));
    owner_only_file(&json)
        .and_then(|_| owner_only_file(&csv))
        .map_err(|e| format!("✕ export failed · {e}"))?;
    netwatch::collectors::connections::export_json(conns, &json.to_string_lossy())
        .and_then(|_| netwatch::collectors::connections::export_csv(conns, &csv.to_string_lossy()))
        .map(|n| format!("✓ exported {} · csv · {n} sockets", json.display()))
        .map_err(|e| format!("✕ export failed · {e}"))
}

fn export_csv(dir: &Path, label: &str, stamp: &str, csv: &str) -> Result<String, String> {
    let path = dir.join(format!("netwatch_{label}_{stamp}.csv"));
    let rows = csv.lines().count().saturating_sub(1);
    netwatch::owner_only::create(&path)
        .and_then(|mut file| file.write_all(csv.as_bytes()))
        .map(|_| format!("✓ exported {} · {rows} rows", path.display()))
        .map_err(|e| format!("✕ export failed · {e}"))
}

fn export_egress(dir: &Path, stamp: &str, profiler: &EgressProfiler) -> Result<String, String> {
    let path = dir.join(format!("netwatch_egress_{stamp}.ndjson"));
    owner_only_file(&path)
        .and_then(|_| profiler.export_ndjson(&path))
        .map(|n| format!("✓ exported {} · {n} records", path.display()))
        .map_err(|e| format!("✕ egress export failed · {e}"))
}

/// report.md and report.json in a directory of their own, as netwatch's
/// `export_diagnose_report` writes them, but owner-only.
fn export_report(dir: &Path, stamp: &str, markdown: &str, json: &str) -> std::io::Result<PathBuf> {
    let dir = dir.join(format!("netwatch_diagnose_{stamp}"));
    netwatch::owner_only::create_dir_all(&dir)?;
    netwatch::owner_only::create(&dir.join("report.md"))?.write_all(markdown.as_bytes())?;
    netwatch::owner_only::create(&dir.join("report.json"))?.write_all(json.as_bytes())?;
    Ok(dir)
}

/// Status strings written by `App` during a call, read back as the result.
fn app_status(app: &App) -> Option<String> {
    app.ui
        .export_status
        .clone()
        .or_else(|| app.diagnose.status.clone())
}

fn reload_policy(app: &mut App, path: &std::path::Path) -> bool {
    app.egress_profiler.reload_policy(path);
    app.egress_profiler.has_policy()
}

fn run_command(app: &mut App, command: Command) -> Result<String, String> {
    match command {
        Command::ToggleRecorder => {
            if app.incident_recorder.is_armed() {
                app.disarm_incident_recorder();
            } else {
                app.arm_incident_recorder();
            }
            app_status(app).ok_or_else(|| "recorder unchanged".into())
        }
        Command::ArmRecorder => {
            app.arm_incident_recorder();
            Ok(app_status(app).unwrap_or_else(|| "flight recorder armed".into()))
        }
        Command::DisarmRecorder => {
            app.disarm_incident_recorder();
            Ok(app_status(app).unwrap_or_else(|| "flight recorder disarmed".into()))
        }
        Command::FreezeRecorder => app
            .incident_recorder
            .freeze("manual freeze")
            .map(|_| "flight recorder frozen · manual freeze".to_string())
            .map_err(|e| format!("✕ freeze failed · {e}")),
        Command::ExportReport if app.diagnose.is_demo() => {
            // netwatch shows the preview and writes nothing for a demo.
            netwatch::diagnose::controller::export_diagnose_report(app);
            let status = app.diagnose.status.clone().unwrap_or_default();
            app.ui.export_status = Some(status.clone());
            Ok(status)
        }
        Command::ExportReport => {
            let dir = ensure_export_dir()?;
            let report = netwatch::diagnose::controller::build_diagnose_report(app);
            let json = report
                .to_json()
                .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"));
            let outcome = export_report(&dir, &timestamp(), &report.to_markdown(), &json)
                .map(|path| format!("report.md + report.json → {}", path.display()))
                .map_err(|e| format!("export failed: {e}"));
            let status = outcome.clone().unwrap_or_else(|e| e);
            app.diagnose.set_status(status.clone());
            app.ui.export_status = Some(status);
            outcome
        }
        Command::ExportIncident => {
            // netwatch writes the bundle owner-only into the same directory;
            // this refuses without one and narrows an old 0755 one first.
            ensure_export_dir()?;
            app.export_incident_bundle();
            let status = app.ui.export_status.clone().unwrap_or_default();
            match status.strip_prefix("Incident bundle saved to ") {
                // Same line the recorder sheet shows: path · files · size.
                Some(path) => Ok(crate::sheets::recorder::bundle_summary(
                    std::path::Path::new(path.trim()),
                )),
                None => Err(status),
            }
        }
        Command::StartCapture => {
            let iface = app.capture_interface.clone();
            let bpf = app.bpf_filter_active.clone();
            app.packet_collector.start_capture(&iface, bpf.as_deref());
            Ok(format!("capture started on {iface}"))
        }
        Command::StopCapture => {
            app.packet_collector.stop_capture();
            Ok("capture stopped".into())
        }
        Command::SetBpf(filter) => {
            let filter = filter.filter(|f| !f.trim().is_empty());
            app.bpf_filter_active = filter.clone();
            let label = filter.as_deref().unwrap_or("cleared");
            // The crate compiles the filter on the capture thread, so the
            // result arrives later as the capture error; don't claim success.
            // A stopped capture stays stopped and uses it on the next start;
            // one that just failed to compile the old filter was requested,
            // so it retries with the new one.
            let bpf_failed = app
                .packet_collector
                .get_error()
                .is_some_and(|e| e.contains("BPF"));
            if app.packet_collector.capture_requested() || bpf_failed {
                let iface = app.capture_interface.clone();
                app.packet_collector.stop_capture();
                app.packet_collector
                    .start_capture(&iface, filter.as_deref());
                Ok(format!("bpf {label} · compiling, capture restarting"))
            } else {
                Ok(format!("bpf {label} · applies when capture starts"))
            }
        }
        Command::SetCaptureInterface(name) => {
            let running = app.packet_collector.capture_requested();
            app.packet_collector.stop_capture();
            app.capture_interface = name.clone();
            if running {
                let bpf = app.bpf_filter_active.clone();
                app.packet_collector.start_capture(&name, bpf.as_deref());
            }
            Ok(format!("capturing {name}"))
        }
        Command::ClearCapture => {
            app.packet_collector.clear();
            Ok("capture cleared".into())
        }
        Command::ExportPcap { ids, label } => {
            let dir = ensure_export_dir()?;
            let wanted: HashSet<u64> = ids.into_iter().collect();
            let packets: Vec<CapturedPacket> = app
                .packet_collector
                .get_packets()
                .iter()
                .filter(|p| wanted.contains(&p.id))
                .cloned()
                .collect();
            export_pcap(&dir, &label, &timestamp(), &packets)
        }
        Command::Whois(ip) => {
            app.whois_cache.request(&ip);
            Ok(format!("whois {ip} requested"))
        }
        Command::Traceroute(target) => {
            app.traceroute_runner.run(&target);
            Ok(format!("traceroute {target} started"))
        }
        Command::ExportConnections => {
            let dir = ensure_export_dir()?;
            export_connections(&dir, &timestamp(), &app.connection_collector.connections())
        }
        Command::ExportCsv { label, csv } => {
            export_csv(&ensure_export_dir()?, &label, &timestamp(), &csv)
        }
        Command::ExportEgress => {
            export_egress(&ensure_export_dir()?, &timestamp(), &app.egress_profiler)
        }
        Command::EgressWrite(edit) => {
            edit.write(app.diagnose.is_demo())?;
            if reload_policy(app, edit.path()) {
                Ok(format!("{} · saved {}", edit.title, edit.path().display()))
            } else {
                Err(format!(
                    "policy saved but reload failed · {}",
                    edit.path().display()
                ))
            }
        }
        Command::DiagnoseAck(id) => {
            if app.diagnose.engine.ack(&id) {
                Ok(format!("{id} acknowledged — still open, just quiet"))
            } else {
                Err(format!("✕ {id} is no longer open"))
            }
        }
        Command::DiagnoseMute(id) => {
            if app.diagnose.engine.mute(&id, 60) {
                Ok(format!("{id} muted for 1h"))
            } else {
                Err(format!("✕ {id} is no longer open"))
            }
        }
        Command::DiagnoseApply(id) => diagnose_apply(app, &id),
        Command::DiagnoseTest { issue, test } => app.start_diagnose_test(&issue, &test),
        Command::DiagnoseStepDone { issue, step } => app.mark_diagnose_step_done(&issue, step),
        Command::DiagnoseLabel { issue, cause } => app.label_issue(&issue, &cause),
        Command::SaveConfig(config) => {
            let mut config = *config;
            config.validate();
            let ai_changed = ai_settings_changed(&app.user_config, &config);
            let old = std::mem::replace(&mut app.user_config, config);
            // Like the TUI: a changed AI row replaces the running collector,
            // so turning insights off stops summaries leaving the machine and
            // a new endpoint or model takes effect without a restart.
            if ai_changed {
                app.insights_collector = insights_collector_for(&app.user_config);
            }
            app.ui.show_geo = app.user_config.show_geo;
            app.ui.packet_follow = app.user_config.packet_follow;
            app.ui.timeline_window = app.user_config.timeline_window_enum();
            app.theme = netwatch::theme::by_name(&app.user_config.theme);
            // Only what changed is written, so the TUI's sections, keys a
            // newer netwatch added and comments survive (`config_file`).
            let path = NetwatchConfig::path()
                .ok_or_else(|| "✕ save failed · cannot determine config directory".to_string())?;
            crate::config_file::save(&path, &old, &app.user_config)
                .map(|()| format!("✓ saved {}", path.display()))
                .map_err(|e| format!("✕ save failed · {e}"))
        }
    }
}

fn ai_settings_changed(old: &NetwatchConfig, new: &NetwatchConfig) -> bool {
    old.insights_enabled != new.insights_enabled
        || old.insights_model != new.insights_model
        || old.insights_endpoint != new.insights_endpoint
}

/// A started collector for `config`, or `None` when insights are off.
/// Dropping the previous collector closes its channel, which ends its worker.
fn insights_collector_for(
    config: &NetwatchConfig,
) -> Option<netwatch::collectors::insights::InsightsCollector> {
    if !config.insights_enabled {
        return None;
    }
    let mut collector = netwatch::collectors::insights::InsightsCollector::new(
        &config.insights_model,
        &config.insights_endpoint,
    );
    collector.start();
    Some(collector)
}

/// Mirrors the TUI: demo sessions simulate the key-bound fix; live sessions
/// never apply anything themselves and record why.
fn diagnose_apply(app: &mut App, id: &str) -> Result<String, String> {
    use netwatch::diagnose::issue::{Action, Applied, StepKind};
    let capability = app.diagnose.capability;
    let Some(issue) = app.diagnose.engine.get(id) else {
        return Err(format!("✕ {id} is no longer tracked"));
    };
    let Some(step) = issue
        .remediation
        .iter()
        .find(|s| s.kind == StepKind::Apply && s.available(capability))
    else {
        return Err("nothing netwatch can apply for this issue — see the steps listed".into());
    };
    let (key, action, text) = (
        step.key.unwrap_or('1'),
        step.action.clone(),
        step.text.clone(),
    );
    if let Some(demo) = app.diagnose.demo.as_mut() {
        let applied = match &action {
            Some(action) => demo.apply(action),
            None => Applied::No {
                reason: "step has no action".into(),
            },
        };
        let ok = matches!(applied, Applied::Yes { .. });
        app.diagnose.engine.record_applied(id, key, applied);
        return if ok {
            Ok(format!("applied · {text} · verifying…"))
        } else {
            Err(format!("✕ not applied · {text}"))
        };
    }
    let reason = app
        .diagnose
        .journal
        .blocked_reason()
        .map(str::to_string)
        .unwrap_or_else(|| match action {
            Some(Action::SetResolver { .. }) => "automatic edits are unavailable here; follow the manual steps or inspect with netwatch resolver status".into(),
            _ => "netwatch cannot perform this step itself".into(),
        });
    app.diagnose.engine.record_applied(
        id,
        key,
        Applied::No {
            reason: reason.clone(),
        },
    );
    Err(format!("✕ not applied · {reason}"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) fn snapshot() -> Snapshot {
        Snapshot::empty()
    }
    #[test]
    fn unmeasured_stale_and_failed_probes_are_distinct() {
        let mut s = snapshot();
        assert_eq!(s.health_color("dns"), crate::theme::muted());
        let h = Arc::make_mut(&mut s.health);
        h.completed.dns = Some(Instant::now());
        h.dns_rtt_ms = None;
        h.dns_loss = netwatch::collectors::health::Loss::Measured(100.0);
        assert_eq!(s.health_color("dns"), crate::theme::error());
        let h = Arc::make_mut(&mut s.health);
        h.completed.dns = Some(Instant::now() - Duration::from_secs(31));
        assert_eq!(s.health_color("dns"), crate::theme::muted());
    }
    #[test]
    fn a_probe_that_could_not_be_sent_is_not_a_dead_link() {
        // netwatch 0.35 reports a probe it could not send as unmeasured with
        // no rtt. That says nothing about the target, so it stays muted.
        let mut s = snapshot();
        let h = Arc::make_mut(&mut s.health);
        h.completed.gateway = Some(s.observed_at);
        h.gateway_rtt_ms = None;
        h.gateway_loss = netwatch::collectors::health::Loss::Unmeasured(
            "icmp is blocked here and the gateway answers no tcp port",
        );
        assert_eq!(s.health_color("gateway"), crate::theme::muted());
        let h = Arc::make_mut(&mut s.health);
        h.gateway_loss = netwatch::collectors::health::Loss::Measured(100.0);
        assert_eq!(s.health_color("gateway"), crate::theme::error());
        let h = Arc::make_mut(&mut s.health);
        h.gateway_rtt_ms = Some(3.0);
        h.gateway_loss = netwatch::collectors::health::Loss::Measured(20.0);
        assert_eq!(s.health_color("gateway"), crate::theme::warn());
    }
    #[test]
    fn successful_probe_alone_does_not_claim_healthy_latency() {
        let mut s = snapshot();
        let h = Arc::make_mut(&mut s.health);
        h.completed.dns = Some(Instant::now());
        h.dns_rtt_ms = Some(2000.0);
        h.dns_loss = netwatch::collectors::health::Loss::Measured(0.0);
        assert_eq!(s.health_color("dns"), crate::theme::text());
    }
    #[test]
    fn promotion_leaves_out_what_the_block_list_matches() {
        use netwatch::collectors::egress::{BlockList, EgressPolicy, EgressProfiler};
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // netwatch's persisted baseline, the one public way to seed profiles.
        let dest = |label: &str, port: u16, sni: Option<&str>, ip: &str| {
            let sni = sni.map_or("null".into(), |s| format!("\"{s}\""));
            format!(
                r#"{{"label":"{label}","port":{port},"sni":{sni},"asn_org":null,"ip":"{ip}","ech":false,"first_seen":{now},"last_seen":{now},"count":3}}"#
            )
        };
        let curl = [
            dest(
                "api.github.com",
                443,
                Some("api.github.com"),
                "140.82.112.5",
            ),
            // Blocked by port 25 globally; the same name on 443 is not.
            dest("mail.example", 25, Some("mail.example"), "203.0.113.25"),
            dest("mail.example", 443, Some("mail.example"), "203.0.113.25"),
            // Blocked by curl's own block list.
            dest("198.51.100.7", 8443, None, "198.51.100.7"),
        ]
        .join(",");
        let mailer = dest("smtp.example", 25, Some("smtp.example"), "203.0.113.26");
        let baseline = format!(
            r#"{{"version":1,"profiles":[{{"process":"curl","dests":[{curl}]}},{{"process":"mailer","dests":[{mailer}]}}]}}"#
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("egress-profiles.json");
        std::fs::write(&path, baseline).unwrap();
        let mut profiler = EgressProfiler::new();
        profiler.load_profiles(&path);
        profiler.set_policy(Some(EgressPolicy {
            block: BlockList {
                ports: vec![25],
                ..Default::default()
            },
            process: [(
                "curl".to_string(),
                ProcessRule {
                    allow_sni: vec!["api.github.com".into()],
                    allow_ports: vec![443],
                    block: BlockList {
                        ip: vec!["198.51.100.0/24".into()],
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )]
            .into(),
            ..Default::default()
        }));
        let (verdicts, promotable) = judge_egress(&profiler, &profiler.snapshot());
        let blocked = |p: &str, l: &str, port: u16| {
            matches!(
                verdicts.get(&(p.into(), l.into(), port)),
                Some(EgressVerdict::Blocked(_))
            )
        };
        assert!(blocked("curl", "mail.example", 25));
        assert!(blocked("curl", "198.51.100.7", 8443));
        assert!(!blocked("curl", "mail.example", 443));
        // netwatch's own promotion would allow all of it.
        let raw = profiler.promote_one("curl").unwrap();
        assert_eq!(raw.allow_ip, ["198.51.100.7"]);
        assert_eq!(raw.allow_ports, [25, 443, 8443]);
        let curl = &promotable["curl"];
        assert_eq!(curl.allow_sni, ["api.github.com", "mail.example"]);
        assert!(curl.allow_ip.is_empty() && curl.allow_asn.is_empty());
        assert_eq!(curl.allow_ports, [443]);
        // Nothing unblocked: no rule at all, since an empty one is
        // unrestricted.
        assert!(profiler.promote_one("mailer").is_some());
        assert!(!promotable.contains_key("mailer"));
    }
    #[test]
    fn promotion_without_blocked_destinations_is_netwatchs() {
        let dest = |sni: Option<&str>, ip: &str, port: u16| EgressDest {
            sni: sni.map(str::to_string),
            asn_org: None,
            port,
            last_ip: ip.into(),
            ech: false,
            first_seen: std::time::SystemTime::now(),
            last_seen: std::time::SystemTime::now(),
            count: 1,
            bytes_out: 0,
            bytes_in: 0,
            activity: VecDeque::new(),
        };
        let rule = ProcessRule {
            allow_sni: vec!["api.github.com".into()],
            allow_ip: vec!["10.0.0.7".into()],
            allow_ports: vec![80, 443],
            ..Default::default()
        };
        let (a, b) = (
            dest(Some("api.github.com"), "140.82.112.5", 443),
            dest(None, "10.0.0.7", 80),
        );
        let kept = without_blocked(rule.clone(), &[(&a, false), (&b, false)]).unwrap();
        assert_eq!(kept.allow_sni, rule.allow_sni);
        assert_eq!(kept.allow_ip, rule.allow_ip);
        assert_eq!(kept.allow_ports, rule.allow_ports);
        // The only named destination blocked: what is left names nothing,
        // which would be unrestricted, so there is no rule.
        let nameless = dest(None, "", 443);
        let rule = ProcessRule {
            allow_sni: vec!["api.github.com".into()],
            allow_ports: vec![443],
            ..Default::default()
        };
        assert!(without_blocked(rule, &[(&a, true), (&nameless, false)]).is_none());
    }
    #[test]
    fn ai_rows_rebuild_or_drop_the_collector() {
        let old = NetwatchConfig {
            insights_enabled: true,
            ..NetwatchConfig::default()
        };
        let off = NetwatchConfig {
            insights_enabled: false,
            ..old.clone()
        };
        let moved = NetwatchConfig {
            insights_endpoint: "http://10.0.0.9:11434".into(),
            ..old.clone()
        };
        let unrelated = NetwatchConfig {
            show_geo: !old.show_geo,
            ..old.clone()
        };
        assert!(ai_settings_changed(&old, &off));
        assert!(ai_settings_changed(&old, &moved));
        assert!(!ai_settings_changed(&old, &unrelated));
        assert!(insights_collector_for(&off).is_none());
        assert!(insights_collector_for(&moved).is_some());
    }
    #[cfg(unix)]
    #[test]
    fn exports_are_owner_only_and_need_a_cache_directory() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        // No HOME means no export, not a shared /tmp directory.
        let refused = prepare_export_dir(None).unwrap_err();
        assert!(refused.contains("no cache directory"), "{refused}");

        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("netwatch").join("exports");
        // An older desktop created it 0755; the next export narrows it.
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let dir = prepare_export_dir(Some(dir)).unwrap();
        assert_eq!(mode(&dir), 0o700);

        let stamp = "20261003_120000";
        let conns = crate::preview::connections();
        let ok = export_connections(&dir, stamp, &conns).unwrap();
        assert!(ok.contains(&format!("{} sockets", conns.len())), "{ok}");
        export_csv(&dir, "interfaces", stamp, "name,rx\neth0,1\n").unwrap();
        export_egress(&dir, stamp, &EgressProfiler::new()).unwrap();
        export_pcap(&dir, "all", stamp, &[]).unwrap();
        let report = export_report(&dir, stamp, "# report\n", "{}").unwrap();
        assert_eq!(mode(&report), 0o700);

        let mut files = Vec::new();
        let mut dirs = vec![dir.clone()];
        while let Some(d) = dirs.pop() {
            for entry in std::fs::read_dir(&d).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    assert_eq!(mode(&path), 0o700, "{}", path.display());
                    dirs.push(path);
                } else {
                    assert_eq!(mode(&path), 0o600, "{}", path.display());
                    files.push(path.file_name().unwrap().to_string_lossy().into_owned());
                }
            }
        }
        files.sort();
        assert_eq!(
            files,
            [
                format!("connections_{stamp}.csv"),
                format!("connections_{stamp}.json"),
                format!("netwatch_all_{stamp}.pcap"),
                format!("netwatch_egress_{stamp}.ndjson"),
                format!("netwatch_interfaces_{stamp}.csv"),
                "report.json".to_string(),
                "report.md".to_string(),
            ]
        );
        // netwatch's writers filled the files they were handed.
        let json = std::fs::read_to_string(dir.join(format!("connections_{stamp}.json"))).unwrap();
        assert!(json.contains("browser"), "{json}");
    }
}
