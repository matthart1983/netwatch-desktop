//! Desktop adapter over the same application runtime used by the TUI.
//!
//! The runtime thread owns `App`. Once per tick it copies what the screens
//! read into an immutable [`Snapshot`]; bulky, append-only stores (the packet
//! ring and stream tracker) travel as shared handles instead of copies, so a
//! 5 000-packet ring is not cloned every second. Screens never mutate `App`:
//! they queue [`Command`]s, and every command reports one [`ActionResult`]
//! that the footer toast shows.
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use netwatch::app::{App, IfaceChangeEvent};
use netwatch::collectors::{
    connections::{Connection, TrackedConnection},
    egress::{EgressPolicy, EgressProfile, ProcessRule, RecentViolation, Verdict as EgressVerdict},
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

#[derive(Clone, Default)]
pub struct EgressSnapshot {
    pub profiles: Vec<EgressProfile>,
    /// (process, destination label, port) → the profiler's verdict.
    pub verdicts: HashMap<(String, String, u16), EgressVerdict>,
    pub policy_path: Option<PathBuf>,
    pub policy: Option<EgressPolicy>,
    /// Unix permission bits of the policy file when it exists.
    pub policy_mode: Option<u32>,
    pub has_policy: bool,
    /// What `promote_one` would write for each observed process.
    pub promotable: HashMap<String, ProcessRule>,
    pub recent: Vec<RecentViolation>,
    pub cooldown_secs: u64,
}

#[derive(Clone)]
pub struct DiagnoseSnapshot {
    /// Every tracked issue, including closed and suppressed ones.
    pub issues: Vec<Issue>,
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
    pub export_dir: PathBuf,
    /// The latest command outcome; `seq` changes once per command.
    pub action: Option<ActionResult>,
}

pub fn export_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("netwatch")
        .join("exports")
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

    pub fn health_color(&self, target: &str) -> egui::Color32 {
        let (at, rtt, loss, prefix) = match target {
            "gateway" => (
                self.health.completed.gateway,
                self.health.gateway_rtt_ms,
                self.health.gateway_loss_pct,
                "gateway.",
            ),
            "dns" => (
                self.health.completed.dns,
                self.health.dns_rtt_ms,
                self.health.dns_loss_pct,
                "dns.",
            ),
            _ => (
                self.health.completed.internet,
                self.health.internet_rtt_ms,
                self.health.internet_loss_pct,
                "path.",
            ),
        };
        if !at.is_some_and(|at| {
            self.observed_at.saturating_duration_since(at) <= std::time::Duration::from_secs(30)
        }) {
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
        if rtt.is_none() || loss >= 50.0 {
            crate::theme::error()
        } else if loss > 0.0 {
            crate::theme::warn()
        } else {
            crate::theme::text()
        }
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
            let mut verdicts = HashMap::new();
            let mut promotable = HashMap::new();
            for profile in &profiles {
                for ((label, port), dest) in &profile.dests {
                    verdicts.insert(
                        (profile.process.clone(), label.clone(), *port),
                        profiler.verdict(&profile.process, dest),
                    );
                }
                if let Some(rule) = profiler.promote_one(&profile.process) {
                    promotable.insert(profile.process.clone(), rule);
                }
            }
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
            events: netwatch::app::build_diagnose_report(app).timeline,
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
    EgressPromoteAll,
    EgressPromote(String),
    /// Additively merge one rule into the policy file (a single-destination
    /// allow from the flow inspector).
    EgressAllow {
        process: String,
        rule: ProcessRule,
        summary: String,
    },
    DiagnoseAck(String),
    DiagnoseMute(String),
    DiagnoseApply(String),
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
    pub fn spawn_session(demo: bool) -> Arc<Self> {
        let snapshot = Arc::new(RwLock::new(None));
        let error = Arc::new(RwLock::new(None));
        let (stop, stopped) = mpsc::channel();
        let (commands, pending) = mpsc::channel();
        let published = Arc::clone(&snapshot);
        let failed = Arc::clone(&error);
        let thread = std::thread::spawn(move || {
            let config = NetwatchConfig::load();
            let mode = netwatch::sandbox::Mode::from_config(&config.sandbox);
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

fn ensure_export_dir() -> Result<PathBuf, String> {
    let dir = export_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("✕ export failed · {} · {e}", dir.display()))?;
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
    let policy = netwatch::collectors::egress::load_policy_file(path);
    let loaded = policy.is_some();
    app.egress_profiler.set_policy(policy);
    loaded
}

fn run_command(app: &mut App, command: Command) -> Result<String, String> {
    use netwatch::collectors::egress;
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
        Command::ExportReport => {
            netwatch::app::export_diagnose_report(app);
            let status = app.diagnose.status.clone().unwrap_or_default();
            app.ui.export_status = Some(status.clone());
            if status.to_lowercase().contains("fail") {
                Err(status)
            } else {
                Ok(status)
            }
        }
        Command::ExportIncident => {
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
            let path = dir.join(format!("netwatch_{label}_{}.pcap", timestamp()));
            netwatch::collectors::packets::export_pcap(&packets, &path.to_string_lossy())
                .map(|n| format!("✓ exported {} · {n} packets", path.display()))
                .map_err(|e| format!("✕ pcap export failed · {e}"))
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
            let stamp = timestamp();
            let conns = app.connection_collector.connections();
            let json = dir.join(format!("connections_{stamp}.json"));
            let csv = dir.join(format!("connections_{stamp}.csv"));
            netwatch::collectors::connections::export_json(&conns, &json.to_string_lossy())
                .and_then(|_| {
                    netwatch::collectors::connections::export_csv(&conns, &csv.to_string_lossy())
                })
                .map(|n| format!("✓ exported {} · csv · {n} sockets", json.display()))
                .map_err(|e| format!("✕ export failed · {e}"))
        }
        Command::ExportCsv { label, csv } => {
            let dir = ensure_export_dir()?;
            let path = dir.join(format!("netwatch_{label}_{}.csv", timestamp()));
            let rows = csv.lines().count().saturating_sub(1);
            std::fs::write(&path, csv)
                .map(|_| format!("✓ exported {} · {rows} rows", path.display()))
                .map_err(|e| format!("✕ export failed · {e}"))
        }
        Command::ExportEgress => {
            let dir = ensure_export_dir()?;
            let path = dir.join(format!("netwatch_egress_{}.ndjson", timestamp()));
            app.egress_profiler
                .export_ndjson(&path)
                .map(|n| format!("✓ exported {} · {n} records", path.display()))
                .map_err(|e| format!("✕ egress export failed · {e}"))
        }
        Command::EgressPromoteAll => {
            let path = egress::default_policy_path().ok_or("✕ promote failed · no config dir")?;
            let policy = app.egress_profiler.promote();
            let rules: Vec<(String, ProcessRule)> = policy.process.into_iter().collect();
            let n = rules.len();
            egress::merge_rules_into_policy_file(&rules, &path)
                .map_err(|e| format!("✕ promote failed · {e}"))?;
            if reload_policy(app, &path) {
                Ok(format!("✓ promoted {n} processes · {}", path.display()))
            } else {
                Err(format!(
                    "✕ promoted but reload refused · check permissions (chmod 644) · {}",
                    path.display()
                ))
            }
        }
        Command::EgressPromote(process) => {
            let path = egress::default_policy_path().ok_or("✕ promote failed · no config dir")?;
            let rule = app
                .egress_profiler
                .promote_one(&process)
                .ok_or_else(|| format!("✕ nothing observed for {process}"))?;
            let diff = egress::rule_diff(app.egress_profiler.declared_rule(&process), &rule);
            egress::merge_rules_into_policy_file(&[(process.clone(), rule)], &path)
                .map_err(|e| format!("✕ promote failed · {e}"))?;
            if reload_policy(app, &path) {
                Ok(format!(
                    "✓ promoted {process} · {diff} · {}",
                    path.file_name().unwrap_or_default().to_string_lossy()
                ))
            } else {
                Err(format!(
                    "✕ promoted but reload refused · chmod 644 {}",
                    path.display()
                ))
            }
        }
        Command::EgressAllow {
            process,
            rule,
            summary,
        } => {
            let path = egress::default_policy_path().ok_or("✕ allow failed · no config dir")?;
            egress::merge_rules_into_policy_file(&[(process.clone(), rule)], &path)
                .map_err(|e| format!("✕ allow failed · {e}"))?;
            if reload_policy(app, &path) {
                Ok(format!(
                    "✓ allowed {summary} for {process} · {}",
                    path.display()
                ))
            } else {
                Err(format!(
                    "✕ written but reload refused · chmod 644 {}",
                    path.display()
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
        Command::SaveConfig(config) => {
            let mut config = *config;
            config.validate();
            let ai_changed = ai_settings_changed(&app.user_config, &config);
            app.user_config = config;
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
            match app.user_config.save() {
                Ok(()) => Ok(format!(
                    "✓ saved {}",
                    NetwatchConfig::path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default()
                )),
                Err(e) => Err(format!("✕ save failed · {e}")),
            }
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
        h.dns_loss_pct = 100.0;
        assert_eq!(s.health_color("dns"), crate::theme::error());
        let h = Arc::make_mut(&mut s.health);
        h.completed.dns = Some(Instant::now() - Duration::from_secs(31));
        assert_eq!(s.health_color("dns"), crate::theme::muted());
    }
    #[test]
    fn successful_probe_alone_does_not_claim_healthy_latency() {
        let mut s = snapshot();
        let h = Arc::make_mut(&mut s.health);
        h.completed.dns = Some(Instant::now());
        h.dns_rtt_ms = Some(2000.0);
        h.dns_loss_pct = 0.0;
        assert_eq!(s.health_color("dns"), crate::theme::text());
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
}
