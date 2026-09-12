//! Thin wrapper around netwatch's existing collectors. No new collection
//! logic lives here — this only owns the collector instances, ticks them on
//! a background thread, and exposes their snapshot getters to the UI.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use netwatch::collectors::config::ConfigCollector;
use netwatch::collectors::connections::{Connection, ConnectionCollector};
use netwatch::collectors::health::HealthStatus;
use netwatch::collectors::packets::StreamTracker;
use netwatch::collectors::traffic::{InterfaceTraffic, TrafficCollector};
use netwatch::collectors::health::HealthProber;

const TICK: Duration = Duration::from_millis(1000);

pub struct Backend {
    traffic: TrafficCollector,
    connections: ConnectionCollector,
    health: HealthProber,
}

impl Backend {
    pub fn spawn() -> Arc<Backend> {
        let stream_tracker = Arc::new(Mutex::new(StreamTracker::new()));
        let backend = Arc::new(Backend {
            traffic: TrafficCollector::new(),
            connections: ConnectionCollector::new(stream_tracker),
            health: HealthProber::new(),
        });

        let ticker = Arc::clone(&backend);
        std::thread::spawn(move || {
            // Owned by this thread alone — `update()` shells out to
            // `ip route` / `/etc/resolv.conf`, cheap enough to redo every
            // cycle so a network change (new gateway, VPN up/down) is
            // picked up without a restart.
            let mut config = ConfigCollector::new();
            loop {
                ticker.traffic.update();
                ticker.connections.update();
                config.update();
                ticker
                    .health
                    .probe(config.config.gateway.as_deref(), config.config.primary_dns().as_deref());
                std::thread::sleep(TICK);
            }
        });

        backend
    }

    pub fn interfaces(&self) -> Arc<Vec<InterfaceTraffic>> {
        self.traffic.interfaces()
    }

    pub fn connections(&self) -> Arc<Vec<Connection>> {
        self.connections.connections()
    }

    pub fn health(&self) -> Arc<HealthStatus> {
        self.health.status()
    }
}
