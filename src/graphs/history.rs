//! Timestamped measurement intervals and a presentation-only scrolling cursor.
//! No interpolation of metric values: short spikes survive pixel bucketing.
use std::time::Instant;

#[derive(Clone, Copy, Debug)]
pub struct Reading {
    pub start: f64,
    pub end: f64,
    pub rx: Option<f64>,
    pub tx: Option<f64>,
}

#[derive(Default)]
pub struct History {
    pub samples: Vec<Reading>,
    pub epoch: Option<Instant>,
    pub latest: Option<Instant>,
    pub cursor: Cursor,
}
impl History {
    /// Called only when the collector publishes a different completion time.
    pub fn update(
        &mut self,
        points: impl IntoIterator<Item = (Instant, Option<f64>, Option<f64>)>,
        interval: f64,
        now: f64,
    ) {
        let points: Vec<_> = points.into_iter().collect();
        let Some((latest, _, _)) = points.last().copied() else {
            *self = Self::default();
            return;
        };
        if self.latest == Some(latest) {
            return;
        }
        let first = self.latest.is_none();
        let epoch = *self.epoch.get_or_insert(points[0].0);
        let seconds = |at: Instant| {
            if at >= epoch {
                at.duration_since(epoch).as_secs_f64()
            } else {
                -epoch.duration_since(at).as_secs_f64()
            }
        };
        self.samples.clear();
        for (i, &(at, rx, tx)) in points.iter().enumerate() {
            let end = seconds(at);
            let previous = if i == 0 {
                end - interval
            } else {
                seconds(points[i - 1].0)
            };
            // A stalled collector is a gap, not a long fabricated measurement.
            let start = if end - previous > interval * 3.0 {
                end - interval
            } else {
                previous
            };
            self.samples.push(Reading {
                start,
                end,
                rx: finite(rx),
                tx: finite(tx),
            });
        }
        let target = seconds(latest);
        self.cursor.retarget(target, now, interval, first);
        self.latest = Some(latest);
    }
}
fn finite(v: Option<f64>) -> Option<f64> {
    v.filter(|v| v.is_finite() && *v >= 0.0)
}

#[derive(Default)]
pub struct Cursor {
    from: f64,
    target: f64,
    started: f64,
    duration: f64,
}
impl Cursor {
    pub fn retarget(&mut self, target: f64, now: f64, cadence: f64, snap: bool) {
        let from = if snap { target } else { self.at(now, true) };
        self.from = from.min(target);
        self.target = target;
        self.started = now;
        self.duration = cadence.clamp(0.1, 1.25);
    }
    pub fn at(&self, now: f64, animate: bool) -> f64 {
        if !animate || self.duration <= 0.0 {
            return self.target;
        }
        let t = ((now - self.started) / self.duration).clamp(0.0, 1.0);
        self.from + (self.target - self.from) * t
    }
    pub fn moving(&self, now: f64) -> bool {
        self.at(now, true) < self.target
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct Bucket {
    pub rx: Option<f64>,
    pub tx: Option<f64>,
}
/// Peak per occupied pixel interval. Unknown intervals stay None; measured
/// zero is Some(0). Linear walk over the visible measurements and columns.
pub fn bucket(samples: &[Reading], cursor: f64, window: f64, out: &mut [Bucket]) {
    if out.is_empty() {
        return;
    }
    let width = window / out.len() as f64;
    let left = cursor - window;
    let mut first = samples.partition_point(|s| s.end <= left);
    for (column, result) in out.iter_mut().enumerate() {
        let start = left + column as f64 * width;
        let end = start + width;
        while first < samples.len() && samples[first].end <= start {
            first += 1;
        }
        *result = Bucket::default();
        for sample in &samples[first..] {
            if sample.start >= end {
                break;
            }
            if sample.end > start {
                if let Some(v) = sample.rx {
                    result.rx = Some(result.rx.unwrap_or(0.0).max(v));
                }
                if let Some(v) = sample.tx {
                    result.tx = Some(result.tx.unwrap_or(0.0).max(v));
                }
            }
        }
    }
}
