# Graph rendering

The dashboard is built around the mirrored throughput graph. Receive is cyan above zero; transmit is violet below it. The three latency charts use the same renderer.

## Capacity and zoom

The default ceiling is the selected interface's reported link capacity, converted from bits/s to bytes/s. Link speed comes from Netwatch's existing platform implementation. It is not inferred from the observed peak. When speed is unavailable, the UI explicitly identifies a fixed 10 MB/s viewing range instead of calling it link capacity.

Use the scale menu or + / − to choose a manual viewing range. Selecting Link capacity restores the default. Values beyond the range clip with a visible indicator; a spike never changes the scale. Both directions share the ceiling. Linear and logarithmic views are available, with 30-second, 1-minute and 5-minute windows.

## Pre-rendered capacity

Each graph owns two cached GPU textures: the complete dim capacity grid (including guide lines), and a fully lit dot-cell surface with the vertical magnitude gradient. Gradients use Netwatch's existing `magnitude_ramp` implementation.

Textures are generated only when dimensions, DPI, layout or colors change. A normal animation frame, new sample, range change or window change does not rasterize or upload capacity cells. The active layer is revealed by textured interval rectangles; it is not rebuilt by drawing every illuminated dot. Texture handles replace the old surfaces on resize rather than accumulating them.

## Animation and measurement integrity

The shared TrafficCollector now retains actual timestamps alongside RX/TX history. Probe charts use the existing probe completion timestamps. No assumption that every sample is one second apart is used to lay out history.

Only the presentation cursor animates. Measurement values do not tween: a spike stays a spike, a measured zero remains distinct from a missing reading, and a collector stall leaves a gap. The mask moves at sub-cell precision over the stationary pre-rendered grid. Sub-cell spikes occupy at least one cell to remain visible at wider time ranges; hover reports the peak within its cell interval.

Scrolling is driven by elapsed time and vsync repaints while moving. It stops at the latest received sample and does not extrapolate new traffic. The time axis/hover account for the small presentation delay during a scroll. Turning off Smooth motion immediately displays the latest samples and stops animation repaints. Off-screen graphs request no animation frames.

## Validation and visual review

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo test cached_graph_frame_cost -- --ignored --nocapture
cargo run -- --graph-preview
cargo run -- --graph-preview --screenshot /tmp/netwatch-graphs.png
```

Preview data is deterministic and prominently labelled DEMO. This mode starts no collectors or network probes and does not modify Netwatch's configuration or baselines. Native screenshot capture is opt-in and captures only the app viewport. Screenshots validate appearance; the explicit frame-cost benchmark and sub-cell regression test validate animation behavior without screenshot encoding overhead.

Regression tests cover capacity conversion, fixed/manual scales, logarithmic mapping, missing data, peak preservation, frame-independent motion, sub-cell movement, texture reuse and resize/DPI invalidation.

On the development host, a debug-build benchmark over 660 frames with 600 measurements and a 1440px graph measured 0.372 ms median / 0.606 ms p95 / 1.060 ms maximum CPU time, including egui tessellation, with one texture bake. These are graph CPU timings, not end-to-end GPU/frame-rate guarantees.
