# Dense view

Choose **Dense view** from the menu or command palette, or cycle Full → Lite → Dense with `V`. `--view dense` starts there directly. All three views share the same running backend, selected connection, pause state, graph controls and interface zoom. Switching views never restarts collectors or changes the apparent text size.

Dense uses the spec's four boxes with no navigator, timeline dock or application footer:

Panel heights scale with the window (NET about 31%, IFACES/HEALTH about 24%, CONNS the rest). Tables size columns from the panel width and text size; optional columns drop first on narrow windows and graphs take the remaining width. Text uses the main view's type scale: 12-point data, 11-point labels and 10-point metadata, in the same bundled fonts. The saved text size applies to every view (115% by default); Ctrl + / Ctrl − steps it in all views, Ctrl 0 returns to 115%, and the ☰ menu lists every size. Dense only reduces spacing between controls and rows. The old separate `dense_text` preference is ignored.

- **1 NET:** mirrored btop throughput spanning the full retained 10-minute history. Link capacity scales the graph when known; otherwise an auto 1-2-5 range over the retained peak replaces the fixed 10 MB/s fallback. Manual ranges still apply. Current/peak/mean rates, session and lifetime byte/packet/drop counters. The SOCKET SIGNALS column shows concern mix, kernel TCP/PID/rate coverage, protocol and state mix, findings and the top peers by rate and socket count.
- **2 IFACES:** rate-sorted interfaces with observed link state, RX/TX, session and lifetime totals, lifetime error/drop counters, wireless signal/retries when reported, and 10-minute histories whose height grows when there are few interfaces. Aggregate counters may count virtual-interface traffic more than once.
- **3 HEALTH:** gateway, DNS and Internet targets, RTT, retained min/p95/jitter and measured probe count, probe loss, fixed 20/100/250 ms viewing-budget meters, a 10-minute RTT trend, status and baseline. Jitter is the mean absolute change between consecutive measured probes; failed probes are gaps. Budgets do not reclassify network health. Waiting, stale, failed and measured readings remain distinct.
- **4 CONNS:** sockets grouped by process, with a header showing PID, socket count and total RX/TX; single-socket processes need no header. Different PIDs remain separate even when names match. Sockets without a PID or name group by remote host; unattributed listening/unconnected sockets collect in one final group that starts collapsed (click to expand; collapsed sockets are skipped by arrow selection). Groups rank by their highest-concern socket. Columns: process, PID, local port, remote, protocol, rates, kernel RTT, lifetime retransmissions, cwnd, rwnd, state, verdict and 60-second flow history on a range shared across flows. The selected socket's endpoint, state, kernel and handshake RTT, retrans/cwnd/ssthresh/MSS/rwnd and captured retransmit/out-of-order counts appear above the virtualized table. Arrow navigation skips headers and scrolls the selected socket into view. Double-click a cell or press Enter to open the same socket in Connections.

In box 4, `g` cycles grouping (none → host → process, remembered between runs). With grouping on, `↑↓` also stop on group headers; `space` or a click folds the group under the cursor, `←`/`→` fold and unfold, and `Z` folds every group or unfolds them all. Unattributed listeners start folded; other groups start open. Space only folds groups; `p` pauses.

Keys **1–4** or the panel-heading buttons zoom/restore a panel. Esc restores four boxes, then returns to Full. `V` returns to the previous Full tab; `L` opens Lite. Arrow keys select and scroll the connection table. `p` pauses the display while collection and recording continue. `d` opens Diagnose; `R`, `F` and `E` control the recorder; `:`, `?` and `q` open commands, help and quit. The title bar includes pause/resume, commands, full-view and maximise/restore controls.

Dense supports **1100×680 logical pixels**, with **1280×760** as its usual starting size; the four boxes scale with larger windows. Table and health content scroll inside their boxes, and long fields retain their full value in tooltips. Returning to Full restores its 900×600 minimum without forcing the user's window smaller.

## Data and rendering

`telemetry.rs` retains presentation history over existing collector output. Session totals begin at the first desktop snapshot and accumulate observed deltas, including counter resets. Interface disappearance establishes a new baseline on reappearance, excluding the unobserved gap. Prior observed totals survive transient disappearance; churn retention is bounded. Flow histories retain up to 60 seconds / 600 samples for the 512 highest-concern sockets. An unchanged collector snapshot does not create a new sample, so polling stalls remain gaps. Missing capture values stay gaps; a missing history is not a zero rate. The full connection table is not limited to 512 sockets.

NET, interface/connection sparklines and RTT budget meters use the same cached capacity textures and magnitude ramps as Full. RTT meters crop a cached horizontal budget surface. Measurement changes do not rebuild capacity. Resizing or changing the palette can rebuild a texture. Flow sparklines share one auto range across all retained flows so rows stay comparable. The main instrument and the selected interface use link capacity by default; without it they use the auto range.

## Verification

Automated tests cover minimum/large layout geometry, all four zooms with unavailable data, real pointer selection and double-click drill-through, keyboard precedence, view switching without replacing the backend, frozen snapshot identity, session counter deltas/resets, bounded histories, and virtualized keyboard scrolling through 1,200 sockets. Capacity cache tests cover repeated frames, changing measurements and resizing.

```sh
cargo test --offline
cargo clippy --offline --all-targets -- -D warnings
cargo build --release --offline
cargo test --offline dense::tests::dense_frame_cost_and_capacity_cache -- --ignored --nocapture
./target/debug/netwatch-desktop --graph-preview --view dense --window-size 1280x760 --screenshot /tmp/dense.png
./target/debug/netwatch-desktop --graph-preview --view dense --dense-box 4 --screenshot /tmp/dense-connections.png
```

The explicit debug performance check measured 1.87 ms median / 2.23 ms p95 for egui UI plus tessellation at 1440×900, with one NET capacity bake across 260 frames. The standalone graph check measured 0.195 ms median / 0.261 ms p95 with one capacity bake across 660 frames. These are CPU timings, not a GPU frame-rate guarantee. Native screenshots are checked separately at minimum/default sizes and in each panel zoom. Screenshot runs avoid activation and ignore shortcuts so incidental keyboard input cannot change the requested view.

Reverified on 2026-09-13 after resuming the implementation thread: 31 automated tests and both opt-in performance/cache checks passed; formatting, strict Clippy, debug and release builds passed. Seven release-binary native captures verified all four boxes at 1280×760 and 1440×900 logical pixels, all four zooms at minimum size, and the live counters-only path. Captures used the host's fractional display scaling. The release runtime smoke test saw 48 sockets, 18 kernel TCP records and fresh completions for all three probe targets. Packet capture remains unavailable on this host without CAP_NET_RAW; the privileged capture path and other operating systems were not verified in this run.

Process grouping follow-up: 32 automated tests passed, including process identity, aggregate unknown rates, concern ordering and selection across group reorder. Both performance/cache checks, strict Clippy, debug and release builds passed. Native release captures checked the grouped minimum-size demo and the live zoomed connection table.

![Dense view with explicit synthetic demo data](screenshots/dense.png)

Typography follow-up (2026-09-15): dense now inherits the full-view type scale and shared zoom. Legacy dense-only font preferences are ignored. At 1280×760, native before/after captures confirmed matching text size and more visible interface/connection columns. The 202-test suite, Clippy, formatting and release build passed; two optional performance tests remain ignored.
