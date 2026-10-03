# Desktop implementation decisions

These amendments resolve contradictions found in the 2026-09-13 desktop design bundle (`~/Downloads/NetWatch desktop application design.zip`). The HTML files remain visual references. Existing Netwatch rule semantics and runtime capabilities take precedence over illustrative mock data and commands.

## Shared implementation

The desktop imports `netwatch-tui` by path. It constructs the existing `App`, starts its runtime on a dedicated thread, and publishes immutable snapshots to egui. Capture, process attribution, TCP state, interface selection, health probing, baselines, diagnostic rules, egress learning and shutdown come from that runtime. Keep these implementations shared; introduce a narrower runtime facade later only if App coupling obstructs an actual feature.

The GUI must not apply worker sandbox restrictions to its display thread. Runtime startup applies policy on its own thread, and errors are displayed rather than silently disabling configured protection.

Unknown metrics are distinct from measured zero. Kernel RTT/retransmissions are explicitly labelled; handshake RTT and flow rates come from packet capture. The headline throughput and graph use the same selected interface. Graph history uses actual collector completion timestamps. The btop-style capacity grid and magnitude gradients are cached textures; only the measurement mask animates. Link capacity is the default scale, with explicit manual zoom. See GRAPHS.md.

## Specification corrections

- Keyboard precedence: text editing and modal sheets, then focused panel actions, then global navigation. Digits typed in a field must not switch tabs. Enter drills; on Egress, `a` stages approval and `w` writes the reviewed diff. Reserve Space for panel actions; use a dedicated pause command instead of conflicting with process navigation.
- Permissions must name the running desktop executable, not `which netwatch`. Generate any grant instructions from actual platform/build capabilities and the resolved executable path; this build disables eBPF. Do not copy the mock's broad capability command.
- Privacy copy: collection and analysis are local. Active health checks send DNS, reachability and STUN probes. Optional online lookups/AI follow the existing Netwatch configuration. Do not claim that no traffic leaves the host.
- Muted dark text is `#8996a8`, replacing `#6c788a`, to meet the specified 4.5:1 contrast on panel and raised backgrounds.
- Full view's minimum window is 900×600. Breakpoints are in layout points (window pixels ÷ UI zoom), and the shell gives things up in this order: below 1180 the inspector is a sheet (`I`), below 860 the navigator is a narrow list of tab names without its groups, below 620 it is the digit rail. Measuring in points keeps the three columns readable at any zoom.

The user’s subsequent graph direction supersedes the draft’s “no animations” instruction: smooth, time-based graph motion is on by default, with a Smooth motion control to disable it.

## Current scope

All ten tabs, the settings / first run / flight recorder / help / palette sheets, and the lite and dense views are implemented against the mocks. The architecture:

- `backend.rs` publishes an immutable `Snapshot` per tick (packet ring and stream tracker as shared handles) and runs `Command`s on the runtime thread; every command yields one `ActionResult` shown as the footer toast.
- `shell.rs` defines the `Screen` and `Sheet` contracts, keys, hints, breadcrumb navigation and filters; `app.rs` draws the Workbench frame and routes keys (sheet → digits → screen → global).
- `ui_kit.rs` holds the spec components (panels with badges, control and status strips, grid tables with per-cell selection, pills, key hints, meters, sparklines, sheets). `theme.rs` provides runtime palettes: dark and paper from the spec plus the six TUI themes mapped by slot.
- `screens/*` own one tab each; `sheets/*` and `lite.rs` own the sheets and lite view.

Where the crate cannot supply what a mock shows, the slot stays and the reason is in panel metadata rather than a fabricated value. Known gaps:

- ASN per hop, interface driver/qdisc/offload/uptime, per-interface gateway/DNS, TLS version per packet, and tcp_info pacing/delivered/lost are not collected.
- Traceroute runs one target at a time with no history; superseded hops and "since" deltas appear only after a retrace in this session. Timeline retransmission and recorder history are kept locally from app start.
- Egress "keep warning" is a desktop-side dismissal for the re-warn interval; single-destination allow merges one rule line. Diagnose apply is simulated in demo sessions and never applied by a live desktop session, matching the TUI.
- Right-click opens no action menu yet; the inspector's actions list serves instead. Column drag-reorder and per-column width persistence are not implemented.
- App-drawn window chrome is opt-in (`--app-chrome`) until edge resizing is verified across compositors.

Dense view is implemented against mock 2o. See [DENSE.md](DENSE.md) for controls, data semantics and verification. In dense, `p` pauses (`f` remains an alias); space folds.
