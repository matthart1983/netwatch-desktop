# Desktop deep review — progress

Source: user's full **netwatch-desktop deep review, 2026-09-15**.
Reconciled against local `master` at `ffd8510` and the working tree on 2026-09-15.
This is the governing desktop backlog. The separate netwatch Diagnose feature
work is not a substitute for completing these findings.

## How to read status

- **Implemented**: the cited commit describes the fix; existing automated checks pass. This does not imply every original manual acceptance check has been repeated.
- **Partial**: some parts have landed; the remaining parts are still work.
- **Open**: the current source confirms the gap.
- **Recheck**: retained from the review; not independently resolved in this reconciliation.

Do not count a shared hook or a passing suite as completion of every screen's behavior.

## Latest completed block: egress write safety

Implemented in the working tree after `ffd8510`:

- All policy mutations use a reviewed edit, guarded against demo mode in the backend.
- `P` opens a combined diff; `w`/process Enter and `a` also require explicit `y`/Write policy confirmation. Esc cancels.
- Edits are built from the actual disk contents. Invalid, symbolic-link and group/world-writable policy files are refused before review and checked again before writing.
- A changed source file or changed permissions invalidate a pending review.
- Writes preserve existing permission bits, comments on promoted rules, unrelated rules and unrestricted ports/name dimensions; a new file starts owner-only.
- Allowing a previously unruled process names the rule and counts other observed destinations that become drift.
- `x` reviews removal of the selected process rule, including the effect of strict mode.
- Draft arrays wrap, and the complete reviewed file diff scrolls in both directions.

Next review block: remaining keyboard/table parity and first-screen behavior,
including point-based breakpoints and dashboard health sizing. See the open and
partial rows below; none are implied complete by this egress work.

## Landed checkpoints

| Commit | Scope |
|---|---|
| `4a54667` | Eight high findings |
| `187fd12` | Shared table context menus, keys/copy hooks, GeoIP handle |
| `f438fe7` | Packets/stats medium fixes |
| `48dee7b` | Shell keys, help, startup recovery, layout toggles, persistence |
| `4fb2563` | Bookmark persistence documentation |
| `ffd8510` | Stats `t` window cycling |

## High findings

| IDs | Status | Result / remaining verification |
|---|---|---|
| DEL-1 | Implemented | Destination Enter drills into packets; process promotion follows selection type. |
| DEL-2 | Implemented | Allow/keep-warning retain the selected destination. |
| PAR-1 | Implemented | AI collector is replaced/dropped when enabled/model/endpoint changes; covered by tests. |
| SHELL-1 | Implemented | Tab removed before egui focus pass; original live Tab-then-2 check remains to repeat. |
| PKS-2 | Implemented | Invalid filters rejected into editable error state. |
| TTP-1 | Implemented | Connections reconstructs sockets alive at the timeline cursor; identifies live values. |
| DCI-1 | Implemented | Top, selected, concern and filtered groups open while preserving process grouping. |
| PKS-1 | Implemented | Stream conversation view with direction and text/hex controls. |

## Medium findings — shell

| IDs | Status | Result / remaining work |
|---|---|---|
| SHELL-3, DEL-5, TTP-2, DCI-17 | Partial | Global `d` landed; recheck dock scrub hints against actual actions. |
| SHELL-4 | Implemented | Palette shell actions bypass tab keys. |
| SHELL-5, PKS-3 | Implemented | Screen receives Enter; `I` opens compact inspector. |
| SHELL-6 | Open | Breakpoints still compare zoomed points, including key routing. |
| SHELL-8, PAR-6, PAR-10, DEL-20 | Partial | Per-view help and scrolling landed; full per-screen key coverage still needs audit. |
| SHELL-11, SHELL-12, DCI-16 | Implemented | Pause/panel/theme keys separated; Stats `t` added in `ffd8510`. |
| SHELL-14, DEL-11 | Implemented | Dock, navigator, lite on-top toggles and short-window dock sizing. |
| SHELL-7, PAR-9 | Implemented | Terminal-only settings labeled; terminal tab choices corrected. |
| PAR-7, SHELL-2 | Implemented | Startup recovery UI and sandbox flags; platform verification still needed. |
| SHELL-10, PAR-8, DEL-13, DCI-12 | Partial | Shared context-menu infrastructure and packet menu; consistent sorting, resizing and remaining screen menus unfinished. |
| PAR-4 | Partial | Global copy hook and packet copy landed; remaining selected-row/inspector implementations need completion. |
| SHELL-13 | Implemented | Whole footer hints, bounded toast width and shorter duration. |
| SHELL-9 | Implemented | Capability fingerprint merge and first-run palette entry. |
| SHELL-15, DEL-6 | Implemented | Window sizes saved on quit. |

## Medium findings — dashboard, connections, interfaces

| IDs | Status | Result / remaining work |
|---|---|---|
| DCI-3, PAR-3 | Partial | Snapshot GeoIP handle and packet peer enrichment landed; Connections still advertises geo without displaying it. |
| DCI-2 | Open | Health height still competes with a connections minimum; check at 1180×720 after breakpoint correction. |
| DCI-7, DCI-8 | Recheck | Retransmission card versus verdicts; empty coverage must not mean nominal. |
| DCI-4, DCI-5, DCI-26 | Recheck | Explanatory text truncation in cards and metadata. |
| DCI-6 | Recheck | Measure with ~2,000 sockets before deciding cache changes. |

## Medium findings — packets and stats

| IDs | Status | Result / remaining work |
|---|---|---|
| PKS-4 | Implemented | Session-only bookmarks. |
| PKS-5 | Implemented | Honest BPF pending/error reporting; stopped capture remains stopped. |
| PKS-6 | Partial | Packet filter conversion improved; process drills still return no filter above eight hosts. |
| PKS-7, PAR-11 | Implemented | Bookmark jumps on `[` / `]`. |
| PKS-8 | Implemented | Session handshake-only RTT histogram/percentiles. |
| PKS-9, PKS-11, PKS-19, SHELL-21 | Implemented | Breadcrumb shortening, Esc clear and retained filter drafts. |
| PKS-13 | Implemented | Separate stream export key; no invisible focus-dependent export. |
| PKS-10, PAR-12 | Implemented | Peer DNS/geo/whois, JA4 names, QUIC/H3 detail. |
| PKS-12, PKS-14 | Implemented | Wheel disables follow; address columns yield space to info. |

## Medium findings — topology, timeline, processes

| IDs | Status | Remaining work |
|---|---|---|
| TTP-3 | Open | Desktop timeline must consume the configured window. |
| TTP-4 | Recheck | Replace unreachable process inspector digit actions with letters. |
| TTP-5, DCI-23 | Open | Show topology whois and share request state across drills/screens. |
| TTP-6 | Recheck | Already-running trace feedback. |
| TTP-7, TTP-8 | Recheck | Baseline-aware correlation and readable prose at minimum size. |
| TTP-9, SHELL-23 | Recheck | Explain unavailable process rates; choose a useful fallback sort. |
| TTP-10, TTP-11, TTP-12 | Recheck | Timeline event/filter parity, public trace targets, process metrics and sorting. |

## Medium findings — diagnose, egress, lite, dense

| IDs | Status | Remaining work |
|---|---|---|
| DEL-16, DEL-17, DEL-21, DEL-8 | Implemented | Working tree: demo guard, exact combined review, disk-based edits, permissions/source checks, new-rule drift warning. |
| DEL-12, PAR-5 | Implemented | Working tree: `x` reviews selected rule removal; `y` confirms. |
| DEL-4, DEL-3 | Open | Align strip/apply selection and implement in-app report preview on `o`; new workflow does not fix these. |
| PAR-2 | Open | AI collector status/errors and regenerate action. |
| DEL-14, DEL-10, DEL-22 | Partial | Dense zoom is 1.0; meter priorities, axis overlap and grouped-child rail still need checking. |
| DEL-7, DEL-15 | Recheck | Lite selection scrolling and DEMO marker. |
| DEL-18, DEL-19 | Partial | Egress diff now wraps/scrolls without eliding entries; Diagnose minimum-size layout still needs checking. |
| DEL-9 | Open | DENSE.md still calls lite unimplemented and describes obsolete view/pause keys. |

## Low findings retained

The review's low/polish findings remain backlog unless explicitly verified:

- DCI-9–25: column widths, sparkline hover, interface role/filter, attribution, visible counts, cadence/history, precision, discoverability, drill back-stack, tooltips and selection scrolling.
- PKS-15–20: capture permission versus stopped/error states, drops labeling, DNS baseline, stream breadcrumb and timestamps.
- TTP-13–25: trace copy/targeting, on-link labeling, counts, clipping, units, dock checklist, rates and event/target navigation.
- SHELL-16–24: recorder time, discard feedback, settings scrim, dense toast expiry, paper contrast, palette scrolling/grouping, saved selections, reduced motion and redundant root hints/keys.
- DEL-23–32: cooldown zero, current policy pills, empty-state clipping, missing units, catalogue/counts, dense casing, demo apply confirmation and navigation/apply availability.
- PAR-13–14: remote-publishing flags/environment and CLI parity. CLI validation/help/version/lite implemented in `48dee7b`; remote-publishing behavior still needs review.

## Original unconfirmed checks

- Live Tab then `2` shortcut behavior.
- Frame time with ~2,000 sockets.
- Strict sandbox failure and recovery on macOS.
- Preservation of hand-written policy comments during promotion: now covered by the desktop editor regression test (table, field and leading comments).
- Whether "changed — relearning" appears on every live start.

## Separate working-tree additions

The latest uncommitted work connects existing netwatch APIs to desktop test
buttons/results, manual-step recovery, incident labels and configured target
probe results. It also corrects the graph test's startup cache assertion.
This is additional feature work, not completion of DEL-3/DEL-4/PAR-2.

Validation of the earlier Diagnose checkpoint: debug/release builds and X11
screenshot inspection. The Wayland screenshot attempt did not complete.

After the egress block: 200 passing tests (24 egress tests), 2 ignored
performance tests, Clippy and formatting checks. File mutation tests use
isolated temporary directories; no real policy was written during validation.

No release, push or installation is implied by this tracker.
