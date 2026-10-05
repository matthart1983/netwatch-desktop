# Changelog

All notable changes to netwatch desktop are listed here, newest first.

## [0.2.0] - 2026-10-05

The first public release. A fresh clone now builds from crates.io, text size has controls anyone can find, and nothing panics or drops out of reach at any size from 100% to 300%. Capture asks for one capability, exports are private to your user, and settings saves stop deleting what the terminal app wrote. Linux gets a .deb, an .rpm and a tarball. macOS and Windows build from source and are experimental.

### Added
- Linux x86_64 releases as a .deb, an .rpm and a tarball, with a `SHA256SUMS` file and a build provenance attestation for each file. They run on glibc 2.35 or newer: Ubuntu 22.04, Debian 12, Fedora 36 and later. 0.1.x needed glibc 2.43. libpcap is built into the binary, so the same build runs on Debian, Ubuntu and Fedora.
- The .deb and .rpm grant `cap_net_raw=ep` as they install, so capture works without a manual `setcap`. Every upgrade or reinstall grants it again.
- A window icon and app id, and a `.desktop` entry with icons from 16 to 512 pixels, so menus, docks and Wayland shells show the app's name and icon.
- Text size controls. The `☰` menu has `−`, `+`, `reset` and a list of sizes. The palette has an entry for each, which also answers to "zoom", "font" and "bigger". Settings has a "this app" group, lite has its own `☰ menu`, and the first-run sheet starts with Normal, Large and Larger. Every change applies at once in all views, shows a toast and is saved.
- `ctrl` or `⌘` with `+`, `=`, `−` and `0` handled by the app itself; `0` returns to the 115% default. `ctrl` with the scroll wheel and trackpad pinch move one size at a time.
- `--text-size PERCENT` sets the text size for one launch without saving it.
- `--dense-box N` opens dense with box N zoomed. `--zoom` still works, with a warning.
- Blocked egress destinations. netwatch 0.35 policies can block destinations globally or per process and choose an alert mode. A blocked destination reads `blocked` in red, comes first in the status strip, badge and title chip, shows in connections and processes, and offers no allow action. Promotion leaves blocked destinations out, and removing a rule names the block entries that go with it.
- A narrow navigator that keeps the tab names, and a digit rail that scrolls, with a scroll bar that stays drawn wherever tabs or table columns are hidden.
- Screen readers get each navigator item's name and whether it's the current tab.
- CI on Linux, macOS and Windows, with `cargo audit`, a build on the oldest supported Rust and a build against netwatch's main branch.
- The render matrix: every tab, sheet and view at every text size on three common screens and each view's smallest window, rendered headless in CI.
- A README screenshot of the text size controls at 150%.
- SECURITY.md, CONTRIBUTING.md, this changelog, issue templates, and crates.io metadata.

### Changed
- Builds against `netwatch-tui` 0.35.1 from crates.io, pinned exactly. A sibling netwatch checkout is no longer needed.
- Building needs Rust 1.95 or newer, because netwatch-tui 0.35.1 uses standard library calls that arrived in 1.95.
- Text size has one range, 100% to 300%, and one default, 115%, at startup and at runtime. It used to be 75% to 250% at startup, 20% to 500% at runtime, and `ctrl 0` went to 100%.
- Capture asks for `cap_net_raw=ep` only, on first run and in the packets tab. The packets tab used to suggest `cap_bpf` and `cap_perfmon` as well, which this build can't use.
- Exports are created 0600 in a 0700 directory and `desktop.toml` is 0600. With no home directory, exports refuse instead of writing to `/tmp`.
- `desktop.toml` is saved atomically and read field by field, so one bad value no longer resets the whole layout. A file that isn't valid TOML is kept as `desktop.toml.bak`, and a toast says so. A failed save shows a toast.
- Saving settings edits `config.toml` in place and writes only the keys you changed. Comments, sections from a newer terminal netwatch, and changes it made meanwhile stay.
- The dashboard scrolls instead of shrinking panels to their headers, and the timeline dock hides itself in short windows.
- First run, lite and the sheets stack into one scrolling column in small windows, and first run's continue button stays on screen.
- Control strips wrap whole groups onto the next line; narrow tables scroll sideways; crowded axis labels and notes thin out or shorten instead of overlapping.
- README is rewritten for a first-time user: install, text size, permissions, the traffic the app sends, and known limitations.
- README screenshots are drawn headless from synthetic data. Tests fail if any shows a real address or this machine's names, or if a committed screenshot isn't the frame drawn from that data.

### Fixed
- A probe netwatch couldn't send, such as a gateway that blocks ping and has no open TCP port, showed as a red dead link. It now shows as unmeasured, with the reason on hover and on the dashboard card.
- `zoom = nan` in `desktop.toml` crashed every launch. It now starts at 115%.
- Dense's socket box went to a negative height at 200% on a 1366×768 screen, which panicked debug builds and hid the sockets in release builds. It now keeps three rows and the page scrolls.
- Switching between full and lite grew the window by the text size on every round trip, and lite's and dense's minimum sizes outgrew a laptop screen at 200%.
- One step up from 115% turned the navigator into bare digits on common screens. Tab names now stay up to 200% on a 1366-pixel screen and up to 300% on a 1920-pixel one.
- Dense's title buttons ran over the brand and off the window at large text sizes.
- The inspector sheet stayed open, and panicked debug builds, once its column fitted again.
- Settings hints, privacy warnings among them, were dropped in narrow windows. They now wrap under the row.
- Retrying a settings save after a failed one reported "saved" and wrote nothing.
- Lite's footer showed `space pause`, though only `p` pauses.
- Ctrl-scroll over the packet list stopped it following new packets.
- A ctrl-scroll notch back down right after scrolling up could move nothing.
- Lite lost its severity word and colour for as long as a toast showed.
- The egress promotion preview implied a process's block list would be deleted.
- Dense printed a socket's decoded protocol in Rust's debug format. It now reads like "tls · example.com".
- A navigator name could run into its value with no space between, as in `dns.slow_resolverfiring`. A long name now shortens first and keeps a gap.
- `--graph-preview` showed real data from this machine. The processes inspector read the command line, user and cgroup of whichever real process had one of the preview's made-up PIDs, and the recorder and grant command showed the real export directory and binary path. A preview now reads none of them.

### Security
- Updates rustls to 0.23.45 for RUSTSEC-2026-0285.
- Picks up netwatch's 0.32.4 security fixes, which 0.1.x lacked. Decrypted payloads in copied packet text lose their terminal control characters, and pcaps are written owner-only.

### Known gaps
- macOS and Windows have no binaries and haven't been tried by hand.
- Started from Explorer, a Windows build opens a console window beside the app. Without it, the programs netwatch's collectors run on every refresh would each flash a console window.
- Screen readers can read little beyond the navigator.
- A capture grant needs a restart, and the app doesn't say so.
- The app doesn't warn when run as root.

## [0.1.1] - 2026-09-15

Private build, superseded by 0.2.0. Don't use it with netwatch 0.35. It was built on netwatch 0.31.2, so it lacks the 0.32.4 security fixes, it needs glibc 2.43, and saving settings deletes the terminal app's `[diagnose_probes]` and `[diagnose_thresholds]`.

### Changed
- Dense shares the full view's type sizes and text zoom.

## [0.1.0] - 2026-09-15

Private build, superseded by 0.2.0, with the same problems as 0.1.1.

### Added
- All ten tabs, the settings, first-run, flight recorder, help and palette sheets, and the lite and dense views, over netwatch's runtime.
- Reviewed egress policy writes that show the full file diff before writing.
- Diagnose incident history, tests, manual-step verification and target probes.
