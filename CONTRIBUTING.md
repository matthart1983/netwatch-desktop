# Contributing to netwatch desktop

Thanks for helping. This file covers building, the checks a pull request has to pass, and the conventions the code follows.

## Getting started

Install Rust 1.95 or newer with [rustup](https://rustup.rs) (Debian and Ubuntu package an older one) and the system libraries listed under [Building](README.md#building) in the README, then:

```sh
git clone https://github.com/matthart1983/netwatch-desktop
cd netwatch-desktop
cargo build --locked
cargo run -- --graph-preview
```

`--graph-preview` draws a synthetic snapshot with no collectors and no probes, so it needs no capture permission. To see live data, run without it and grant capture as described under [Permissions](README.md#permissions).

The netwatch library comes from crates.io, pinned to one exact version. To work against a local netwatch checkout, override it for one command and keep the override out of your commits:

```sh
cargo build --config 'patch.crates-io.netwatch-tui.path="../netwatch"'
git checkout Cargo.lock
```

## Before you open a pull request

Run what CI runs:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

`cargo test` includes the render matrix. It draws every tab, sheet and view at every text size from 100% to 300%, on 1366×768, 1440×900, 1920×1080 and each view's smallest window, headless and in a debug build so egui's layout assertions run. It fails on a panic, a sheet that leaves the window, first run's continue button off screen, or dense's socket box under three rows. If you change a layout, this is the test that tells you whether it still works for someone who needs large text.

If your change is visible in a README screenshot, redraw them:

```sh
cargo test write_screenshots -- --ignored
```

The screenshots come from the synthetic snapshot in `src/app/screenshots/fixture.rs`. A normal `cargo test` fails if any of them shows a real address or a name from your machine, or if a committed PNG doesn't match the frame the test draws now, so commit the redrawn PNGs with the change that altered them. Never commit a screenshot taken from a live session. That includes `--demo`, which adds a scenario on top of your real sockets, addresses and processes.

## Conventions

- Every behaviour change comes with a test that fails without it. Most screens have a `tests.rs` beside them with a harness that renders the screen headless and finds text or clicks on it.
- Text size scales the whole interface. Don't size anything in fixed pixels that has to fit text; measure, and let the content scroll when it doesn't fit.
- A value netwatch doesn't collect is shown as `–` with a reason, never made up. A measured zero and a missing reading look different.
- Screens never touch netwatch's `App`. They read the `Snapshot` and send a `Command`, and each command reports one result.
- Don't `unwrap()` on anything that came from the network, the user, a file or another process.
- Files the app writes for the user are owner-only. Use netwatch's `owner_only` helpers.
- When you add or change a key, update help, the footer hints, the palette entry and README together.

## Commits and pull requests

- Keep a pull request to one change. Small fixes found along the way can go in their own commits.
- Write commit subjects in the imperative, the way the history does ("Add …", "Fix …", "Keep …"), and say in the body why the change is needed: what was wrong, for whom, and how you know.
- Add a line under the unreleased version at the top of [CHANGELOG.md](CHANGELOG.md).
- For a visible change, put a screenshot in the pull request. Draw it with `--graph-preview` or the screenshot test, not from your own machine.

## Security

Please report vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes, not in an issue or pull request.

## License

By contributing you agree that your work is released under the [MIT licence](LICENSE).
