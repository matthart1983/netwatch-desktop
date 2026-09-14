# Netwatch Desktop

Native egui front end over the Netwatch runtime, collectors, diagnose engine and egress linter. It implements the Workbench shell from the desktop design spec: title bar · navigator · status strip · content + inspector · timeline dock · footer, with sheets over the top and lite and dense views.

Requires the sibling `../netwatch` checkout and the same platform capture/build dependencies as Netwatch.

```sh
cargo run                         # live runtime
cargo run -- --demo               # live runtime + the Diagnose demo scenario and a seeded capture
cargo run -- --tab packets        # start on a tab (any of the ten names)
cargo run -- --view lite|dense
cargo run -- --sheet settings     # settings · recorder · firstrun · palette · help
cargo run -- --theme paper        # dark paper terminal ocean solarized dracula nord sky
cargo run -- --app-chrome         # app-drawn window chrome (three dots, edge resize)
cargo run -- --check-runtime
cargo run -- --graph-preview      # synthetic snapshot, no collectors
cargo test
```

## Screens

`1` dashboard · `2` connections · `3` interfaces · `4` packets + decode · `5` stats · `6` topology · `7` timeline · `8` processes · `9` diagnose · `0` egress. Each tab's keys are in its footer; clicking a hint does the same as pressing it.

Global keys: `1–9 0` tabs · `:` or ctrl-K palette (`/` filter, `>` jump, `@` host or process) · `↵` drill / `esc` back (breadcrumb) · `p` or space pause the display · `R` arm, `F` freeze, `E` recorder & export sheet · `V` cycle full → lite → dense, `L` lite · `,` settings · `?` help · `t` graph scale on graph tabs, otherwise theme · `q` quit. Ctrl `+` / `−` zooms the interface (dense: text size).

Every chart draws in one look: btop dot cells or solid bars, with or without the magnitude fade. Toggle it from **☰ menu** in the title bar (also in dense), the palette (`graphs: switch to …`), or the settings sheet; it is saved as `graph_style` / `graph_fade` in the netwatch config.

Clicking a navigator node (gateway, dns, an interface, a process) filters the current tab and adds it to the breadcrumb. Tab, view, theme, zoom, dock height, per-tab control choices and the lite window persist in `~/.config/netwatch/desktop.toml` (`NETWATCH_DESKTOP_PREFS` overrides the path; `--screenshot` and `--graph-preview` runs neither read nor write it).

Pause pins the displayed snapshot; collectors, recording and exports continue. Writes (exports, policy promotions, config saves) report their path in the footer toast. Capture without permission degrades to interface counters and kernel TCP metrics, and the packets tab shows the grant command for the running executable. Active health checks send network probes.

See [design decisions and remaining scope](docs/DESIGN-NOTES.md), [graphs](docs/GRAPHS.md) and [dense view](docs/DENSE.md).

Fonts: IBM Plex Mono/Sans and Adwaita Mono (symbol fallback), bundled under `assets/fonts` with their OFL licences.
