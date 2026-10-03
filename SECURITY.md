# Security policy

netwatch desktop shows other programs' network traffic, and its binary usually carries the `cap_net_raw` capability so it can capture packets. It parses traffic from the network and text from other users' processes. Reports about any of that are welcome and come first.

## Reporting a vulnerability

Please don't open a public issue for a security problem.

- Preferred: [GitHub private vulnerability reporting](https://github.com/matthart1983/netwatch-desktop/security/advisories/new), "Report a vulnerability" under the Security tab.
- Or email matthew.t.hartley@gmail.com with `[netwatch-desktop security]` in the subject.

You'll get an acknowledgement within 72 hours and a triage verdict within 7 days. A confirmed vulnerability gets a patch release as soon as the fix is ready. Please allow time for that release before you disclose. We're happy to agree a date with you, and we'll credit you in the advisory and release notes, or leave your name out if you prefer.

Packet parsing, protocol decoding and the collectors live in [netwatch](https://github.com/matthart1983/netwatch). A bug there affects both apps; report it to netwatch, as its [security policy](https://github.com/matthart1983/netwatch/blob/main/SECURITY.md) says. If you aren't sure which project it belongs to, report it here and we'll move it.

## Supported versions

Fixes go into the latest release only. Please check the problem still happens there before reporting.

| Version | Supported |
|---|---|
| latest 0.2.x | yes |
| 0.1.0, 0.1.1 | no. They were built on netwatch 0.31, before its 0.32.4 fixes for terminal control characters in copied text and world-readable pcaps. Upgrade. |

## What we care about most

In rough order:

1. Privilege. Anything that lets another local user, or a file or setting they control, use the capture capability the binary carries.
2. Sensitive data in the wrong place. Exports, `desktop.toml` and the incident bundle are meant to be readable by your user alone (0600 files, 0700 directories). Anything the app writes where other users can read it, or traffic it sends that README's "What it sends over the network" doesn't list, is a bug.
3. Hostile input. A crash, hang or misleading display caused by crafted packets, DNS names, TLS fields, process command lines or config files. Text the app copies to the clipboard that carries terminal control or bidirectional characters counts too.
4. The egress policy writer. It refuses symbolic links and group- or world-writable files and re-checks the file before replacing it. A way past those checks is in scope.
5. The sandbox. On Linux, netwatch confines the runtime thread and its workers with Landlock. A way around that is in scope. The window's own thread and the incident history worker run unconfined by design, as README says.

Out of scope: a dependency bug with no path to exploit it through this app (please tell the dependency's maintainers, though a note to us is welcome), attacks that need root already, and settings you chose, such as turning on online GeoIP lookups.

## Running it safely

- Grant `cap_net_raw=ep` and nothing else. This build has no eBPF backend, so `cap_bpf` and `cap_perfmon` add nothing.
- Don't run the app with `sudo`. It doesn't need root.
- Treat exports, pcaps and incident bundles as private. They hold addresses, host names, process names and packet contents.
