# Diagnose: product workflow through P3

The rules engine, incident recorder, next-test loop and developer target probes
are available in the TUI and desktop. Model training and inference are not part
of this implementation.

## Developer targets

Add targets to netwatch's `config.toml` and restart the app:

```toml
diagnose_record_episodes = true

[[diagnose_targets]]
name = "staging api"
host = "api.staging.example.internal"
port = 443
path = "/healthz"
expect_status = 200
interval_secs = 60
```

`tls` defaults to true on port 443. For a plain TCP service, set `http = false`
and set `tls = false` if appropriate. Without `expect_status`, HTTP 4xx and 5xx
responses are errors; an explicit expected status takes precedence.

The desktop's **targets** control shows DNS, TCP, TLS and HTTP stages, timings,
and context. A missing or stale result says it is waiting for a fresh probe.
Probes use the host's network and direct connections. Process proxy environment,
GNOME proxy mode, VPN interfaces and container bridges are context; the probe
is not run inside another application's environment or a container. GNOME PAC
mode does not establish that a particular target needs a proxy.

TLS uses bundled public WebPKI trust roots, not an application's private trust
store. Local NTP clock error comes from synchronised `chronyc -n tracking` when
available; absent context stays unmeasured. An HTTP Date header does not provide
clock-skew evidence. See the [chrony tracking documentation](https://chrony-project.org/doc/4.8/chronyc.html#tracking).

## Diagnose an incident

1. Select an issue and inspect its evidence and possible causes.
2. In **Tests and recovery**, run the suggested test or another offered test.
   Each test shows its expected time, traffic cost and any disruption. Results
   are recorded with the incident and update its cause ranking.
3. Carry out a manual remediation, then click **I've done this** beside that
   step. Netwatch watches for recovery and repeats supporting tests. This
   records a manual action; it does not execute the instruction.
4. When the issue closes, the optional cause prompt records what actually
   happened. You can skip it or change the answer from the issue/history.

## History and sharing

**Incident history** lists the latest 100 saved incidents, including their
issue timelines, evidence, tests, actions, verification and labels. An active
incident appears after the recorder finishes it, including its post-roll.
Reopen history to refresh the list. Saved incidents can be labelled after the
original engine session has ended.

**Export incidents…** previews the last seven days of saved recordings. It
shows included episodes, replaced/removed field counts and skipped files before
**Save pseudonymised bundle** writes the file. No upload occurs. The existing
report export is a separate local report containing local detail.

Episode exports replace addresses and target identities with keyed tokens,
hash routing domains and remove free-text notes, diagnostic details, remediation
text, process names and artifact paths. Local recordings retain their original
detail. Bundles are written atomically with owner-only file permissions on Unix.
The per-install key stays on the device; exports are pseudonymised, not anonymous.

CLI equivalents:

```sh
netwatch diagnose episodes
netwatch diagnose replay /path/to/episode.json.gz
netwatch diagnose export --since 7d --dry-run
netwatch diagnose export --since 7d --out /path/to/bundle.json.gz
```

## Validation boundary

Automated coverage includes each P3 cause, local HTTP probes, HTTP 407 handling,
NTP parsing, live/replay parity, redacted target replay, private export files and
a simulated 24-hour storage/replay check. The simulation is not a live
24-hour workstation soak.

The privileged namespace fault lab (M1), actual workstation soak and pilot
release gates remain. Before ML evaluation, add independent monitored-time and
alert accounting, historical baseline inputs, and an explicit DNS/target family
mapping. Current QuietSample recordings alone do not establish false alerts per
device-week or supply a week of baseline history.
