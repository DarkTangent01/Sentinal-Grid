# Command execution security

## Risk levels (`app/access/commands.py classify`)

| Level | Examples | Diagnostics | Read-only terminal | Change terminal | Change request |
|---|---|---|---|---|---|
| `READ_ONLY` | show / get / display, `diagnose sys top`, `/system resource print` | yes | yes | yes | — |
| `LOW_RISK` | ping, traceroute, terminal length, enable, exit, `set cli screen-length` | yes | yes | yes | — |
| `MODERATE_RISK` | clear counters, debug, write memory, copy out, unrecognised commands, unsafe pipes | no | blocked | yes | yes |
| `HIGH_RISK` | configure / config / edit / set / no / commit / rollback, clear ip bgp, start shell | no | blocked | yes | yes (approval + rollback lines) |
| `DESTRUCTIVE` | reload, write erase, format, delete, execute factoryreset, request system zeroize, `/system reboot` | no | blocked | blocked | refused |

## Classification rules

- **Prefix tree, conservative.**
  - Abbreviations are accepted the way CLIs accept them.
  - An abbreviation that could expand to several verbs takes the highest risk among them (`s` → show / set / ssh →
    `DESTRUCTIVE` via `squeeze`).
  - In operational sessions the universal abbreviations `sh`, `conf`, `wr`, `int`, `diag`, `exec` resolve
    explicitly.
  - In change sessions (possibly in configuration mode, where `sh` means shutdown) they do not.
- **Pipes:** only output filters are allowed (`include`, `exclude`, `begin`, `section`, `count`, `match`, `no-more`,
  `display`, `grep` …). `| redirect`, `| save`, `| tee` → `MODERATE_RISK`.
- **Several commands on one line** (`;`, `&&`, `||`, backticks, `$(`): the highest risk of the parts.
- **`do` / `run`** prefixes (IOS / Junos configuration mode): the rest of the line is classified as an operational
  command.
- **Unknown commands:** `MODERATE_RISK`, so blocked in read-only sessions.
- **Tests:** 36 parametrised cases in `test_command_risk_classification`, plus template checks.

## Diagnostics

- The API takes template ids or categories only. There is no command parameter.
- Every template command is checked at import (and again before sending) to be `LOW_RISK` or lower. A template above
  that is a startup error.
- Templates run only on their own platform (`platform_of(device)` or the administrator's override).
- Output is masked, capped at 256 kB per command, and stored with the job.

## Terminal line guard

See [SSH_TERMINAL_GUIDE.md](SSH_TERMINAL_GUIDE.md). The guarantees, each tested in `test_line_guard` and
`test_terminal_session_end_to_end`:
- the Enter of a refused line never reaches the device;
- after a refusal, nothing more is forwarded except Ctrl-C until the device shows a fresh prompt, so the refused text
  cannot be submitted later;
- lines edited with history or cursor keys are refused in read-only sessions;
- secrets typed at a password prompt are not recorded.

The guard is defence in depth. It cannot see what a device does with completion or aliases it defines itself, so the
device's own AAA remains authoritative.

## Bulk execution

- **Permissions:** `nms.device.access.diagnostics` and `nms.automation.execute`.
- **Limits:**
  - at most `ACCESS_BULK_MAX_DEVICES` (500) devices per job;
  - three running bulk jobs per user;
  - concurrency 1–50 (default 10);
  - per-device timeout 10–900 s.
- **Isolation:** one device's failure (address refused, login rejected, timeout, unexpected error) is recorded on that
  device and the job continues.
- **Cancellation:** stops devices that have not started and cancels running ones.

## What is never possible

- An arbitrary command from an API parameter.
- A command to a host or port that is not a registered device's management service.
- A configuration change from an alert, a schedule or the AI assistant.
- A destructive command from any path.
