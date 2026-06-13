# DuckyScript Behaviour Sandbox

A **static behaviour-analysis sandbox** for DuckyScript and Bash Bunny
(`QUACK`/Q-prefixed) payloads. It parses a payload, statically *simulates*
the keystrokes/commands it would inject, and produces a human-readable
Markdown (or JSON) report describing the processes, files, registry keys,
network connections and ATT&CK techniques the payload would touch -- all
**without ever executing the payload**.

It's meant to let you triage and document a Rubber Ducky / Bash Bunny
payload's intent before it ever touches a target machine.

> **Intended use:** authorized security testing, red-team payload review,
> and defensive triage -- e.g. auditing a payload you wrote (or were handed)
> before loading it onto hardware you plan to use against systems you own,
> manage, or have written authorization to test. This project performs no
> network access, file I/O on the host, or code execution of any kind; it
> only reads the payload text you give it.

## How it works

```
payload text
     │
     ▼
 parser.py     -- tokenizes DuckyScript/QUACK syntax into Instructions,
     │             builds control-flow jump tables (IF/ELSE/WHILE/FUNCTION)
     ▼
 emulator.py   -- walks the instructions on a virtual clock, modelling
     │             keystrokes, held modifiers, REPEAT/loops, variables,
     │             and a process tree (explorer.exe -> cmd.exe -> ...)
     │             whenever a line of typed text is "submitted" (ENTER)
     ▼
 analyzer.py   -- matches the reconstructed command text against a library
     │             of MITRE ATT&CK-mapped regex rules, extracts IOCs
     │             (URLs, domains, IPs, files, registry keys), and decodes
     │             base64 `-EncodedCommand` payloads recursively
     ▼
 report.py     -- renders a Markdown or JSON report: risk score, ATT&CK
                   tactic summary, findings table, execution timeline,
                   process tree, network/file/registry activity, and
                   defanged IOCs
```

Because runtime conditions (`IF (...) THEN`) can't be evaluated statically,
**all branches of a conditional are modelled** (with a note explaining why)
-- the sandbox errs on the side of showing you everything a payload *could*
do.

### Safety limits

The emulator never executes anything, but pathological scripts (huge
`REPEAT` counts, `WHILE (1==1)` loops, infinitely recursive `FUNCTION`s)
could otherwise make analysis itself hang. Three caps guarantee the
simulation always terminates quickly, and a note is added to the report
whenever one is hit:

| Cap | Value | Behaviour when hit |
| --- | --- | --- |
| `Emulator.MAX_WHILE_ITERS` | 5 | Loop body is modelled 5 times, then `END_WHILE` is skipped |
| `Emulator.MAX_REPEAT` | 200 | `REPEAT n` replays the previous instruction at most 200 times |
| `Emulator.MAX_STEPS` | 200,000 | Whole-program instruction-pointer step counter; analysis is truncated |

## Installation

```bash
pip install -e .
```

This installs the `duckysandbox` package and a `duckysandbox` console
script. No third-party dependencies are required (stdlib only).

## Usage

```bash
# Markdown report to stdout, auto-detect target OS
duckysandbox payloads/recon_only.txt

# Force a target OS and write the report to a file
duckysandbox payloads/linux_reverse_shell.txt --os linux -o report.md

# JSON report (for feeding into other tooling)
duckysandbox payloads/powershell_dropper.txt --format json

# Read a payload from stdin
cat payload.txt | duckysandbox -

# CI-friendly: exit 1 if any finding is "high" severity or above
duckysandbox payloads/bashbunny_exfil.txt --fail-on high
```

Or run as a module without installing:

```bash
python -m duckysandbox payloads/recon_only.txt
```

### Python API

```python
from duckysandbox import emulate, render_markdown, render_json

result = emulate(open("payload.txt").read(), target_os="windows")
print(render_markdown(result, payload_name="payload.txt"))
```

## Report contents

Each report includes:

- **Risk score & rating** -- 0-100 score (sum of per-finding severity
  weights, capped) mapped to Informational/Low/Medium/High/Critical.
- **Summary** -- a one-line narrative of the payload's notable behaviours,
  ordered along the cyber kill chain.
- **ATT&CK Tactic Summary** -- findings grouped by MITRE ATT&CK tactic.
- **Findings** -- table of rule matches (line, severity, tactic, technique,
  evidence) plus a description of each triggered rule.
- **Execution Timeline** -- every modelled keystroke, process launch, file
  operation, registry change, and network connection, in simulated-time
  order.
- **Modelled Process Tree** -- the parent/child process lineage the payload
  would create (e.g. `explorer.exe -> cmd.exe -> powershell.exe`).
- **Network / File / Registry Activity** -- tables of every connection,
  file read/write/delete, and registry key touched.
- **Indicators of Compromise** -- URLs, domains, IPs, files and registry
  keys, each shown alongside a defanged form (`hxxp://`, `[.]`) safe to
  paste into chat or tickets.
- **Sandbox Notes / Parser Warnings** -- e.g. "WHILE loop capped at 5
  iterations", "decoded base64 -EncodedCommand", "payload ends with typed
  text that was never submitted".

## Sample payloads

The `payloads/` directory contains example payloads exercising different
parts of the analyzer:

| Payload | What it demonstrates |
| --- | --- |
| `recon_only.txt` | Basic Windows recon (`whoami`, `systeminfo`, `ipconfig`, `net user`) redirected to a file -- low risk |
| `powershell_dropper.txt` | `GUI r` -> obfuscated/encoded PowerShell download-and-execute, plus `Run` key persistence -- critical risk |
| `bashbunny_exfil.txt` | `ATTACKMODE HID STORAGE`, Wi-Fi profile/key dumping, exfil via a Discord webhook -- critical risk |
| `linux_reverse_shell.txt` | `IF`/`ELSE` and `WHILE` modelling, `/dev/tcp` reverse shell on Linux -- medium risk |
| `feature_showcase.txt` | Variables (`VAR`), `FUNCTION`/call, `REPEAT`, `HOLD`/`RELEASE` modifier handling -- high risk |

Try them with, e.g.:

```bash
duckysandbox payloads/powershell_dropper.txt
```

## Running the tests

```bash
python -m unittest discover tests
```

The test suite (stdlib `unittest`, no extra dependencies) covers the
parser's control-flow structures, the analyzer's detection rules and IOC
extraction, the emulator's loop/repeat/step caps and process-tree modelling,
and the Markdown/JSON report rendering.

## Extending the rule library

Detection rules live in `duckysandbox/analyzer.py` as `Rule` entries in the
`RULES` list:

```python
Rule("EXEC-PS", "PowerShell execution", EXECUTION, "T1059.001 PowerShell",
     LOW, r"\b(?:powershell(?:\.exe)?|pwsh)\b",
     "Launches PowerShell, a common LOLBin for further execution."),
```

Each rule maps a regex to a MITRE ATT&CK tactic/technique, a severity, and a
human-readable explanation that ends up in the report's "Rule Details"
section. Side-effect extraction (processes, files, registry, network/IOCs)
is handled separately in the `_record_*` helpers in the same module.
