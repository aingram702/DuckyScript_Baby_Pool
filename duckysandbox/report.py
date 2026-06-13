"""Human-readable (Markdown) and machine-readable (JSON) report rendering."""

from __future__ import annotations

import json

from . import analyzer
from .analyzer import Finding
from .emulator import EmulationResult


TACTIC_ORDER = [
    analyzer.EXECUTION,
    analyzer.PERSISTENCE,
    analyzer.PRIVESC,
    analyzer.EVASION,
    analyzer.CRED_ACCESS,
    analyzer.DISCOVERY,
    analyzer.LATERAL,
    analyzer.COLLECTION,
    analyzer.C2,
    analyzer.EXFIL,
    analyzer.IMPACT,
]


def compute_risk_score(findings: list[Finding]) -> int:
    """A simple 0-100 risk score: sum of per-finding severity weights, capped."""
    return min(100, sum(analyzer.SEVERITY_WEIGHT.get(f.severity, 0) for f in findings))


def risk_rating(score: int) -> str:
    if score <= 0:
        return "Informational"
    if score < 20:
        return "Low"
    if score < 50:
        return "Medium"
    if score < 80:
        return "High"
    return "Critical"


# -- helpers -----------------------------------------------------------------

def _esc(value) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def _table(headers: list[str], rows: list[list]) -> str:
    if not rows:
        return ""
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        out.append("| " + " | ".join(_esc(c) for c in row) + " |")
    return "\n".join(out)


def _defang(s: str) -> str:
    return s.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def _narrative(findings: list[Finding]) -> str:
    if not findings:
        return ("No notable techniques were detected. This does not guarantee the "
                "payload is benign -- review the execution timeline below for the "
                "exact keystrokes and commands it injects.")
    seen_titles: list[str] = []
    for tactic in TACTIC_ORDER:
        for f in findings:
            if f.tactic == tactic and f.title not in seen_titles:
                seen_titles.append(f.title)
    for f in findings:
        if f.title not in seen_titles:
            seen_titles.append(f.title)
    if len(seen_titles) == 1:
        return f"This payload's notable behaviour: {seen_titles[0]}."
    return "This payload exhibits the following notable behaviours: " + "; ".join(seen_titles) + "."


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-analyzer.SEVERITY_RANK.get(f.severity, 0), f.lineno))


def _process_tree(processes) -> list[str]:
    """Render the modelled parent/child process lineage as nested bullets."""
    lines: list[str] = []
    all_names = {p.name for p in processes}
    by_parent: dict[str, list[int]] = {}
    for idx, p in enumerate(processes):
        by_parent.setdefault(p.parent, []).append(idx)

    visited: set[int] = set()

    def walk(idx: int, depth: int) -> None:
        if idx in visited:
            return
        visited.add(idx)
        p = processes[idx]
        cmd = f" -- `{_esc(p.cmdline)[:90]}`" if p.cmdline else ""
        elevated = " *(elevated)*" if p.integrity == "high" else ""
        lines.append(f"{'  ' * depth}- **{p.name}**{elevated} (t={p.timestamp}, line {p.lineno}){cmd}")
        for cidx in by_parent.get(p.name, []):
            if cidx != idx:
                walk(cidx, depth + 1)

    roots = [i for i, p in enumerate(processes) if p.parent not in all_names]
    for r in roots:
        walk(r, 0)
    for i in range(len(processes)):
        if i not in visited:
            walk(i, 0)
    return lines


# -- markdown report -----------------------------------------------------------

def render_markdown(result: EmulationResult, payload_name: str = "payload") -> str:
    vm = result.vmstate
    findings = _sorted_findings(result.findings)
    score = compute_risk_score(result.findings)
    rating = risk_rating(score)

    lines: list[str] = []
    lines.append(f"# DuckyScript Behaviour Sandbox Report")
    lines.append("")
    lines.append(f"**Payload:** `{payload_name}`  ")
    lines.append(f"**Detected target OS:** {result.target_os}  ")
    lines.append(f"**Simulated duration:** {_fmt_ms(vm.clock_ms)}  ")
    lines.append(f"**Lines analysed:** {len(result.program)}  ")
    lines.append(f"**Findings:** {len(result.findings)}  ")
    lines.append(f"**Overall risk:** **{rating}** (score {score}/100)")
    lines.append("")
    lines.append("> This is a *static behavioural simulation*. The payload's keystroke "
                  "stream was reconstructed and matched against known attack techniques; "
                  "nothing in this report was executed on a real system.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(_narrative(result.findings))
    lines.append("")

    # -- Tactic summary ---------------------------------------------------
    tactic_counts: dict[str, list[Finding]] = {}
    for f in result.findings:
        tactic_counts.setdefault(f.tactic, []).append(f)
    if tactic_counts:
        lines.append("## ATT&CK Tactic Summary")
        lines.append("")
        rows = []
        for tactic in TACTIC_ORDER:
            fs = tactic_counts.get(tactic)
            if not fs:
                continue
            worst = max(fs, key=lambda f: analyzer.SEVERITY_RANK.get(f.severity, 0))
            rows.append([tactic, len(fs), worst.severity.upper()])
        for tactic, fs in tactic_counts.items():
            if tactic not in TACTIC_ORDER:
                worst = max(fs, key=lambda f: analyzer.SEVERITY_RANK.get(f.severity, 0))
                rows.append([tactic, len(fs), worst.severity.upper()])
        lines.append(_table(["Tactic", "Findings", "Highest Severity"], rows))
        lines.append("")

    # -- Findings table -----------------------------------------------------
    if findings:
        lines.append("## Findings")
        lines.append("")
        rows = [[f.lineno, f.severity.upper(), f.tactic, f.title, f.technique, f"`{f.evidence}`"]
                for f in findings]
        lines.append(_table(["Line", "Severity", "Tactic", "Title", "Technique", "Evidence"], rows))
        lines.append("")
        lines.append("### Rule Details")
        lines.append("")
        seen_rules: dict[str, Finding] = {}
        for f in findings:
            seen_rules.setdefault(f.rule_id, f)
        for rid, f in seen_rules.items():
            lines.append(f"- **{rid} -- {f.title}** ({f.technique}): {f.explanation}")
        lines.append("")
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("No rule-based findings were triggered.")
        lines.append("")

    # -- Execution timeline ---------------------------------------------------
    events = vm.all_events()
    if events:
        lines.append("## Execution Timeline")
        lines.append("")
        rows = []
        for e in events:
            rows.append([e.timestamp, e.lineno, e.kind, _describe_event(e)])
        lines.append(_table(["Time", "Line", "Type", "Detail"], rows))
        lines.append("")

    # -- Process tree -----------------------------------------------------------
    if vm.processes:
        lines.append("## Modelled Process Tree")
        lines.append("")
        lines.extend(_process_tree(vm.processes))
        lines.append("")

    # -- Network ------------------------------------------------------------------
    if vm.network:
        lines.append("## Network Activity")
        lines.append("")
        rows = [[n.timestamp, n.lineno, n.protocol, f"{n.host}:{n.port}" if n.port else n.host,
                 n.direction, n.detail] for n in vm.network]
        lines.append(_table(["Time", "Line", "Protocol", "Destination", "Direction", "Detail"], rows))
        lines.append("")

    # -- Files --------------------------------------------------------------------
    if vm.files:
        lines.append("## File System Activity")
        lines.append("")
        rows = [[fi.timestamp, fi.lineno, fi.operation, f"`{fi.path}`", fi.detail] for fi in vm.files]
        lines.append(_table(["Time", "Line", "Operation", "Path", "Detail"], rows))
        lines.append("")

    # -- Registry -----------------------------------------------------------------
    if vm.registry:
        lines.append("## Registry Activity")
        lines.append("")
        rows = [[r.timestamp, r.lineno, r.operation, f"`{r.key}`", r.value, r.data] for r in vm.registry]
        lines.append(_table(["Time", "Line", "Operation", "Key", "Value", "Data"], rows))
        lines.append("")

    # -- IOCs -----------------------------------------------------------------------
    iocs = vm.iocs
    if any(iocs.values()):
        lines.append("## Indicators of Compromise")
        lines.append("")
        if iocs["urls"]:
            lines.append("**URLs:**")
            for u in sorted(iocs["urls"]):
                lines.append(f"- `{u}` (defanged: `{_defang(u)}`)")
            lines.append("")
        if iocs["domains"]:
            lines.append("**Domains:**")
            for d in sorted(iocs["domains"]):
                lines.append(f"- `{d}` (defanged: `{_defang(d)}`)")
            lines.append("")
        if iocs["ips"]:
            lines.append("**IP Addresses:**")
            for ip in sorted(iocs["ips"]):
                lines.append(f"- `{ip}`")
            lines.append("")
        if iocs["files"]:
            lines.append("**Files touched:**")
            for f in sorted(iocs["files"]):
                lines.append(f"- `{f}`")
            lines.append("")
        if iocs["registry"]:
            lines.append("**Registry keys touched:**")
            for r in sorted(iocs["registry"]):
                lines.append(f"- `{r}`")
            lines.append("")

    # -- Notes / warnings -----------------------------------------------------------
    if vm.notes:
        lines.append("## Sandbox Notes")
        lines.append("")
        for n in vm.notes:
            lines.append(f"- {n}")
        lines.append("")

    if result.warnings:
        lines.append("## Parser Warnings")
        lines.append("")
        for w in result.warnings:
            lines.append(f"- {w}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _fmt_ms(ms: int) -> str:
    seconds, millis = divmod(int(ms), 1000)
    minutes, seconds = divmod(seconds, 60)
    return f"{minutes:02d}:{seconds:02d}.{millis:03d}"


def _describe_event(e) -> str:
    kind = e.kind
    if kind == "keystroke":
        return e.description
    if kind == "process":
        return f"New process `{e.name}` (parent `{e.parent}`)" + (f": `{e.cmdline}`" if e.cmdline else "")
    if kind == "file":
        return f"{e.operation} `{e.path}`" + (f" ({e.detail})" if e.detail else "")
    if kind == "registry":
        target = e.key + (f"\\{e.value}" if e.value else "")
        return f"{e.operation} `{target}`" + (f" = `{e.data}`" if e.data else "")
    if kind == "network":
        dest = f"{e.host}:{e.port}" if e.port else e.host
        return f"{e.protocol.upper()} {e.direction} to `{dest}`" + (f" ({e.detail})" if e.detail else "")
    return str(e)


# -- JSON report ------------------------------------------------------------------

def to_dict(result: EmulationResult, payload_name: str = "payload") -> dict:
    vms = result.vmstate.to_dict()
    findings_sorted = _sorted_findings(result.findings)
    score = compute_risk_score(result.findings)
    return {
        "payload": payload_name,
        "target_os": result.target_os,
        "duration_ms": vms["duration_ms"],
        "risk_score": score,
        "risk_rating": risk_rating(score),
        "summary": _narrative(result.findings),
        "findings": [f.to_dict() for f in findings_sorted],
        "warnings": result.warnings,
        "notes": vms["notes"],
        "iocs": vms["iocs"],
        "keystrokes": vms["keystrokes"],
        "processes": vms["processes"],
        "files": vms["files"],
        "registry": vms["registry"],
        "network": vms["network"],
    }


def render_json(result: EmulationResult, payload_name: str = "payload") -> str:
    return json.dumps(to_dict(result, payload_name), indent=2)
