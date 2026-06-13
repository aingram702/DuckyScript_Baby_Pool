"""HTML rendering for the DuckyScript Behaviour Sandbox.

Used by the CLI's ``--format html`` option and by the web UI in
:mod:`duckysandbox.webapp`. The output is a single self-contained HTML
document with inline CSS -- no external assets or JavaScript are required to
view a report.
"""

from __future__ import annotations

import html as _html
import urllib.parse

from . import analyzer, report
from .analyzer import Finding
from .emulator import EmulationResult


# -- icon / badge maps --------------------------------------------------------

SEVERITY_BADGE = {
    analyzer.INFO: ("ℹ️", "info"),       # info
    analyzer.LOW: ("🟢", "low"),
    analyzer.MEDIUM: ("🟡", "medium"),
    analyzer.HIGH: ("🟠", "high"),
    analyzer.CRITICAL: ("🔴", "critical"),
}

RATING_BADGE = {
    "Informational": ("🦆💻", "informational"),
    "Low": ("🦆🔍", "low"),
    "Medium": ("🦆⚡", "medium"),
    "High": ("🦆🔥", "high"),
    "Critical": ("🦆⚔️", "critical"),
}

RATING_TAGLINE = {
    "Informational": "Just a duck quietly using a computer.",
    "Low": "The duck is poking around, but keeping it civil.",
    "Medium": "The duck means business -- worth a closer look.",
    "High": "The duck came armed. Treat this payload as dangerous.",
    "Critical": "DUCK IS AT WAR. This payload is built to do serious damage.",
}

TACTIC_ICON = {
    analyzer.EXECUTION: "▶️",
    analyzer.PERSISTENCE: "📌",
    analyzer.PRIVESC: "⬆️",
    analyzer.EVASION: "🥷",
    analyzer.CRED_ACCESS: "🔑",
    analyzer.DISCOVERY: "🔍",
    analyzer.LATERAL: "🔗",
    analyzer.COLLECTION: "📥",
    analyzer.C2: "📡",
    analyzer.EXFIL: "📤",
    analyzer.IMPACT: "💥",
}

EVENT_ICON = {
    "keystroke": "⌨️",
    "process": "\U0001f5a5️",
    "file": "📁",
    "registry": "\U0001f5c4️",
    "network": "🌐",
}

_FAVICON_SVG = (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>"
    "<text y='.9em' font-size='90'>\U0001f986</text></svg>"
)
FAVICON_DATA_URI = "data:image/svg+xml," + urllib.parse.quote(_FAVICON_SVG)


# -- small helpers --------------------------------------------------------------

def _h(value) -> str:
    return _html.escape(str(value), quote=True)


def _badge(icon: str, label: str, css_class: str) -> str:
    return f'<span class="badge badge-{css_class}">{icon} {_h(label)}</span>'


def _table_html(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return ""
    head = "".join(f"<th>{_h(h)}</th>" for h in headers)
    body_rows = "\n".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    return (f'<div class="table-wrap"><table class="report-table">\n'
            f"<thead><tr>{head}</tr></thead>\n<tbody>\n{body_rows}\n</tbody>\n"
            f"</table></div>")


def _describe_event_html(e) -> str:
    kind = e.kind
    if kind == "keystroke":
        return _h(e.description)
    if kind == "process":
        cmd = f": <code>{_h(e.cmdline)}</code>" if e.cmdline else ""
        return f"New process <code>{_h(e.name)}</code> (parent <code>{_h(e.parent)}</code>){cmd}"
    if kind == "file":
        detail = f" ({_h(e.detail)})" if e.detail else ""
        return f"{_h(e.operation)} <code>{_h(e.path)}</code>{detail}"
    if kind == "registry":
        target = e.key + (f"\\{e.value}" if e.value else "")
        data = f" = <code>{_h(e.data)}</code>" if e.data else ""
        return f"{_h(e.operation)} <code>{_h(target)}</code>{data}"
    if kind == "network":
        dest = f"{e.host}:{e.port}" if e.port else e.host
        detail = f" ({_h(e.detail)})" if e.detail else ""
        return f"{_h(e.protocol.upper())} {_h(e.direction)} to <code>{_h(dest)}</code>{detail}"
    return _h(str(e))


def _process_tree_html(processes) -> str:
    all_names = {p.name for p in processes}
    by_parent: dict[str, list[int]] = {}
    for idx, p in enumerate(processes):
        by_parent.setdefault(p.parent, []).append(idx)

    visited: set[int] = set()

    def render(idx: int) -> str:
        visited.add(idx)
        p = processes[idx]
        cmd = f" -- <code>{_h(p.cmdline)[:120]}</code>" if p.cmdline else ""
        elevated = ' <span class="tag-elevated">elevated</span>' if p.integrity == "high" else ""
        children = [render(c) for c in by_parent.get(p.name, []) if c != idx and c not in visited]
        child_html = f"<ul>{''.join(children)}</ul>" if children else ""
        return (f'<li><span class="proc-icon">\U0001f5a5️</span> <strong>{_h(p.name)}</strong>'
                f'{elevated}<span class="proc-meta">t={p.timestamp}, line {p.lineno}</span>{cmd}'
                f"{child_html}</li>")

    roots = [i for i, p in enumerate(processes) if p.parent not in all_names]
    items = [render(r) for r in roots if r not in visited]
    items += [render(i) for i in range(len(processes)) if i not in visited]
    return f'<ul class="process-tree">{"".join(items)}</ul>'


# -- main report fragment -------------------------------------------------------

def render_html_fragment(result: EmulationResult, payload_name: str = "payload") -> str:
    """Render the report body as a self-contained HTML fragment (no <html>/<head>)."""
    vm = result.vmstate
    findings = report._sorted_findings(result.findings)
    score = report.compute_risk_score(result.findings)
    rating = report.risk_rating(score)
    icon, css_class = RATING_BADGE.get(rating, ("🦆", "informational"))
    tagline = RATING_TAGLINE.get(rating, "")

    parts: list[str] = []

    parts.append('<div class="report-meta">')
    for label, value in (
        ("Payload", payload_name),
        ("Target OS", result.target_os),
        ("Duration", report._fmt_ms(vm.clock_ms)),
        ("Lines analysed", len(result.program)),
        ("Findings", len(result.findings)),
    ):
        parts.append(
            f'<div class="meta-item"><span class="meta-label">{_h(label)}</span>'
            f'<span class="meta-value">{_h(value)}</span></div>'
        )
    parts.append("</div>")

    parts.append(
        f'<div class="risk-banner risk-{css_class}">'
        f'<div class="risk-icon">{icon}</div>'
        f'<div class="risk-body"><div class="risk-rating">{_h(rating)} '
        f'<span class="risk-score">(score {score}/100)</span></div>'
        f'<div class="risk-tagline">{_h(tagline)}</div></div></div>'
    )

    parts.append(
        '<blockquote class="disclaimer">This is a <strong>static behavioural '
        "simulation</strong>. The payload's keystroke stream was reconstructed "
        "and matched against known attack techniques; nothing in this report "
        "was executed on a real system.</blockquote>"
    )

    # -- Summary -----------------------------------------------------------
    parts.append('<section class="card"><h2>📋 Summary</h2>')
    parts.append(f"<p>{_h(report._narrative(result.findings))}</p></section>")

    # -- ATT&CK Tactic Summary ----------------------------------------------
    tactic_counts: dict[str, list[Finding]] = {}
    for f in result.findings:
        tactic_counts.setdefault(f.tactic, []).append(f)
    if tactic_counts:
        rows = []
        for tactic in report.TACTIC_ORDER:
            fs = tactic_counts.get(tactic)
            if not fs:
                continue
            worst = max(fs, key=lambda f: analyzer.SEVERITY_RANK.get(f.severity, 0))
            sev_icon, sev_css = SEVERITY_BADGE.get(worst.severity, ("⚪", "info"))
            rows.append([f"{TACTIC_ICON.get(tactic, '')} {_h(tactic)}", str(len(fs)),
                          _badge(sev_icon, worst.severity.upper(), sev_css)])
        for tactic, fs in tactic_counts.items():
            if tactic not in report.TACTIC_ORDER:
                worst = max(fs, key=lambda f: analyzer.SEVERITY_RANK.get(f.severity, 0))
                sev_icon, sev_css = SEVERITY_BADGE.get(worst.severity, ("⚪", "info"))
                rows.append([_h(tactic), str(len(fs)), _badge(sev_icon, worst.severity.upper(), sev_css)])
        parts.append('<section class="card"><h2>🗺️ ATT&amp;CK Tactic Summary</h2>')
        parts.append(_table_html(["Tactic", "Findings", "Highest Severity"], rows))
        parts.append("</section>")

    # -- Findings ------------------------------------------------------------
    if findings:
        rows = []
        for f in findings:
            sev_icon, sev_css = SEVERITY_BADGE.get(f.severity, ("⚪", "info"))
            rows.append([
                str(f.lineno),
                _badge(sev_icon, f.severity.upper(), sev_css),
                f"{TACTIC_ICON.get(f.tactic, '')} {_h(f.tactic)}",
                _h(f.title),
                _h(f.technique),
                f"<code>{_h(f.evidence)}</code>",
            ])
        parts.append('<section class="card"><h2>🔎 Findings</h2>')
        parts.append(_table_html(["Line", "Severity", "Tactic", "Title", "Technique", "Evidence"], rows))
        parts.append('<h3>Rule Details</h3><ul class="rule-details">')
        seen_rules: dict[str, Finding] = {}
        for f in findings:
            seen_rules.setdefault(f.rule_id, f)
        for rid, f in seen_rules.items():
            parts.append(
                f"<li><strong>{_h(rid)} — {_h(f.title)}</strong> "
                f'<span class="technique">({_h(f.technique)})</span>: {_h(f.explanation)}</li>'
            )
        parts.append("</ul></section>")
    else:
        parts.append('<section class="card"><h2>🔎 Findings</h2>'
                      "<p>No rule-based findings were triggered.</p></section>")

    # -- Execution Timeline ----------------------------------------------------
    events = vm.all_events()
    if events:
        rows = [[str(e.timestamp), str(e.lineno), f"{EVENT_ICON.get(e.kind, '')} {_h(e.kind)}",
                 _describe_event_html(e)] for e in events]
        parts.append('<section class="card"><h2>⏱️ Execution Timeline</h2>')
        parts.append(_table_html(["Time", "Line", "Type", "Detail"], rows))
        parts.append("</section>")

    # -- Process Tree -----------------------------------------------------------
    if vm.processes:
        parts.append('<section class="card"><h2>🌳 Modelled Process Tree</h2>')
        parts.append(_process_tree_html(vm.processes))
        parts.append("</section>")

    # -- Network -------------------------------------------------------------------
    if vm.network:
        rows = [[str(n.timestamp), str(n.lineno), _h(n.protocol),
                 f"<code>{_h(f'{n.host}:{n.port}' if n.port else n.host)}</code>",
                 _h(n.direction), _h(n.detail)] for n in vm.network]
        parts.append('<section class="card"><h2>🌐 Network Activity</h2>')
        parts.append(_table_html(["Time", "Line", "Protocol", "Destination", "Direction", "Detail"], rows))
        parts.append("</section>")

    # -- Files ----------------------------------------------------------------------
    if vm.files:
        rows = [[str(fi.timestamp), str(fi.lineno), _h(fi.operation),
                 f"<code>{_h(fi.path)}</code>", _h(fi.detail)] for fi in vm.files]
        parts.append('<section class="card"><h2>📁 File System Activity</h2>')
        parts.append(_table_html(["Time", "Line", "Operation", "Path", "Detail"], rows))
        parts.append("</section>")

    # -- Registry --------------------------------------------------------------------
    if vm.registry:
        rows = [[str(r.timestamp), str(r.lineno), _h(r.operation),
                 f"<code>{_h(r.key)}</code>", _h(r.value), _h(r.data)] for r in vm.registry]
        parts.append('<section class="card"><h2>\U0001f5c4️ Registry Activity</h2>')
        parts.append(_table_html(["Time", "Line", "Operation", "Key", "Value", "Data"], rows))
        parts.append("</section>")

    # -- IOCs ------------------------------------------------------------------------
    iocs = vm.iocs
    if any(iocs.values()):
        parts.append('<section class="card"><h2>🚩 Indicators of Compromise</h2>')
        for label, key in (("URLs", "urls"), ("Domains", "domains"), ("IP Addresses", "ips"),
                           ("Files touched", "files"), ("Registry keys touched", "registry")):
            values = iocs.get(key)
            if not values:
                continue
            parts.append(f"<h3>{label}</h3><ul class=\"ioc-list\">")
            for v in sorted(values):
                if key in ("urls", "domains"):
                    parts.append(f'<li><code>{_h(v)}</code> '
                                  f'<span class="defanged">(defanged: <code>{_h(report._defang(v))}</code>)</span></li>')
                else:
                    parts.append(f"<li><code>{_h(v)}</code></li>")
            parts.append("</ul>")
        parts.append("</section>")

    # -- Notes / warnings -------------------------------------------------------------
    if vm.notes:
        parts.append('<section class="card"><h2>📝 Sandbox Notes</h2><ul>')
        for n in vm.notes:
            parts.append(f"<li>{_h(n)}</li>")
        parts.append("</ul></section>")

    if result.warnings:
        parts.append('<section class="card"><h2>⚠️ Parser Warnings</h2><ul>')
        for w in result.warnings:
            parts.append(f"<li>{_h(w)}</li>")
        parts.append("</ul></section>")

    return "\n".join(parts)


# -- standalone document ---------------------------------------------------------

_CSS = """
:root {
  --bg: #0d1117;
  --bg-card: #161b22;
  --border: #30363d;
  --text: #c9d1d9;
  --text-dim: #8b949e;
  --accent: #ffd23f;
  --info: #58a6ff;
  --low: #3fb950;
  --medium: #d29922;
  --high: #db6d28;
  --critical: #f85149;
  --font-mono: "Fira Code", "JetBrains Mono", Consolas, "Courier New", monospace;
  --font-sans: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font-family: var(--font-sans); line-height: 1.5; }
.container { max-width: 980px; margin: 0 auto; padding: 0 1.25rem 3rem; }
.page-header, .app-header {
  text-align: center; padding: 2.5rem 1rem 1.5rem;
  background: linear-gradient(180deg, rgba(255,210,63,0.08), transparent);
  border-bottom: 1px solid var(--border);
}
.duck-logo { font-size: 3.5rem; line-height: 1; margin-bottom: 0.25rem; }
.page-header h1, .app-header h1 { margin: 0.25rem 0; font-size: 1.8rem; color: var(--accent); }
.tagline { color: var(--text-dim); margin: 0.25rem 0 0; font-size: 0.95rem; }
.duck-banner { font-family: var(--font-mono); color: var(--accent); white-space: pre; text-align: center; margin: 0.5rem 0 0; font-size: 0.8rem; }
a { color: var(--info); }
h2 { font-size: 1.15rem; margin: 0 0 0.75rem; }
h3 { font-size: 1rem; margin: 1rem 0 0.5rem; color: var(--text-dim); }
.card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem 1.5rem; margin: 1.25rem 0; }
.report-meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 0.75rem; margin: 1.5rem 0 1rem; }
.meta-item { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 0.6rem 0.8rem; display: flex; flex-direction: column; }
.meta-label { font-size: 0.7rem; text-transform: uppercase; color: var(--text-dim); letter-spacing: 0.05em; }
.meta-value { font-size: 1rem; font-family: var(--font-mono); word-break: break-all; margin-top: 0.15rem; }
.risk-banner { display: flex; align-items: center; gap: 1rem; border: 1px solid var(--border); border-left: 6px solid var(--text-dim); border-radius: 10px; padding: 1rem 1.25rem; margin: 1rem 0; }
.risk-icon { font-size: 2.5rem; }
.risk-rating { font-size: 1.3rem; font-weight: 700; }
.risk-score { font-weight: 400; color: var(--text-dim); font-size: 0.95rem; }
.risk-tagline { color: var(--text-dim); margin-top: 0.15rem; }
.risk-informational { border-left-color: var(--info); }
.risk-low { border-left-color: var(--low); }
.risk-medium { border-left-color: var(--medium); }
.risk-high { border-left-color: var(--high); }
.risk-critical { border-left-color: var(--critical); background: rgba(248,81,73,0.08); }
.disclaimer { border-left: 3px solid var(--accent); margin: 1rem 0; padding: 0.6rem 1rem; color: var(--text-dim); font-size: 0.9rem; background: rgba(255,210,63,0.05); border-radius: 0 6px 6px 0; }
.badge { display: inline-flex; align-items: center; gap: 0.3rem; padding: 0.15rem 0.55rem; border-radius: 999px; font-size: 0.78rem; font-weight: 700; white-space: nowrap; border: 1px solid currentColor; }
.badge-info { color: var(--info); }
.badge-low { color: var(--low); }
.badge-medium { color: var(--medium); }
.badge-high { color: var(--high); }
.badge-critical { color: var(--critical); }
.table-wrap { overflow-x: auto; }
.report-table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
.report-table th, .report-table td { padding: 0.5rem 0.65rem; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }
.report-table th { color: var(--text-dim); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
.report-table tr:hover td { background: rgba(255,255,255,0.02); }
code, pre { font-family: var(--font-mono); background: rgba(110,118,129,0.15); border-radius: 4px; padding: 0.1rem 0.35rem; font-size: 0.85em; }
.process-tree, .process-tree ul { list-style: none; margin: 0; padding-left: 1.4rem; }
.process-tree { padding-left: 0; }
.process-tree li { margin: 0.35rem 0; border-left: 1px dashed var(--border); padding-left: 0.75rem; }
.proc-meta { color: var(--text-dim); font-size: 0.8rem; margin-left: 0.4rem; }
.tag-elevated { background: rgba(248,81,73,0.15); color: var(--critical); border-radius: 999px; padding: 0.05rem 0.5rem; font-size: 0.7rem; margin-left: 0.4rem; }
.rule-details { padding-left: 1.2rem; }
.rule-details li { margin: 0.4rem 0; }
.technique { color: var(--text-dim); }
.ioc-list { padding-left: 1.2rem; }
.ioc-list li { margin: 0.3rem 0; }
.defanged { color: var(--text-dim); font-size: 0.85em; }
.duck-form { display: flex; flex-direction: column; gap: 0.85rem; margin: 1.5rem 0; }
.duck-form textarea { width: 100%; min-height: 280px; background: #010409; color: var(--text); border: 1px solid var(--border); border-radius: 8px; padding: 0.85rem; font-family: var(--font-mono); font-size: 0.9rem; resize: vertical; }
.form-row { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: center; }
.duck-form select, .duck-form button { background: var(--bg-card); color: var(--text); border: 1px solid var(--border); border-radius: 8px; padding: 0.55rem 0.9rem; font-size: 0.9rem; font-family: var(--font-sans); }
.analyze-btn { background: var(--accent); color: #1a1a00; border: none; font-weight: 700; cursor: pointer; padding: 0.6rem 1.4rem; border-radius: 8px; font-size: 0.95rem; }
.analyze-btn:hover { background: #ffe26b; }
.duck-form select:hover, .duck-form button:hover { border-color: var(--accent); }
.form-error { color: var(--critical); font-weight: 700; }
.site-footer { text-align: center; color: var(--text-dim); font-size: 0.8rem; padding: 2rem 1rem; }
@media (max-width: 600px) {
  .page-header h1, .app-header h1 { font-size: 1.4rem; }
  .duck-logo { font-size: 2.5rem; }
  .card { padding: 1rem; }
}
"""


def page(title: str, body_html: str) -> str:
    """Wrap a body fragment in a full, styled HTML document."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" href="{FAVICON_DATA_URI}">
<title>{_h(title)}</title>
<style>{_CSS}</style>
</head>
<body>
{body_html}
</body>
</html>
"""


def render_html(result: EmulationResult, payload_name: str = "payload") -> str:
    """Render a full, self-contained HTML report document."""
    fragment = render_html_fragment(result, payload_name)
    body = (
        '<header class="page-header">'
        '<div class="duck-logo">\U0001f986\U0001f4bb</div>'
        "<h1>DuckyScript Behaviour Sandbox Report</h1>"
        "</header>"
        f'<main class="container">{fragment}</main>'
        '<footer class="site-footer">Generated by the DuckyScript Behaviour Sandbox '
        "-- a static simulation. Nothing here was executed.</footer>"
    )
    return page(f"Sandbox report: {payload_name}", body)
