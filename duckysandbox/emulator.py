"""Behaviour emulator.

Walks a parsed :class:`~duckysandbox.parser.Program` with an instruction
pointer, modelling the effects of each instruction on a virtual host:

* ``STRING`` / ``STRINGLN`` accumulate into a "typed line" buffer;
* pressing ``ENTER`` (or any chord containing it) flushes that buffer to the
  :mod:`duckysandbox.analyzer`, which classifies it and records concrete
  side-effects (processes, files, registry, network) on the
  :class:`~duckysandbox.vmstate.VMState`;
* control flow (``IF``/``WHILE``/``REPEAT``/``FUNCTION``) is interpreted with
  safety caps so the analysis always terminates.

Because runtime conditions (window titles, OS version, time of day, ...)
cannot be known statically, every branch of an ``IF``/``ELSE_IF``/``ELSE``
chain is modelled -- the report shows everything a payload *could* do, which
is the conservative choice for a pre-deployment audit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import analyzer, keymap
from .analyzer import Finding
from .parser import Instruction, Program, parse
from .vmstate import VMState


CONDITIONAL_NOTE = (
    "This payload contains conditional (IF/ELSE) logic; the sandbox models "
    "every branch because it cannot evaluate runtime conditions such as "
    "window titles, OS version, or time of day."
)

# Combos that return keyboard focus to the desktop / app launcher, which in
# turn closes any modelled "current shell" context.
_DESKTOP_RESET_KEYS = [
    frozenset({"GUI"}),
    frozenset({"GUI", "R"}),
    frozenset({"GUI", "D"}),
    frozenset({"GUI", "E"}),
    frozenset({"GUI", "S"}),
    frozenset({"GUI", "X"}),
    frozenset({"CTRL", "ESC"}),
    frozenset({"CTRL", "ESCAPE"}),
]

_DESKTOP_NAME = {"windows": "explorer.exe", "macos": "Finder", "linux": "gnome-shell"}

_VAR_RE = re.compile(r"^[\$%]?(\w+)%?\s*(?:=\s*)?(.*)$")
_INT_RE = re.compile(r"-?\d+")


def _parse_int(s: str, default: int = 0) -> int:
    m = _INT_RE.search(s or "")
    return int(m.group(0)) if m else default


def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


def _truncate(s: str, n: int = 100) -> str:
    return s if len(s) <= n else s[: n - 3] + "..."


def detect_target_os(text: str) -> str:
    """Best-effort guess of the OS a payload targets, from its content."""
    score = {"windows": 0, "macos": 0, "linux": 0}
    if re.search(r"\bGUI\b", text):
        score["windows"] += 1
        score["linux"] += 1
    if re.search(r"\b(?:COMMAND|OPTION)\b", text):
        score["macos"] += 2
    if re.search(r"osascript|/Applications/|Terminal\.app|launchctl|\.plist|/Library/", text, re.I):
        score["macos"] += 3
    if re.search(r"powershell|cmd(?:\.exe)?\b|C:\\|reg add|schtasks|\.exe\b", text, re.I):
        score["windows"] += 3
    if re.search(r"/bin/(?:ba)?sh|/etc/|xdotool|gnome-terminal|xterm|crontab"
                 r"|\bbash\b|/dev/tcp/|CTRL\s+ALT\s+T\b", text, re.I):
        score["linux"] += 3
    best = max(score, key=score.get)
    return best if score[best] > 0 else "windows"


@dataclass
class EmulationResult:
    vmstate: VMState
    findings: list[Finding]
    warnings: list[str]
    target_os: str
    program: Program


class Emulator:
    """Interprets a :class:`Program`, producing an :class:`EmulationResult`."""

    MAX_STEPS = 200_000
    MAX_WHILE_ITERS = 5
    MAX_REPEAT = 200

    def __init__(self, program: Program, target_os: str = "windows") -> None:
        self.program = program
        self.target_os = target_os
        self.vmstate = VMState(target_os=target_os)
        self.findings: list[Finding] = []
        self.vars: dict[str, str] = {}
        self.default_delay = 0
        self.char_delay = 0
        self.held_mods: set[str] = set()
        self.line_buffer = ""
        self.process_stack = [_DESKTOP_NAME.get(target_os, "explorer.exe")]
        self._last_repeatable: Instruction | None = None

    # -- main loop -----------------------------------------------------

    def run(self) -> EmulationResult:
        ins = self.program.instructions
        ip = 0
        steps = 0
        call_stack: list[int] = []
        while_iters: dict[int, int] = {}

        while ip < len(ins):
            steps += 1
            if steps > self.MAX_STEPS:
                self.vmstate.add_note(
                    f"Execution step limit ({self.MAX_STEPS}) reached; analysis truncated."
                )
                break

            instr = ins[ip]
            op = instr.op

            if op in ("REM", "REM_BLOCK", "END_REM", "NOP"):
                ip += 1
                continue

            if op in ("IF", "ELSE_IF", "ELSE"):
                if instr.arg:
                    self.vmstate.add_note(CONDITIONAL_NOTE)
                ip += 1
                continue
            if op == "END_IF":
                ip += 1
                continue

            if op == "WHILE":
                count = while_iters.get(ip, 0)
                if count < self.MAX_WHILE_ITERS:
                    while_iters[ip] = count + 1
                    ip += 1
                else:
                    self.vmstate.add_note(
                        f"Line {instr.lineno}: WHILE loop capped at "
                        f"{self.MAX_WHILE_ITERS} iterations for analysis."
                    )
                    ip = self.program.while_end.get(ip, ip) + 1
                continue
            if op == "END_WHILE":
                ip = self.program.while_back.get(ip, ip - 1)
                continue

            if op == "FUNCTION":
                # Function bodies only run when CALLed; skip over the
                # definition during normal top-to-bottom execution.
                ip = self.program.func_skip.get(ip, ip) + 1
                continue
            if op == "END_FUNCTION" or op == "RETURN":
                if call_stack:
                    ip = call_stack.pop()
                else:
                    ip += 1
                continue
            if op == "CALL":
                target = self.program.func_range.get(instr.arg)
                if target:
                    call_stack.append(ip + 1)
                    ip = target[0]
                else:
                    self.vmstate.add_note(
                        f"Line {instr.lineno}: call to undefined function "
                        f"`{instr.arg}` (ignored)."
                    )
                    ip += 1
                continue

            if op == "REPEAT":
                self._do_repeat(instr)
                ip += 1
                continue

            self._execute(instr)
            if op in ("STRING", "STRINGLN", "KEY", "DELAY"):
                self._last_repeatable = instr
            ip += 1

        # A trailing typed-but-not-submitted command is still worth analysing.
        if self.line_buffer.strip():
            self.vmstate.add_note(
                "Payload ends with typed text that was never submitted with "
                "ENTER; it is analysed anyway."
            )
            last_line = ins[-1].lineno if ins else 0
            self._flush_buffer(last_line)

        return EmulationResult(
            vmstate=self.vmstate,
            findings=self.findings,
            warnings=list(self.program.warnings),
            target_os=self.target_os,
            program=self.program,
        )

    # -- instruction dispatch -------------------------------------------

    def _execute(self, instr: Instruction) -> None:
        op = instr.op
        if op == "STRING":
            self._type_text(instr, instr.arg, newline=False)
        elif op == "STRINGLN":
            self._type_text(instr, instr.arg, newline=True)
        elif op == "KEY":
            self._press_keys(instr)
        elif op == "DELAY":
            self.vmstate.advance(_parse_int(instr.arg))
        elif op == "DEFAULT_DELAY":
            self.default_delay = _parse_int(instr.arg)
        elif op == "CHAR_DELAY":
            self.char_delay = _parse_int(instr.arg)
        elif op == "VAR":
            self._handle_var(instr)
        elif op == "ATTACKMODE":
            self._handle_attackmode(instr)
        elif op == "RANDOM":
            self._handle_random(instr)
        elif op in ("HOLD", "RELEASE"):
            self._handle_hold_release(instr)
        elif op in ("LED", "HW"):
            self.vmstate.add_note(
                f"Line {instr.lineno}: device directive `{instr.raw.strip()}` "
                "has no effect on the host OS."
            )
        elif op == "UNKNOWN":
            self.vmstate.add_note(
                f"Line {instr.lineno}: unrecognised instruction "
                f"`{instr.raw.strip()}` (ignored)."
            )

        if op in ("STRING", "STRINGLN", "KEY") and self.default_delay:
            self.vmstate.advance(self.default_delay)

    def _do_repeat(self, instr: Instruction) -> None:
        requested = _parse_int(instr.arg, default=1)
        n = max(0, min(requested, self.MAX_REPEAT))
        if requested > self.MAX_REPEAT:
            self.vmstate.add_note(
                f"Line {instr.lineno}: REPEAT count capped at "
                f"{self.MAX_REPEAT} for analysis."
            )
        if self._last_repeatable is None:
            return
        for _ in range(n):
            self._execute(self._last_repeatable)

    # -- typing / keystrokes ----------------------------------------------

    def _type_text(self, instr: Instruction, text: str, newline: bool) -> None:
        text = self._substitute_vars(text)
        if text:
            self.vmstate.record_keystroke(instr.lineno, f"Type: {_truncate(text)}", text=text)
            self.line_buffer += text
            if self.char_delay:
                self.vmstate.advance(len(text) * self.char_delay)
        if newline:
            self.vmstate.record_keystroke(instr.lineno, "Press ENTER", keys=["ENTER"])
            self._flush_buffer(instr.lineno)

    def _press_keys(self, instr: Instruction) -> None:
        keys = list(self.held_mods) + list(instr.keys)
        desc = keymap.describe_combo(keys) or ("Press " + "+".join(keys))
        self.vmstate.record_keystroke(instr.lineno, desc, keys=keys)

        upkeys = {k.upper() for k in keys}

        if upkeys & {"ENTER", "RETURN"}:
            elevated = bool({"CTRL", "CONTROL"} & upkeys) and "SHIFT" in upkeys
            self._flush_buffer(instr.lineno, elevated=elevated)
        elif upkeys in _DESKTOP_RESET_KEYS:
            self.process_stack = self.process_stack[:1]
            self.line_buffer = ""
        elif upkeys == {"ALT", "F4"} and len(self.process_stack) > 1:
            self.process_stack.pop()
        elif upkeys == {"BACKSPACE"} and self.line_buffer:
            self.line_buffer = self.line_buffer[:-1]

    def _flush_buffer(self, lineno: int, elevated: bool = False) -> None:
        text = self.line_buffer.strip()
        self.line_buffer = ""
        if not text:
            return

        parent = self.process_stack[-1]
        findings = analyzer.analyze_command(text, lineno, self.vmstate, parent=parent)
        self.findings.extend(findings)

        if elevated:
            self.vmstate.add_note(
                f"Line {lineno}: command was submitted via Ctrl+Shift+Enter, "
                "which typically triggers a UAC elevation prompt."
            )

        for f in findings:
            name = analyzer.PROCESS_RULE_NAMES.get(f.rule_id)
            if name in analyzer.INTERACTIVE_SHELLS:
                self.process_stack.append(name)
                break

    # -- misc directives ----------------------------------------------------

    def _handle_var(self, instr: Instruction) -> None:
        m = _VAR_RE.match(instr.arg)
        if not m:
            return
        name, value = m.group(1), _strip_quotes(m.group(2))
        self.vars[name] = value

    def _substitute_vars(self, text: str) -> str:
        if not self.vars:
            return text
        return re.sub(r"\$(\w+)", lambda m: self.vars.get(m.group(1), m.group(0)), text)

    def _handle_attackmode(self, instr: Instruction) -> None:
        arg = instr.arg.strip()
        self.vmstate.add_note(f"BashBunny ATTACKMODE configuration: {arg}")
        up = arg.upper()
        if "STORAGE" in up:
            self.findings.append(Finding(
                "BB-STORAGE", "Mass-storage mode enabled", analyzer.EXFIL,
                "T1052.001 Exfiltration over USB", analyzer.MEDIUM,
                instr.raw.strip(), instr.lineno,
                "Exposes the device's onboard storage to the host -- a channel "
                "for staging tools or exfiltrating files."))
        if re.search(r"ETHERNET|RNDIS|ECM|NCM", up):
            self.findings.append(Finding(
                "BB-NETIFACE", "Emulated USB network adapter", analyzer.C2,
                "T1200 Hardware Additions", analyzer.MEDIUM,
                instr.raw.strip(), instr.lineno,
                "Presents a USB network adapter to the host, which can be used "
                "for traffic interception, DNS hijacking, or as a C2 channel."))

    def _handle_random(self, instr: Instruction) -> None:
        self.vmstate.add_note(
            "Uses RANDOM_* keystroke directives to inject randomised filler "
            "characters (commonly used for jitter or signature evasion)."
        )
        self.vmstate.record_keystroke(instr.lineno, "Type random character")

    def _handle_hold_release(self, instr: Instruction) -> None:
        arg = instr.arg.strip()
        if instr.op == "HOLD":
            if arg:
                self.held_mods.add(arg.upper())
            self.vmstate.record_keystroke(instr.lineno, f"Hold {arg}" if arg else "Hold")
        else:
            if arg:
                self.held_mods.discard(arg.upper())
            else:
                self.held_mods.clear()
            self.vmstate.record_keystroke(instr.lineno, f"Release {arg}" if arg else "Release all")


def emulate(text: str, target_os: str | None = None, source_name: str = "payload") -> EmulationResult:
    """Parse and emulate payload *text*, returning an :class:`EmulationResult`."""
    program = parse(text, source_name=source_name)
    if target_os is None:
        target_os = detect_target_os(text)
    return Emulator(program, target_os=target_os).run()
