"""Parser for DuckyScript (classic + 3.0) and BashBunny payloads.

The parser turns raw payload text into a flat list of :class:`Instruction`
objects and pre-computes the control-flow structure (IF / WHILE / FUNCTION jump
tables) so the emulator can walk the program with a simple instruction pointer.
It is deliberately forgiving: unknown keywords become ``UNKNOWN`` instructions
rather than hard errors, because real-world payloads frequently mix dialects.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import keymap


# Directives understood directly (everything else is a key-press, a function
# call, or UNKNOWN).
# DEFAULT_DELAY adds a pause after every instruction; the *_CHAR_DELAY /
# STRING_DELAY family instead paces each character within a STRING, so the
# two are tracked separately by the emulator.
_DEFAULT_DELAY_ALIASES = {"DEFAULT_DELAY", "DEFAULTDELAY"}
_CHAR_DELAY_ALIASES = {"DEFAULT_CHAR_DELAY", "DEFAULTCHARDELAY",
                       "STRING_DELAY", "STRINGDELAY"}

_CONTROL_OPS = {"IF", "ELSE_IF", "ELSE", "END_IF",
                "WHILE", "END_WHILE",
                "FUNCTION", "END_FUNCTION", "RETURN"}


@dataclass
class Instruction:
    lineno: int
    raw: str
    op: str                       # normalised opcode (upper-case)
    arg: str = ""                 # remainder of the line (case preserved)
    keys: list[str] = field(default_factory=list)  # for KEY chords

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        extra = f" keys={self.keys}" if self.keys else (f" arg={self.arg!r}" if self.arg else "")
        return f"<{self.lineno}:{self.op}{extra}>"


@dataclass
class IfBlock:
    headers: list[int]            # indices of IF / ELSE_IF / ELSE lines
    end: int                      # index of END_IF


@dataclass
class Program:
    instructions: list[Instruction]
    source_name: str = "payload"

    # control-flow tables (populated by build_structure)
    branch_next: dict[int, int] = field(default_factory=dict)   # header -> next header/END_IF
    branch_end: dict[int, int] = field(default_factory=dict)    # header -> END_IF
    while_end: dict[int, int] = field(default_factory=dict)     # WHILE -> END_WHILE
    while_back: dict[int, int] = field(default_factory=dict)    # END_WHILE -> WHILE
    func_range: dict[str, tuple[int, int]] = field(default_factory=dict)  # NAME -> (body_start, END_FUNCTION)
    func_skip: dict[int, int] = field(default_factory=dict)     # FUNCTION -> END_FUNCTION
    warnings: list[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.instructions)


def _normalise_func_name(token: str) -> str:
    return token.strip().rstrip("()").strip().upper()


def _split_first(line: str) -> tuple[str, str]:
    parts = line.split(None, 1)
    if not parts:
        return "", ""
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], parts[1]


def _parse_line(lineno: int, raw: str) -> Instruction | None:
    """Parse a single already-stripped line into an Instruction (or None)."""
    line = raw.strip()
    if not line:
        return None

    first, rest = _split_first(line)
    op = first.upper()

    # Comments ---------------------------------------------------------
    if op in ("REM", "REM_BLOCK", "END_REM"):
        return Instruction(lineno, raw, op, rest)

    # BashBunny QUACK / Q wrappers run an embedded ducky command.
    if op in ("QUACK", "Q"):
        if not rest.strip():
            return Instruction(lineno, raw, "NOP")
        inner = _parse_line(lineno, rest)
        return inner if inner is not None else Instruction(lineno, raw, "NOP")

    # Typed text -------------------------------------------------------
    if op in ("STRING", "STRINGLN"):
        return Instruction(lineno, raw, op, rest)

    # Delays -----------------------------------------------------------
    if op == "DELAY":
        return Instruction(lineno, raw, "DELAY", rest.strip())
    if op in _DEFAULT_DELAY_ALIASES:
        return Instruction(lineno, raw, "DEFAULT_DELAY", rest.strip())
    if op in _CHAR_DELAY_ALIASES:
        return Instruction(lineno, raw, "CHAR_DELAY", rest.strip())

    # Repetition -------------------------------------------------------
    if op == "REPEAT":
        return Instruction(lineno, raw, "REPEAT", rest.strip())

    # Variables / constants -------------------------------------------
    if op in ("VAR", "DEFINE"):
        return Instruction(lineno, raw, "VAR", rest.strip())

    # Control flow -----------------------------------------------------
    if op == "IF":
        return Instruction(lineno, raw, "IF", _strip_condition(rest))
    if op in ("ELSE_IF", "ELSEIF"):
        return Instruction(lineno, raw, "ELSE_IF", _strip_condition(rest))
    if op == "ELSE":
        # "ELSE IF (...) THEN" -> ELSE_IF
        if rest.strip().upper().startswith("IF"):
            _, cond = _split_first(rest)
            return Instruction(lineno, raw, "ELSE_IF", _strip_condition(cond))
        return Instruction(lineno, raw, "ELSE")
    if op == "END_IF":
        return Instruction(lineno, raw, "END_IF")
    if op == "WHILE":
        return Instruction(lineno, raw, "WHILE", _strip_condition(rest))
    if op == "END_WHILE":
        return Instruction(lineno, raw, "END_WHILE")
    if op == "FUNCTION":
        return Instruction(lineno, raw, "FUNCTION", _normalise_func_name(rest))
    if op == "END_FUNCTION":
        return Instruction(lineno, raw, "END_FUNCTION")
    if op == "RETURN":
        return Instruction(lineno, raw, "RETURN")

    # Explicit function call (canonical DuckyScript 3.0 calls a function by
    # writing its bare name; CALL is accepted as a common alias). Both forms
    # are resolved against defined functions in build_structure().
    if op == "CALL":
        return Instruction(lineno, raw, "UNKNOWN", rest.strip())

    # BashBunny / hardware directives ---------------------------------
    if op == "ATTACKMODE":
        return Instruction(lineno, raw, "ATTACKMODE", rest.strip())
    if op in ("LED", "LED_R", "LED_G", "LED_B"):
        return Instruction(lineno, raw, "LED", rest.strip())
    if op in ("HOLD", "RELEASE"):
        return Instruction(lineno, raw, op, rest.strip())
    if op in ("GET", "HOST_OS", "WAIT_FOR_BUTTON_PRESS", "BUTTON_DEF",
              "END_BUTTON", "RESET", "INJECT_MOD", "SAVE_HOST_KEYBOARD_LOCK_STATE",
              "RESTORE_HOST_KEYBOARD_LOCK_STATE"):
        return Instruction(lineno, raw, "HW", line)
    if op.startswith("RANDOM"):
        return Instruction(lineno, raw, "RANDOM", op)

    # Key presses ------------------------------------------------------
    if keymap.is_keypress_opcode(op):
        keys = _parse_keys(line)
        return Instruction(lineno, raw, "KEY", line, keys)

    # Anything else: could be a function call (resolved later) or unknown.
    return Instruction(lineno, raw, "UNKNOWN", line)


def _parse_keys(line: str) -> list[str]:
    keys: list[str] = []
    for tok in line.split():
        up = tok.upper()
        if up in keymap.KEYPRESS_OPCODES:
            keys.append(up)
        else:
            keys.append(tok)  # a literal character such as 'r' in "GUI r"
    return keys


def _strip_condition(text: str) -> str:
    """Extract the bare condition from ``(cond) THEN`` style clauses."""
    s = text.strip()
    # drop a trailing THEN keyword
    if s.upper().endswith("THEN"):
        s = s[:-4].strip()
    # drop a single matching pair of wrapping parentheses
    if s.startswith("(") and s.endswith(")"):
        s = s[1:-1].strip()
    return s


def build_structure(program: Program) -> None:
    """Populate the control-flow jump tables on *program* in place."""
    ins = program.instructions
    if_stack: list[list[int]] = []
    while_stack: list[int] = []
    func_stack: list[tuple[int, str]] = []
    in_rem_block = False

    for idx, instr in enumerate(ins):
        op = instr.op

        # Multi-line REM blocks suppress structure detection inside them.
        if op == "REM_BLOCK":
            in_rem_block = True
            continue
        if op == "END_REM":
            in_rem_block = False
            continue
        if in_rem_block:
            continue

        if op == "IF":
            if_stack.append([idx])
        elif op in ("ELSE_IF", "ELSE"):
            if if_stack:
                if_stack[-1].append(idx)
            else:
                program.warnings.append(f"line {instr.lineno}: {op} without IF")
        elif op == "END_IF":
            if if_stack:
                headers = if_stack.pop()
                for i, h in enumerate(headers):
                    program.branch_next[h] = headers[i + 1] if i + 1 < len(headers) else idx
                    program.branch_end[h] = idx
            else:
                program.warnings.append(f"line {instr.lineno}: END_IF without IF")
        elif op == "WHILE":
            while_stack.append(idx)
        elif op == "END_WHILE":
            if while_stack:
                w = while_stack.pop()
                program.while_end[w] = idx
                program.while_back[idx] = w
            else:
                program.warnings.append(f"line {instr.lineno}: END_WHILE without WHILE")
        elif op == "FUNCTION":
            func_stack.append((idx, instr.arg))
        elif op == "END_FUNCTION":
            if func_stack:
                fidx, name = func_stack.pop()
                program.func_range[_normalise_func_name(name)] = (fidx + 1, idx)
                program.func_skip[fidx] = idx
            else:
                program.warnings.append(f"line {instr.lineno}: END_FUNCTION without FUNCTION")

    for headers in if_stack:
        program.warnings.append(f"line {ins[headers[0]].lineno}: IF without END_IF")
    for w in while_stack:
        program.warnings.append(f"line {ins[w].lineno}: WHILE without END_WHILE")

    # Resolve UNKNOWN instructions that name a defined function into CALLs.
    for instr in ins:
        if instr.op == "UNKNOWN":
            name = _normalise_func_name(instr.arg.split(None, 1)[0]) if instr.arg else ""
            if name in program.func_range:
                instr.op = "CALL"
                instr.arg = name


def parse(text: str, source_name: str = "payload") -> Program:
    """Parse payload *text* into a :class:`Program`."""
    instructions: list[Instruction] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        instr = _parse_line(lineno, raw)
        if instr is not None:
            instructions.append(instr)
    program = Program(instructions, source_name)
    build_structure(program)
    return program
