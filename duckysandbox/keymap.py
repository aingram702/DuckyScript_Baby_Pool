"""Key definitions for DuckyScript / BashBunny payloads.

DuckyScript is a keystroke-injection language: every line begins with a command
keyword.  Some keywords name *keys* (``ENTER``, ``GUI``, ``CTRL`` ...) while
others are *directives* (``STRING``, ``DELAY`` ...).  This module knows which
tokens are keys so the parser can classify a line as a key-press instruction,
and it provides human-readable descriptions for common hot-key combinations so
the behaviour report can explain what a chord actually does on the target host.
"""

from __future__ import annotations

# Modifier keys.  These may appear alone, chorded together, or combined with a
# single character / named key (e.g. ``GUI r`` or ``CTRL ALT DELETE``).
MODIFIERS = {
    "CTRL", "CONTROL",
    "ALT",
    "SHIFT",
    "GUI", "WINDOWS", "WIN",
    "COMMAND", "OPTION",  # macOS aliases used by some payloads
}

# Standalone named keys (no character payload of their own).
NAMED_KEYS = {
    "ENTER", "RETURN",
    "TAB",
    "SPACE",
    "ESC", "ESCAPE",
    "BACKSPACE",
    "DELETE", "DEL",
    "INSERT",
    "HOME", "END",
    "PAGEUP", "PAGEDOWN",
    "UP", "UPARROW", "DOWN", "DOWNARROW",
    "LEFT", "LEFTARROW", "RIGHT", "RIGHTARROW",
    "PRINTSCREEN", "PRINT",
    "PAUSE", "BREAK",
    "CAPSLOCK", "NUMLOCK", "SCROLLLOCK",
    "MENU", "APP",
    "PAUSE", "POWER",
}
# Function keys F1 - F12 (and a few keyboards expose up to F24).
NAMED_KEYS |= {f"F{i}" for i in range(1, 25)}

# Every token that, when it leads a line, means "this is a key-press" rather
# than a directive such as STRING / DELAY / REM.
KEYPRESS_OPCODES = MODIFIERS | NAMED_KEYS

# Human readable meaning of well-known chords.  Keys are frozensets of the
# normalised tokens so ordering ("CTRL ALT DEL" vs "ALT CTRL DEL") does not
# matter.  Used purely to enrich the behaviour report.
_COMBOS = {
    frozenset({"GUI", "R"}): "Open the Windows Run dialog",
    frozenset({"GUI", "D"}): "Show the desktop / minimise all windows",
    frozenset({"GUI", "E"}): "Open File Explorer",
    frozenset({"GUI", "I"}): "Open Windows Settings",
    frozenset({"GUI", "X"}): "Open the Power User (WinX) menu",
    frozenset({"GUI", "L"}): "Lock the workstation",
    frozenset({"GUI", "S"}): "Open Search",
    frozenset({"GUI", "M"}): "Minimise all windows",
    frozenset({"ALT", "F4"}): "Close the active window",
    frozenset({"ALT", "TAB"}): "Switch between windows",
    frozenset({"ALT", "SPACE"}): "Open the window system menu",
    frozenset({"CTRL", "ALT", "DELETE"}): "Secure Attention Sequence (Ctrl+Alt+Del)",
    frozenset({"CTRL", "ALT", "DEL"}): "Secure Attention Sequence (Ctrl+Alt+Del)",
    frozenset({"CTRL", "SHIFT", "ESC"}): "Open Task Manager",
    frozenset({"CTRL", "SHIFT", "ESCAPE"}): "Open Task Manager",
    frozenset({"CTRL", "SHIFT", "ENTER"}): "Run elevated (UAC) from the active dialog",
    frozenset({"CTRL", "C"}): "Copy / send SIGINT in a terminal",
    frozenset({"CTRL", "V"}): "Paste",
    frozenset({"CTRL", "X"}): "Cut",
    frozenset({"CTRL", "A"}): "Select all",
    frozenset({"CTRL", "Z"}): "Undo",
    frozenset({"CTRL", "S"}): "Save",
    frozenset({"CTRL", "W"}): "Close the current tab/document",
    frozenset({"CTRL", "L"}): "Focus the address/location bar",
    frozenset({"CTRL", "SHIFT", "N"}): "Open a new private/incognito window",
}


def is_keypress_opcode(token: str) -> bool:
    """Return True if *token* (a leading line keyword) denotes a key-press."""
    return token.upper() in KEYPRESS_OPCODES


def is_modifier(token: str) -> bool:
    return token.upper() in MODIFIERS


def describe_combo(keys) -> str:
    """Best-effort English description of a key chord, or "" if unknown."""
    upper = frozenset(k.upper() for k in keys)
    return _COMBOS.get(upper, "")
