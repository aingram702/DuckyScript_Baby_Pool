"""Virtual machine state and the event log produced while emulating a payload.

The sandbox never runs a payload on a real operating system.  Instead it
reconstructs the command stream the payload would inject and *models* the
side-effects on a virtual host.  Those modelled side-effects are recorded here:
HID keystroke events, process creation, file-system writes, registry changes
and network connections.  This is the structured "behaviour log" that the
report is rendered from.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


def _fmt_clock(ms: int) -> str:
    """Render a virtual-clock millisecond offset as ``mm:ss.mmm``."""
    seconds, millis = divmod(int(ms), 1000)
    minutes, seconds = divmod(seconds, 60)
    return f"{minutes:02d}:{seconds:02d}.{millis:03d}"


@dataclass
class Event:
    """Base class for everything in the behaviour log."""

    t_ms: int          # virtual time offset from start of execution
    lineno: int        # source line of the payload that triggered the event
    kind: str = field(init=False, default="event")

    @property
    def timestamp(self) -> str:
        return _fmt_clock(self.t_ms)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind
        d["timestamp"] = self.timestamp
        return d


@dataclass
class KeystrokeEvent(Event):
    """A modelled HID report: text typed or a key chord pressed."""

    description: str = ""
    text: str = ""        # literal characters typed (for STRING)
    keys: list[str] = field(default_factory=list)  # chord, e.g. ["GUI", "R"]
    kind = "keystroke"


@dataclass
class ProcessEvent(Event):
    """A process the injected keystrokes would cause to be created."""

    name: str = ""
    cmdline: str = ""
    parent: str = ""
    integrity: str = "medium"   # medium / high (elevated)
    kind = "process"


@dataclass
class FileEvent(Event):
    """A file-system modification (write / create / delete / copy)."""

    path: str = ""
    operation: str = "write"    # write / create / append / delete / copy / read
    detail: str = ""
    kind = "file"


@dataclass
class RegistryEvent(Event):
    """A Windows registry modification."""

    key: str = ""
    value: str = ""
    data: str = ""
    operation: str = "set"      # set / add / delete
    kind = "registry"


@dataclass
class NetworkEvent(Event):
    """An attempted network connection / data transfer."""

    host: str = ""
    port: int = 0
    protocol: str = "tcp"       # tcp / udp / http / https / dns / smb / ftp
    direction: str = "outbound"  # outbound / inbound
    detail: str = ""
    kind = "network"


class VMState:
    """Mutable virtual-host state accumulated during emulation.

    Besides the raw event log it keeps de-duplicated, convenient views
    (processes, files, registry, network) that the report iterates over, plus a
    set of indicators of compromise (IOCs) harvested along the way.
    """

    def __init__(self, target_os: str = "windows") -> None:
        self.target_os = target_os
        self.clock_ms = 0

        self.keystrokes: list[KeystrokeEvent] = []
        self.processes: list[ProcessEvent] = []
        self.files: list[FileEvent] = []
        self.registry: list[RegistryEvent] = []
        self.network: list[NetworkEvent] = []

        # Indicators of compromise, keyed by type for tidy reporting.
        self.iocs: dict[str, set[str]] = {
            "urls": set(),
            "domains": set(),
            "ips": set(),
            "files": set(),
            "registry": set(),
        }

        # Free-form notes (e.g. decoded encoded-commands, loop caps hit).
        self.notes: list[str] = []

    # -- recording helpers -------------------------------------------------

    def advance(self, ms: int) -> None:
        if ms > 0:
            self.clock_ms += ms

    def record_keystroke(self, lineno: int, description: str,
                         text: str = "", keys: list[str] | None = None) -> None:
        self.keystrokes.append(
            KeystrokeEvent(self.clock_ms, lineno, description, text, keys or [])
        )

    def record_process(self, lineno: int, name: str, cmdline: str = "",
                       parent: str = "", integrity: str = "medium") -> ProcessEvent:
        ev = ProcessEvent(self.clock_ms, lineno, name, cmdline, parent, integrity)
        self.processes.append(ev)
        return ev

    def record_file(self, lineno: int, path: str, operation: str = "write",
                    detail: str = "") -> None:
        self.files.append(FileEvent(self.clock_ms, lineno, path, operation, detail))
        self.iocs["files"].add(path)

    def record_registry(self, lineno: int, key: str, value: str = "",
                        data: str = "", operation: str = "set") -> None:
        self.registry.append(
            RegistryEvent(self.clock_ms, lineno, key, value, data, operation)
        )
        self.iocs["registry"].add(key + (f"\\{value}" if value else ""))

    def record_network(self, lineno: int, host: str, port: int = 0,
                       protocol: str = "tcp", direction: str = "outbound",
                       detail: str = "") -> None:
        self.network.append(
            NetworkEvent(self.clock_ms, lineno, host, port, protocol, direction, detail)
        )

    def add_note(self, note: str) -> None:
        if note not in self.notes:
            self.notes.append(note)

    # -- aggregate views ---------------------------------------------------

    def all_events(self) -> list[Event]:
        """Every event sorted by virtual time then source line."""
        merged: list[Event] = []
        merged += self.keystrokes
        merged += self.processes
        merged += self.files
        merged += self.registry
        merged += self.network
        merged.sort(key=lambda e: (e.t_ms, e.lineno))
        return merged

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_os": self.target_os,
            "duration_ms": self.clock_ms,
            "keystrokes": [e.to_dict() for e in self.keystrokes],
            "processes": [e.to_dict() for e in self.processes],
            "files": [e.to_dict() for e in self.files],
            "registry": [e.to_dict() for e in self.registry],
            "network": [e.to_dict() for e in self.network],
            "iocs": {k: sorted(v) for k, v in self.iocs.items()},
            "notes": list(self.notes),
        }
