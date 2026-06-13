"""Behaviour-detection engine.

Given a reconstructed shell command (the text a payload would have typed into a
``cmd``/``powershell``/terminal window) this module:

* runs a library of regex rules to produce MITRE ATT&CK-mapped *findings*; and
* extracts concrete side-effects (network connections, registry changes, file
  writes, child processes) into the :class:`~duckysandbox.vmstate.VMState`.

It is a *static* analysis of the injected command stream -- nothing is ever
executed -- which is exactly what makes auditing a payload here safe.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from .vmstate import VMState


# -- severity model --------------------------------------------------------

INFO = "info"
LOW = "low"
MEDIUM = "medium"
HIGH = "high"
CRITICAL = "critical"

SEVERITY_WEIGHT = {INFO: 0, LOW: 5, MEDIUM: 12, HIGH: 25, CRITICAL: 40}
SEVERITY_RANK = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4}

# MITRE ATT&CK tactic names (used as report groupings).
EXECUTION = "Execution"
PERSISTENCE = "Persistence"
PRIVESC = "Privilege Escalation"
EVASION = "Defense Evasion"
CRED_ACCESS = "Credential Access"
DISCOVERY = "Discovery"
LATERAL = "Lateral Movement"
COLLECTION = "Collection"
C2 = "Command and Control"
EXFIL = "Exfiltration"
IMPACT = "Impact"


@dataclass
class Finding:
    rule_id: str
    title: str
    tactic: str
    technique: str
    severity: str
    evidence: str
    lineno: int
    explanation: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "tactic": self.tactic,
            "technique": self.technique,
            "severity": self.severity,
            "evidence": self.evidence,
            "lineno": self.lineno,
            "explanation": self.explanation,
        }


@dataclass
class Rule:
    rule_id: str
    title: str
    tactic: str
    technique: str
    severity: str
    pattern: str
    explanation: str

    def __post_init__(self) -> None:
        self.regex = re.compile(self.pattern, re.IGNORECASE)


# -- rule library ----------------------------------------------------------
# Ordered roughly by ATT&CK tactic.  Patterns are intentionally conservative
# to keep false positives low while catching the techniques that show up most
# often in real HID injection payloads.
RULES: list[Rule] = [
    # Execution ---------------------------------------------------------
    Rule("EXEC-PS", "PowerShell execution", EXECUTION, "T1059.001 PowerShell",
         LOW, r"\b(?:powershell(?:\.exe)?|pwsh)\b",
         "Launches Windows PowerShell, a common host for fileless tradecraft."),
    Rule("EXEC-CMD", "Windows command shell", EXECUTION, "T1059.003 Windows Command Shell",
         LOW, r"\bcmd(?:\.exe)?\b",
         "Spawns cmd.exe to run shell commands."),
    Rule("EXEC-WSCRIPT", "Windows Script Host", EXECUTION, "T1059.005 Visual Basic / T1059.007 JScript",
         MEDIUM, r"\b(?:wscript|cscript)(?:\.exe)?\b",
         "Uses the Windows Script Host to run VBScript/JScript."),
    Rule("EXEC-IEX", "Invoke-Expression", EXECUTION, "T1059.001 PowerShell",
         HIGH, r"\b(?:iex|Invoke-Expression)\b",
         "Evaluates a dynamically-built string as code (fileless execution)."),
    Rule("EXEC-BASH", "Shell execution", EXECUTION, "T1059.004 Unix Shell",
         LOW, r"\b(?:/bin/(?:ba)?sh|bash|zsh|sh)\b\s+-c\b|^\s*(?:bash|sh|zsh)\b",
         "Runs a Unix shell (bash/sh/zsh) to execute commands."),
    Rule("EXEC-OSASCRIPT", "AppleScript execution", EXECUTION, "T1059.002 AppleScript",
         MEDIUM, r"\bosascript\b",
         "Uses osascript to run AppleScript/JXA on macOS."),
    Rule("EXEC-MSHTA", "mshta proxy execution", EVASION, "T1218.005 Mshta",
         HIGH, r"\bmshta(?:\.exe)?\b",
         "Uses mshta.exe to execute remote/inline HTA script (signed-binary proxy)."),
    Rule("EXEC-RUNDLL32", "rundll32 proxy execution", EVASION, "T1218.011 Rundll32",
         MEDIUM, r"\brundll32(?:\.exe)?\b",
         "Uses rundll32.exe, frequently abused to proxy execution of code."),
    Rule("EXEC-REGSVR32", "regsvr32 (squiblydoo)", EVASION, "T1218.010 Regsvr32",
         HIGH, r"\bregsvr32(?:\.exe)?\b",
         "Uses regsvr32.exe, abused to run scriptlets while bypassing application control."),

    # Defense Evasion -----------------------------------------------------
    Rule("EVAS-HIDDEN", "Hidden window", EVASION, "T1564.003 Hidden Window",
         MEDIUM, r"-w(?:indowstyle)?\s+hidden|-windowstyle\s+hidden",
         "Runs with a hidden window to avoid drawing the user's attention."),
    Rule("EVAS-BYPASS", "Execution-policy bypass", EVASION, "T1059.001 PowerShell",
         MEDIUM, r"-e(?:x|p|xecutionpolicy)?\s+bypass|-ep\s+bypass|-exec\s+bypass",
         "Bypasses PowerShell execution policy to allow unsigned scripts to run."),
    Rule("EVAS-NOPROFILE", "No-profile / non-interactive", EVASION, "T1059.001 PowerShell",
         LOW, r"-nop\b|-noprofile\b|-noni\b|-noninteractive\b",
         "Suppresses profile/interactive prompts -- typical of automated payloads."),
    Rule("EVAS-ENCODED", "Encoded command", EVASION, "T1027 Obfuscated Files or Information",
         HIGH, r"-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{12,}",
         "Passes a base64-encoded command to hide its intent (decoded by the sandbox)."),
    Rule("EVAS-AMSI", "AMSI tampering", EVASION, "T1562.001 Disable or Modify Tools",
         CRITICAL, r"amsiInitFailed|AmsiUtils|amsi\.dll|System\.Management\.Automation\.AmsiUtils",
         "Attempts to neuter the Antimalware Scan Interface (AMSI)."),
    Rule("EVAS-DEFENDER", "Disable Microsoft Defender", EVASION, "T1562.001 Disable or Modify Tools",
         CRITICAL, r"Set-MpPreference\s+[^\n]*-Disable\w+|Add-MpPreference\s+[^\n]*-ExclusionPath|-DisableRealtimeMonitoring",
         "Disables Microsoft Defender real-time protection or adds an exclusion path."),
    Rule("EVAS-FIREWALL", "Disable firewall", EVASION, "T1562.004 Disable or Modify System Firewall",
         HIGH, r"netsh\s+advfirewall\s+set\s+\w+\s+state\s+off|Set-NetFirewallProfile\s+[^\n]*-Enabled\s+False",
         "Turns off the host firewall."),
    Rule("EVAS-CLEARLOG", "Clear event logs", EVASION, "T1070.001 Clear Windows Event Logs",
         HIGH, r"wevtutil\s+cl\b|Clear-EventLog\b|Remove-EventLog\b",
         "Clears Windows event logs to destroy forensic evidence."),
    Rule("EVAS-HIDEFILE", "Hide file attribute", EVASION, "T1564.001 Hidden Files and Directories",
         LOW, r"attrib\s+(?:\+[rsh]\s*)*\+h",
         "Marks a file hidden to keep it out of casual sight."),
    Rule("EVAS-UAC", "UAC bypass binary", PRIVESC, "T1548.002 Bypass User Account Control",
         HIGH, r"\b(?:fodhelper|eventvwr|computerdefaults|sdclt|slui|wsreset)(?:\.exe)?\b",
         "References a binary commonly abused to auto-elevate and bypass UAC."),
    Rule("PRIVESC-RUNAS", "Run as another user", PRIVESC, "T1134 Access Token Manipulation",
         MEDIUM, r"\brunas\s+/user:",
         "Attempts to run a command as a different (potentially privileged) user."),

    # Persistence -----------------------------------------------------------
    Rule("PERS-RUNKEY", "Run-key persistence", PERSISTENCE, "T1547.001 Registry Run Keys / Startup Folder",
         HIGH, r"(?:reg(?:\.exe)?\s+add|New-ItemProperty|Set-ItemProperty)[^\n]*(?:\\Run\b|\\RunOnce\b|CurrentVersion\\Run)",
         "Installs autostart persistence via a registry Run/RunOnce key."),
    Rule("PERS-SCHTASKS", "Scheduled task", PERSISTENCE, "T1053.005 Scheduled Task",
         HIGH, r"schtasks\s+/create|Register-ScheduledTask\b",
         "Creates a scheduled task for persistence or delayed execution."),
    Rule("PERS-STARTUP", "Startup folder drop", PERSISTENCE, "T1547.001 Startup Folder",
         HIGH, r"Start Menu\\Programs\\Startup|shell:startup",
         "Drops an artifact into the Startup folder for autostart on logon."),
    Rule("PERS-SERVICE", "Service creation", PERSISTENCE, "T1543.003 Windows Service",
         HIGH, r"\bsc(?:\.exe)?\s+create\b|New-Service\b",
         "Creates a Windows service for persistence or privileged execution."),
    Rule("PERS-WMI", "WMI event subscription", PERSISTENCE, "T1546.003 WMI Event Subscription",
         MEDIUM, r"Register-WmiEvent|__EventFilter|CommandLineEventConsumer",
         "Registers a WMI event subscription, a stealthy persistence mechanism."),
    Rule("PERS-LAUNCHAGENT", "LaunchAgent/Daemon persistence", PERSISTENCE, "T1543.001 Launch Agent",
         HIGH, r"~/Library/LaunchAgents|/Library/LaunchDaemons|launchctl\s+load",
         "Installs a macOS LaunchAgent/LaunchDaemon for persistence."),
    Rule("PERS-CRON", "Cron job persistence", PERSISTENCE, "T1053.003 Cron",
         HIGH, r"\bcrontab\s+-|/etc/cron|/var/spool/cron",
         "Adds a cron job for scheduled, persistent execution."),
    Rule("PERS-PROFILE", "Shell profile persistence", PERSISTENCE, "T1546.004 Unix Shell Configuration Modification",
         MEDIUM, r"\.(?:bash_profile|bashrc|zshrc|profile)\b",
         "Appends to a shell startup file so commands run on every new shell."),

    # Credential Access -------------------------------------------------------
    Rule("CRED-MIMIKATZ", "Mimikatz / credential dumping", CRED_ACCESS, "T1003.001 LSASS Memory",
         CRITICAL, r"\bmimikatz\b|sekurlsa::|lsadump::|Invoke-Mimikatz",
         "References Mimikatz or its credential-dumping modules."),
    Rule("CRED-LSASS", "LSASS memory dump", CRED_ACCESS, "T1003.001 LSASS Memory",
         CRITICAL, r"\blsass\.exe\b|comsvcs\.dll[^\n]*MiniDump|procdump[^\n]*lsass",
         "Attempts to dump the LSASS process to harvest credentials."),
    Rule("CRED-SAM", "SAM/SYSTEM hive dump", CRED_ACCESS, "T1003.002 Security Account Manager",
         CRITICAL, r"reg(?:\.exe)?\s+save\s+hklm\\(?:sam|system|security)",
         "Saves the SAM/SYSTEM/SECURITY registry hives for offline credential extraction."),
    Rule("CRED-DCSYNC", "DCSync", CRED_ACCESS, "T1003.006 DCSync",
         CRITICAL, r"lsadump::dcsync",
         "Performs a DCSync attack to replicate domain credential data."),
    Rule("CRED-BROWSER", "Browser credential access", CRED_ACCESS, "T1555.003 Credentials from Web Browsers",
         HIGH, r"Login Data|Local State|(?:Chrome|Edge|Firefox)[^\n]*(?:Login Data|cookies)",
         "Targets browser-stored credential/cookie databases."),
    Rule("CRED-VAULTCMD", "Windows Credential Manager", CRED_ACCESS, "T1555.004 Windows Credential Manager",
         HIGH, r"\bvaultcmd\b|cmdkey\s+/list",
         "Enumerates saved credentials from Windows Credential Manager."),
    Rule("CRED-WIFI-KEY", "Wi-Fi password recovery", CRED_ACCESS, "T1552 Unsecured Credentials",
         HIGH, r"netsh\s+wlan\s+show\s+profile[^\n]*key\s*=\s*clear",
         "Reveals the cleartext pre-shared key for a saved Wi-Fi profile."),

    # Discovery -------------------------------------------------------------
    Rule("DISC-SYSTEMINFO", "System information discovery", DISCOVERY, "T1082 System Information Discovery",
         INFO, r"\bsysteminfo\b|Get-ComputerInfo",
         "Collects general operating-system and hardware information."),
    Rule("DISC-WHOAMI", "User/privilege discovery", DISCOVERY, "T1033 System Owner/User Discovery",
         INFO, r"\bwhoami\b",
         "Identifies the current user and/or privilege level."),
    Rule("DISC-NETUSER", "Account/group discovery", DISCOVERY, "T1087 Account Discovery",
         LOW, r"\bnet\s+(?:user|localgroup)\b|Get-LocalGroupMember|Get-LocalUser",
         "Enumerates local user accounts or group membership (e.g. Administrators)."),
    Rule("DISC-NETWORK", "Network configuration discovery", DISCOVERY, "T1016 System Network Configuration Discovery",
         INFO, r"\bipconfig\b|\bifconfig\b|\barp\s+-a\b|\bnetstat\b",
         "Enumerates network interfaces, ARP cache, or active connections."),
    Rule("DISC-WIFI-LIST", "Wi-Fi profile enumeration", DISCOVERY, "T1016 System Network Configuration Discovery",
         LOW, r"netsh\s+wlan\s+show\s+profiles\b",
         "Lists the names of saved Wi-Fi network profiles."),
    Rule("DISC-AV", "Security software discovery", DISCOVERY, "T1518.001 Security Software Discovery",
         MEDIUM, r"Get-MpComputerStatus|securitycenter2|Get-MpThreatDetection",
         "Checks for installed antivirus/endpoint security products."),
    Rule("DISC-TASKLIST", "Process discovery", DISCOVERY, "T1057 Process Discovery",
         INFO, r"\btasklist\b|Get-Process\b|\bps\s+-ef\b|\bps\s+aux\b",
         "Lists running processes on the host."),

    # Lateral Movement --------------------------------------------------------
    Rule("LAT-PSEXEC", "PsExec-style remote execution", LATERAL, "T1021.002 SMB/Windows Admin Shares",
         HIGH, r"\b(?:ps|pa)exec(?:\.exe|64)?\b",
         "Uses PsExec-style tooling to execute commands on a remote host."),
    Rule("LAT-WMIC", "Remote WMI execution", LATERAL, "T1047 Windows Management Instrumentation",
         HIGH, r"wmic\s+/node:|Invoke-WmiMethod[^\n]*-ComputerName",
         "Invokes WMI against a remote computer to run commands."),
    Rule("LAT-PSREMOTE", "PowerShell remoting", LATERAL, "T1021.006 Windows Remote Management",
         HIGH, r"Enter-PSSession|New-PSSession|Invoke-Command[^\n]*-ComputerName",
         "Establishes a remote PowerShell session on another host."),

    # Collection ---------------------------------------------------------------
    Rule("COLL-CLIP", "Clipboard access", COLLECTION, "T1115 Clipboard Data",
         MEDIUM, r"Get-Clipboard|\bclip(?:\.exe)?\b",
         "Reads or writes the contents of the system clipboard."),
    Rule("COLL-SCREENSHOT", "Screen capture", COLLECTION, "T1113 Screen Capture",
         HIGH, r"CopyFromScreen|\[Drawing\.Bitmap\]|Graphics]::FromImage",
         "Captures an image of the screen."),
    Rule("COLL-KEYLOG", "Keystroke logging", COLLECTION, "T1056.001 Keylogging",
         CRITICAL, r"GetAsyncKeyState|SetWindowsHookEx",
         "Installs a low-level hook to record keystrokes."),

    # Command and Control --------------------------------------------------------
    Rule("C2-IWR", "Web request download", C2, "T1105 Ingress Tool Transfer",
         MEDIUM, r"Invoke-WebRequest|\biwr\b|Invoke-RestMethod|\bcurl\b|\bwget\b",
         "Downloads content from a remote URL onto the host."),
    Rule("C2-WEBCLIENT", "WebClient download/execute", C2, "T1105 Ingress Tool Transfer",
         HIGH, r"Net\.WebClient|DownloadString|DownloadFile|DownloadData",
         "Uses .NET WebClient to fetch (and often immediately execute) remote content."),
    Rule("C2-CERTUTIL", "certutil download (LOLBin)", C2, "T1105 Ingress Tool Transfer",
         HIGH, r"certutil(?:\.exe)?\s+[^\n]*-urlcache",
         "Abuses certutil.exe to download a file from the internet."),
    Rule("C2-BITSADMIN", "BITS job download", C2, "T1197 BITS Jobs",
         HIGH, r"bitsadmin\s+/transfer|Start-BitsTransfer",
         "Uses the Background Intelligent Transfer Service to fetch a file."),
    Rule("C2-REVSHELL-TCP", "Reverse shell (TCP socket)", C2, "T1059 Command and Scripting Interpreter",
         CRITICAL, r"Net\.Sockets\.TCPClient|System\.Net\.Sockets\.TcpClient",
         "Opens a raw TCP socket back to an attacker, characteristic of a reverse shell."),
    Rule("C2-REVSHELL-BASH", "Reverse shell (bash /dev/tcp)", C2, "T1059.004 Unix Shell",
         CRITICAL, r"/dev/tcp/|nc\s+-e\s|ncat\s+-e\s|/bin/sh\s+>&\s*/dev/tcp",
         "Uses a bash /dev/tcp redirection or netcat -e to spawn a reverse shell."),

    # Exfiltration -------------------------------------------------------------
    Rule("EXFIL-FTP", "FTP upload", EXFIL, "T1048 Exfiltration Over Alternative Protocol",
         MEDIUM, r"\bftp\s+-s:|Net\.FtpWebRequest|UploadFile",
         "Uploads data to a remote host via FTP."),
    Rule("EXFIL-MAIL", "Email exfiltration", EXFIL, "T1048 Exfiltration Over Alternative Protocol",
         MEDIUM, r"Send-MailMessage|smtp\.",
         "Sends data out via SMTP/email."),
    Rule("EXFIL-DISCORD", "Discord webhook exfiltration", EXFIL, "T1567.001 Exfiltration to Code Repository/Webhook",
         HIGH, r"discord(?:app)?\.com/api/webhooks",
         "Posts data to a Discord webhook, a popular low-noise exfil channel."),
    Rule("EXFIL-TELEGRAM", "Telegram bot exfiltration", EXFIL, "T1567 Exfiltration Over Web Service",
         HIGH, r"api\.telegram\.org/bot",
         "Sends data to a Telegram bot API endpoint."),

    # Impact -------------------------------------------------------------------
    Rule("IMPACT-SHADOWCOPY", "Delete shadow copies", IMPACT, "T1490 Inhibit System Recovery",
         CRITICAL, r"vssadmin\s+delete\s+shadows|Get-WmiObject\s+[^\n]*ShadowCopy[^\n]*\.Delete|wmic\s+shadowcopy\s+delete",
         "Deletes Volume Shadow Copies, removing a common recovery path (ransomware precursor)."),
    Rule("IMPACT-CIPHER", "Secure-wipe free space", IMPACT, "T1485 Data Destruction",
         HIGH, r"cipher\s+/w",
         "Overwrites deleted data so it cannot be recovered."),
    Rule("IMPACT-BCDEDIT", "Disable recovery options", IMPACT, "T1490 Inhibit System Recovery",
         CRITICAL, r"bcdedit[^\n]*recoveryenabled\s+no|bcdedit[^\n]*bootstatuspolicy\s+ignoreallfailures",
         "Disables Windows recovery/repair options at boot."),
    Rule("IMPACT-DELETE", "Mass file deletion", IMPACT, "T1485 Data Destruction",
         CRITICAL, r"\bdel\b(?=[^\n]*\s/f\b)(?=[^\n]*\s/s\b)(?=[^\n]*\s/q\b)(?:\s+/[a-z]\b)*"
                   r"|Remove-Item(?=[^\n]*-Recurse)(?=[^\n]*-Force)|\brm\s+-(?=\w*r)\w*f\w*\s",
         "Recursively and forcibly deletes files/directories without confirmation."),
    Rule("IMPACT-DISKPART", "Disk wipe via diskpart", IMPACT, "T1561.002 Disk Structure Wipe",
         CRITICAL, r"diskpart[^\n]*\bclean\b",
         "Uses diskpart to wipe a disk's partition table."),
]


# -- IOC / artefact extraction ----------------------------------------------

_URL_RE = re.compile(r"(?:https?|ftp)://[^\s'\"<>|)\]]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_IP_PORT_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})[\s:,]+(\d{2,5})\b")
_DEVTCP_RE = re.compile(r"/dev/tcp/([^/\s'\"]+)/(\d{1,5})", re.IGNORECASE)
_ENCODED_RE = re.compile(r"-e(?:nc|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,})", re.IGNORECASE)

# Redirection: one or two '>' characters followed by a destination path.
_REDIRECT_RE = re.compile(r"(>{1,2})\s*([^\s|&;<>]+)")
_OUTFILE_RE = re.compile(r"Out-File\s+(?:-FilePath\s+)?(-Append\s+)?(?:-Encoding\s+\S+\s+)?([^\s|&;]+)", re.I)
_SETCONTENT_RE = re.compile(r"(Set-Content|Add-Content)\s+(?:-Path\s+)?([^\s|&;]+)", re.I)
_NEWITEM_RE = re.compile(r"New-Item\s+(?:-Path\s+)?([^\s|&;]+?)(?:\s+-ItemType\s+\S+)?(?:\s|$)", re.I)
_DELETE_FILE_RE = re.compile(r"(?:Remove-Item|del|erase)\s+(?:-Path\s+)?(?:(?:/|-)[a-zA-Z]+\s+)*([^\s|&;]+)", re.I)
_COPY_RE = re.compile(r"(?:Copy-Item|copy|xcopy)\s+([^\s|&;]+)\s+([^\s|&;]+)", re.I)
_CERTUTIL_RE = re.compile(r"certutil(?:\.exe)?\s+[^\n]*-urlcache[^\n]*\s(\S+)\s*$", re.I)

_REG_ADD_RE = re.compile(
    r"reg(?:\.exe)?\s+add\s+(\"[^\"]+\"|\S+)[^\n]*?/v\s+(\"[^\"]+\"|\S+)[^\n]*?/d\s+(\"[^\"]+\"|\S+)", re.I)
_REG_DELETE_RE = re.compile(r"reg(?:\.exe)?\s+delete\s+(\"[^\"]+\"|\S+)(?:\s+/v\s+(\"[^\"]+\"|\S+))?", re.I)
_ITEMPROP_RE = re.compile(
    r"(New|Set)-ItemProperty\s+(?:-Path\s+)?(\"[^\"]+\"|\S+)[^\n]*?-Name\s+(\"[^\"]+\"|\S+)[^\n]*?-Value\s+(\"[^\"]+\"|\S+)",
    re.I)

# Binaries that, when seen, represent a new child process being launched.
PROCESS_RULE_NAMES = {
    "EXEC-PS": "powershell.exe",
    "EXEC-CMD": "cmd.exe",
    "EXEC-WSCRIPT": "wscript.exe",
    "EXEC-BASH": "bash",
    "EXEC-OSASCRIPT": "osascript",
    "EXEC-MSHTA": "mshta.exe",
    "EXEC-RUNDLL32": "rundll32.exe",
    "EXEC-REGSVR32": "regsvr32.exe",
    "LAT-PSEXEC": "psexec.exe",
}

# Subset of the above that represent an interactive shell a payload can keep
# typing further commands into (used to build the modelled process tree).
INTERACTIVE_SHELLS = {"cmd.exe", "powershell.exe", "bash", "pwsh"}


def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


def decode_encoded_commands(text: str) -> list[str]:
    """Decode any ``-EncodedCommand <base64>`` arguments found in *text*.

    PowerShell's ``-EncodedCommand`` is base64 of UTF-16LE text. Returns a list
    of decoded strings (possibly empty). Decoding failures are ignored.
    """
    out: list[str] = []
    for m in _ENCODED_RE.finditer(text):
        token = m.group(1)
        # Trim to a multiple of 4 to tolerate trailing garbage captured by the regex.
        token = token[: len(token) - (len(token) % 4)] if len(token) % 4 else token
        try:
            raw = base64.b64decode(token, validate=False)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded = raw.decode("utf-16le")
        except UnicodeDecodeError:
            decoded = raw.decode("utf-8", errors="replace")
        decoded = decoded.strip("\x00").strip()
        if decoded:
            out.append(decoded)
    return out


def _record_network_iocs(text: str, lineno: int, vmstate: VMState) -> None:
    seen_spans: set[tuple[int, int]] = set()

    for m in _URL_RE.finditer(text):
        url = m.group(0).rstrip(".,;)")
        seen_spans.add(m.span())
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else 21)
        vmstate.iocs["urls"].add(url)
        if host:
            if _IPV4_RE.fullmatch(host):
                vmstate.iocs["ips"].add(host)
            else:
                vmstate.iocs["domains"].add(host)
        vmstate.record_network(lineno, host, port, protocol=parsed.scheme or "tcp",
                                detail=f"GET {url}")

    for m in _IP_PORT_RE.finditer(text):
        if m.span() in seen_spans or any(s <= m.start() < e for s, e in seen_spans):
            continue
        host, port = m.group(1), int(m.group(2))
        vmstate.iocs["ips"].add(host)
        vmstate.record_network(lineno, host, port, protocol="tcp",
                                detail="raw socket connection")

    for m in _DEVTCP_RE.finditer(text):
        host, port = m.group(1), int(m.group(2))
        if _IPV4_RE.fullmatch(host):
            vmstate.iocs["ips"].add(host)
        else:
            vmstate.iocs["domains"].add(host)
        vmstate.record_network(lineno, host, port, protocol="tcp",
                                detail="/dev/tcp reverse shell")


def _record_file_ops(text: str, lineno: int, vmstate: VMState) -> None:
    for m in _REDIRECT_RE.finditer(text):
        op = "append" if m.group(1) == ">>" else "write"
        path = _strip_quotes(m.group(2))
        if path and not path.startswith(("&", "1", "2")):
            vmstate.record_file(lineno, path, op, detail="shell redirection")

    for m in _OUTFILE_RE.finditer(text):
        op = "append" if m.group(1) else "write"
        vmstate.record_file(lineno, _strip_quotes(m.group(2)), op, detail="Out-File")

    for m in _SETCONTENT_RE.finditer(text):
        op = "append" if m.group(1).lower() == "add-content" else "write"
        vmstate.record_file(lineno, _strip_quotes(m.group(2)), op, detail=m.group(1))

    for m in _NEWITEM_RE.finditer(text):
        vmstate.record_file(lineno, _strip_quotes(m.group(1)), "create", detail="New-Item")

    for m in _COPY_RE.finditer(text):
        src, dst = _strip_quotes(m.group(1)), _strip_quotes(m.group(2))
        vmstate.record_file(lineno, dst, "copy", detail=f"copied from {src}")

    for m in _DELETE_FILE_RE.finditer(text):
        path = _strip_quotes(m.group(1))
        if path:
            vmstate.record_file(lineno, path, "delete", detail="deleted")

    for m in _CERTUTIL_RE.finditer(text):
        path = _strip_quotes(m.group(1))
        if path and not path.lower().startswith(("http://", "https://", "-")):
            vmstate.record_file(lineno, path, "download_write", detail="certutil -urlcache")


def _record_registry_ops(text: str, lineno: int, vmstate: VMState) -> None:
    for m in _REG_ADD_RE.finditer(text):
        key, value, data = (_strip_quotes(g) for g in m.groups())
        vmstate.record_registry(lineno, key, value, data, operation="set")

    for m in _REG_DELETE_RE.finditer(text):
        key = _strip_quotes(m.group(1))
        value = _strip_quotes(m.group(2)) if m.group(2) else ""
        vmstate.record_registry(lineno, key, value, operation="delete")

    for m in _ITEMPROP_RE.finditer(text):
        _verb, key, value, data = m.groups()
        vmstate.record_registry(lineno, _strip_quotes(key), _strip_quotes(value),
                                 _strip_quotes(data), operation="set")


def _record_process_ops(text: str, lineno: int, vmstate: VMState,
                         findings: list[Finding], parent: str) -> None:
    seen: set[str] = set()
    for f in findings:
        name = PROCESS_RULE_NAMES.get(f.rule_id)
        if name and name not in seen:
            seen.add(name)
            integrity = "high" if any(x.tactic == PRIVESC for x in findings) else "medium"
            vmstate.record_process(lineno, name, cmdline=text.strip(),
                                    parent=parent, integrity=integrity)


def highest_severity(findings: list[Finding]) -> str:
    if not findings:
        return INFO
    return max((f.severity for f in findings), key=lambda s: SEVERITY_RANK.get(s, 0))


def analyze_command(text: str, lineno: int, vmstate: VMState,
                     parent: str = "explorer.exe", _depth: int = 0) -> list[Finding]:
    """Analyse a reconstructed command line, mutating *vmstate* in place.

    Returns the list of :class:`Finding` objects produced for *text* (including
    any decoded sub-commands).
    """
    findings: list[Finding] = []
    for rule in RULES:
        m = rule.regex.search(text)
        if m:
            evidence = m.group(0)
            if len(evidence) > 120:
                evidence = evidence[:117] + "..."
            findings.append(Finding(rule.rule_id, rule.title, rule.tactic, rule.technique,
                                     rule.severity, evidence, lineno, rule.explanation))

    _record_network_iocs(text, lineno, vmstate)
    _record_file_ops(text, lineno, vmstate)
    _record_registry_ops(text, lineno, vmstate)
    _record_process_ops(text, lineno, vmstate, findings, parent)

    if _depth < 3:
        for decoded in decode_encoded_commands(text):
            preview = decoded if len(decoded) <= 200 else decoded[:200] + "..."
            vmstate.add_note(f"Line {lineno}: decoded base64 -EncodedCommand payload: {preview}")
            findings.extend(analyze_command(decoded, lineno, vmstate, parent="powershell.exe",
                                              _depth=_depth + 1))

    return findings
