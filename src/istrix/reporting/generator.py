"""Professional report generation engine for iStrix.

Supports single-host and multi-host (aggregate) reports across four levels:
  brief        – Score, severity legend, risk profile, host summary
  detail       – Brief + full findings table per host
  threat       – Detail + threat cards with CVE paragraphs
  remediation  – Detail findings table + remediation actions (no threat cards)
"""

import json as _std_json
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape

from istrix.models.finding import Finding
from istrix.models.risk import RiskProfile
from istrix.models.scan import ScanConfig, ScanResult
from istrix.reporting.json_export import load_from_json
from istrix.reporting.remediation import generate_remediation_commands

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BRANDING_PATH = Path(__file__).parent.parent.parent.parent / "config" / "branding.yaml"
VULNDB_PATH = Path(__file__).parent.parent.parent.parent / "config" / "vulndb.yaml"
TEMPLATES_DIR = Path(__file__).parent / "templates"

# ---------------------------------------------------------------------------
# Severity sort key
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ──────────────────────────────────────────────────────────────────────────────
# ReportConfig
# ──────────────────────────────────────────────────────────────────────────────


class ReportConfig:
    """Configuration for a report generation run.

    Accepts a **list** of JSON result paths so that multiple host scans can be
    aggregated into a single report.  A single-element list produces a
    per-host report (backward-compatible with the pre-2.0 API).
    """

    def __init__(
        self,
        results_paths: list[str],
        level: str = "detail",
        output_format: str = "html",
        output_dir: str = ".",
        customer_name: str = "",
        site_name: str = "",
        scan_notes: str = "",
        branding_path: str | None = None,
        risk_profile: RiskProfile | None = None,
    ):
        self.results_paths = [Path(p) for p in results_paths]
        self.level = level  # brief | detail | threat | remediation
        self.output_format = output_format  # html | pdf | md | json
        self.output_dir = Path(output_dir)
        self.customer_name = customer_name
        self.site_name = site_name
        self.scan_notes = scan_notes
        self.report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.branding = self._load_branding(branding_path)
        self.risk_profile = risk_profile or RiskProfile()

    @property
    def is_aggregate(self) -> bool:
        """True when more than one result file is provided."""
        return len(self.results_paths) > 1

    def _load_branding(self, path: str | None = None) -> dict:
        p = Path(path) if path else BRANDING_PATH
        try:
            with open(p) as f:
                return yaml.safe_load(f)
        except Exception:
            return {
                "company": {"name": "Security Assessment"},
                "colors": {},
                "report_stationery": {},
            }


# ──────────────────────────────────────────────────────────────────────────────
# Host-level data container (internal helper)
# ──────────────────────────────────────────────────────────────────────────────


class _HostData:
    """Pre-computed data for a single host used in aggregate reports."""

    __slots__ = (
        "host_id", "result", "os", "hardware", "findings",
        "threats", "sev_counts", "score", "score_label", "score_color",
    )

    def __init__(
        self,
        host_id: str,
        result: ScanResult,
        os_name: str,
        hardware: str = "",
        findings: list[Finding] = None,
        threats: list[dict] = None,
        sev_counts: dict[str, int] = None,
        score: int = 0,
        label: str = "",
        color: str = "",
    ):
        self.host_id = host_id
        self.result = result
        self.os = os_name
        self.hardware = hardware
        self.findings = findings or []
        self.threats = threats or []
        self.sev_counts = sev_counts or {}
        self.score = score
        self.score_label = label
        self.score_color = color


# ──────────────────────────────────────────────────────────────────────────────
# ReportGenerator
# ──────────────────────────────────────────────────────────────────────────────


class ReportGenerator:
    """Generates professional pentest reports at multiple levels.

    Handles both single-host and multi-host aggregate reports transparently.
    """

    # ------------------------------------------------------------------
    # Static knowledge bases (kept exactly as in previous versions)
    # ------------------------------------------------------------------

    REMEDIATION_OS_ADVICE = {
        "Linux": {
            "ssh": (
                "Upgrade OpenSSH: `apt upgrade openssh-server` or "
                "`yum update openssh-server`. Minimum version: 9.8."
            ),
            "nginx": (
                "Upgrade nginx: `apt upgrade nginx` or `yum update nginx`. "
                "Minimum version: 1.26.0."
            ),
            "nfs": (
                "Restrict NFS exports in /etc/exports with client IPs and "
                "root_squash. Use `exportfs -ra` to reload."
            ),
            "rpcbind": (
                "Disable if NFS not needed: `systemctl disable rpcbind`. "
                "Otherwise restrict with firewall."
            ),
            "http": (
                "Apply latest web server patches: `apt upgrade apache2` or `yum update httpd`. "
                "Review virtual host configs, disable directory listing, enable TLS 1.2+."
            ),
            "dns": (
                "Apply BIND patches: `apt upgrade bind9` or `yum update bind`. "
                "Enable DNSSEC, restrict zone transfers, limit recursion to authorized clients."
            ),
            "snmp": (
                "Disable SNMP if not needed: `systemctl disable snmpd`. "
                "Otherwise configure SNMPv3 with authPriv and restrict with firewall."
            ),
            "general": (
                "Run `apt update && apt upgrade -y` or `yum update -y`. "
                "Enable automatic security updates."
            ),
        },
        "Oracle Linux": {
            "ssh": (
                "Upgrade OpenSSH: `dnf update openssh-server -y`. "
                "Minimum version: 9.8. Restart: `systemctl restart sshd`."
            ),
            "nginx": (
                "Upgrade nginx: `dnf update nginx -y`. "
                "Minimum version: 1.26.0. Reload: `nginx -s reload`."
            ),
            "nfs": (
                "Restrict NFS exports in /etc/exports with client IPs and "
                "root_squash. Use `exportfs -ra` to reload."
            ),
            "rpcbind": (
                "Disable if NFS not needed: `systemctl disable rpcbind`. "
                "Otherwise restrict with firewall."
            ),
            "http": (
                "Apply latest web server patches: `dnf update httpd -y`. "
                "Review virtual host configs, disable directory listing, enable TLS 1.2+."
            ),
            "dns": (
                "Apply BIND patches: `dnf update bind -y`. "
                "Enable DNSSEC, restrict zone transfers, limit recursion to authorized clients."
            ),
            "snmp": (
                "Disable SNMP if not needed: `systemctl disable snmpd`. "
                "Otherwise configure SNMPv3 with authPriv and restrict with firewall."
            ),
            "general": (
                "Run `dnf update -y`. Enable automatic security updates: "
                "`dnf install dnf-automatic -y && systemctl enable --now dnf-automatic.timer`."
            ),
        },
        "Rocky Linux": {
            "ssh": "Upgrade OpenSSH: `dnf update openssh-server -y`. Restart: `systemctl restart sshd`.",
            "nginx": "Upgrade nginx: `dnf update nginx -y`. Reload: `nginx -s reload`.",
            "nfs": "Restrict NFS exports in /etc/exports. Use `exportfs -ra` to reload.",
            "rpcbind": "Disable if NFS not needed: `systemctl disable rpcbind`.",
            "http": "Apply patches: `dnf update httpd -y`. Review virtual host configs.",
            "dns": "Apply patches: `dnf update bind -y`. Restrict zone transfers.",
            "general": "Run `dnf update -y`. Enable automatic updates via dnf-automatic.",
        },
        "CentOS": {
            "ssh": "Upgrade OpenSSH: `dnf update openssh-server -y`. Restart: `systemctl restart sshd`.",
            "nginx": "Upgrade nginx: `dnf update nginx -y`. Reload: `nginx -s reload`.",
            "nfs": "Restrict NFS exports in /etc/exports. Use `exportfs -ra` to reload.",
            "rpcbind": "Disable if NFS not needed: `systemctl disable rpcbind`.",
            "http": "Apply patches: `dnf update httpd -y`. Review virtual host configs.",
            "dns": "Apply patches: `dnf update bind -y`. Restrict zone transfers.",
            "general": "Run `dnf update -y`. Enable dnf-automatic for security updates.",
        },
        "AlmaLinux": {
            "ssh": "Upgrade OpenSSH: `dnf update openssh-server -y`. Restart: `systemctl restart sshd`.",
            "nginx": "Upgrade nginx: `dnf update nginx -y`. Reload: `nginx -s reload`.",
            "nfs": "Restrict NFS exports in /etc/exports. Use `exportfs -ra` to reload.",
            "rpcbind": "Disable if NFS not needed: `systemctl disable rpcbind`.",
            "http": "Apply patches: `dnf update httpd -y`. Review virtual host configs.",
            "dns": "Apply patches: `dnf update bind -y`. Restrict zone transfers.",
            "general": "Run `dnf update -y`. Enable automatic updates via dnf-automatic.",
        },
        "Red Hat Enterprise Linux": {
            "ssh": "Upgrade OpenSSH: `dnf update openssh-server -y`. Restart: `systemctl restart sshd`.",
            "nginx": "Upgrade nginx: `dnf update nginx -y`. Reload: `nginx -s reload`.",
            "nfs": "Restrict NFS exports in /etc/exports. Use `exportfs -ra` to reload.",
            "rpcbind": "Disable if NFS not needed: `systemctl disable rpcbind`.",
            "http": "Apply patches: `dnf update httpd -y`. Review virtual host configs.",
            "dns": "Apply patches: `dnf update bind -y`. Restrict zone transfers.",
            "general": "Run `dnf update -y`. Red Hat subscriptions: check via `subscription-manager`.",
        },
        "RHEL": {
            "ssh": "Upgrade OpenSSH: `dnf update openssh-server -y`. Restart: `systemctl restart sshd`.",
            "nginx": "Upgrade nginx: `dnf update nginx -y`. Reload: `nginx -s reload`.",
            "nfs": "Restrict NFS exports in /etc/exports. Use `exportfs -ra` to reload.",
            "rpcbind": "Disable if NFS not needed: `systemctl disable rpcbind`.",
            "http": "Apply patches: `dnf update httpd -y`. Review virtual host configs.",
            "dns": "Apply patches: `dnf update bind -y`. Restrict zone transfers.",
            "general": "Run `dnf update -y`. Enable automatic updates via dnf-automatic.",
        },
        "Linux (RHEL-family)": {
            "ssh": "Upgrade OpenSSH: `dnf update openssh-server -y`. Restart: `systemctl restart sshd`.",
            "nginx": "Upgrade nginx: `dnf update nginx -y`. Reload: `nginx -s reload`.",
            "nfs": "Restrict NFS exports in /etc/exports. Use `exportfs -ra` to reload.",
            "rpcbind": "Disable if NFS not needed: `systemctl disable rpcbind`.",
            "http": "Apply patches: `dnf update httpd -y`. Review virtual host configs.",
            "dns": "Apply patches: `dnf update bind -y`. Restrict zone transfers.",
            "general": "Run `dnf update -y`. Enable automatic updates via dnf-automatic.",
        },
        "Windows": {
            "ssh": "Upgrade OpenSSH via Windows Update or download from GitHub/PowerShell.",
            "smb": (
                "Disable SMBv1: `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`. "
                "Enforce SMB signing: Set-SmbServerConfiguration -EnableSecuritySignature $true. "
                "Restrict SMB to necessary hosts via Windows Firewall."
            ),
            "rdp": (
                "Enable Network Level Authentication (NLA): System Properties → Remote → "
                "'Allow connections only from computers running Remote Desktop with NLA'. "
                "Restrict RDP via Windows Firewall to specific management IPs."
            ),
            "http": (
                "Apply latest IIS security patches via Windows Update. "
                "Enable request filtering, remove unnecessary modules, use HTTPS with TLS 1.2+. "
                "Run `Get-WindowsFeature Web-*` to audit installed IIS components."
            ),
            "dns": (
                "Apply DNS Server patches via Windows Update. "
                "Enable DNSSEC validation, restrict zone transfers, enable DNS query logging."
            ),
            "snmp": (
                "Disable SNMP if not needed: `Remove-WindowsFeature SNMP-Service`. "
                "Otherwise configure SNMPv3 with authentication and encryption."
            ),
            "general": (
                "Run Windows Update. Enable Windows Defender Firewall. "
                "Review service accounts. Apply latest cumulative updates and security patches."
            ),
        },
        "Cisco IOS": {
            "ssh": (
                "Upgrade Cisco IOS via `software install` or `request system software add`. "
                "Verify with `show version`. Ensure SSH is enabled with `ip ssh version 2` "
                "and `crypto key generate rsa modulus 2048`."
            ),
            "snmp": (
                "Disable SNMP if not needed: `no snmp-server`. Otherwise restrict to read-only "
                "with strong community strings or SNMPv3: `snmp-server community <string> RO <acl>`."
            ),
            "general": (
                "Review Cisco IOS version against Cisco Security Advisories (PSIRTs). "
                "Upgrade via `software install file flash:<image.bin> activate commit`. "
                "Disable unused services: `no ip http-server`, `no ip finger`, `no service telnet`. "
                "Enable AAA: `aaa new-model` and configure TACACS+/RADIUS authentication."
            ),
        },
        "Cisco Device": {
            "ssh": (
                "Verify firmware/OS version against Cisco advisories. Upgrade via platform method. "
                "Disable SSH v1: `ip ssh version 2`."
            ),
            "general": (
                "Review device against Cisco Security Advisories. Upgrade firmware/OS. "
                "Disable unused management services. Enable AAA and strong authentication."
            ),
        },
        "Juniper JunOS": {
            "ssh": (
                "Upgrade JunOS via `request system software add`. Verify with `show version`. "
                "Enable strong SSH: `set system services ssh protocol-version v2`."
            ),
            "general": (
                "Review Juniper Security Advisories. Upgrade via `request system software add <image>`. "
                "Disable unused services: `delete system services telnet`, `delete system services web-management`."
            ),
        },
        "HP iLO": {
            "ssh": (
                "Update iLO firmware via HP Service Pack for ProLiant (SPP) or HP SUM. "
                "Disable SSH if not needed via iLO web interface."
            ),
            "general": (
                "Update iLO firmware to the latest version from HPE Support Center. "
                "Disable unused management protocols. Rotate default credentials. "
                "Enable iLO security features (AES/CCM encryption)."
            ),
        },
        "Dell iDRAC": {
            "ssh": (
                "Update iDRAC firmware via Dell's iDRAC Update Utility or Lifecycle Controller. "
                "Disable SSH if not needed via iDRAC Settings → Services."
            ),
            "general": (
                "Update iDRAC firmware via Dell Support. Disable unused management protocols. "
                "Rotate default credentials (root/calvin). Restrict access via iDRAC IP filtering."
            ),
        },
        "VMware ESXi": {
            "ssh": (
                "Update ESXi via `esxcli software profile update`. Verify with `vmware -v`. "
                "Disable SSH if not needed: `vim-cmd hostsvc/advopt/update UserVars.SuppressShellWarning long 0`."
            ),
            "general": (
                "Apply latest VMware ESXi patches via vSphere Lifecycle Manager. "
                "Review against VMware Security Advisories (VMSA). Disable shell/SSH when not in use. "
                "Enable Lockdown Mode for production hosts."
            ),
        },
        "unknown": {
            "general": (
                "Apply latest vendor security patches. Review exposed services "
                "and disable unnecessary ones."
            ),
        },
    }

    _vulndb_cache: dict | None = None

    def _load_vulndb(self) -> dict:
        """Load vulnerability knowledge base from YAML, with caching."""
        if self._vulndb_cache is not None:
            return self._vulndb_cache
        try:
            with open(VULNDB_PATH) as f:
                data = yaml.safe_load(f)
            vulns = data.get("vulnerabilities", {}) if data else {}
            self._vulndb_cache = vulns
        except Exception:
            self._vulndb_cache = {}
        return self._vulndb_cache

    _DEFAULT_THREAT = {
        "title": None,
        "cvss": "N/A",
        "vector": "N/A",
        "summary": (
            "This CVE was identified by the Vulners NSE script during the scan. "
            "Refer to the NVD link for full details and the latest CVSS score. "
            "The finding indicates a known vulnerability exists in the detected software version."
        ),
        "exploit_narrative": (
            "This vulnerability was flagged by automated detection during the scan. "
            "Without a specific knowledge-base entry the exact exploitation mechanics "
            "cannot be detailed here, but any CVE appearing in a live scan result "
            "represents a published, verifiable weakness. Attackers may leverage "
            "publicly available exploit code or proof-of-concept research to target "
            "this flaw. The practical impact depends on the CVSS vector — consult "
            "the NVD link below for the official assessment and attack-scenario analysis."
        ),
        "commands": [],
    }

    # ------------------------------------------------------------------
    # Constructor
    # ------------------------------------------------------------------

    def __init__(self, config: ReportConfig):
        self.config = config
        # Load one ScanResult per file; track host-id (IP/hostname from first finding)
        self._raw_results: list[tuple[str, ScanResult]] = []
        for path in config.results_paths:
            sr = load_from_json(path)
            host = self._resolve_host(sr, path)
            self._raw_results.append((host, sr))
        # is_aggregate: multiple files OR single file with multi-host data
        if config.is_aggregate:
            self.is_aggregate = True
        else:
            hosts: set[str] = set()
            for _, sr in self._raw_results:
                for f in sr.findings:
                    if f.host:
                        hosts.add(f.host)
            self.is_aggregate = len(hosts) > 1
        self.env = self._setup_jinja()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_host(result: ScanResult, path: Path) -> str:
        """Heuristically derive a display host-id from findings or filename."""
        for f in result.findings:
            if f.host:
                return f.host
        return path.stem

    @staticmethod
    @staticmethod
    def _detect_os(findings: list[Finding]) -> str:
        """Detect OS from findings (per-host) with version where available.

        Network devices (Cisco, Juniper, Arista) are detected before Linux/Windows
        to prevent IOS-XE (Linux kernel) devices from being misclassified.
        """
        import re
        # 0. Early network device detection (Cisco/Juniper/Arista)
        #    Must run BEFORE nmap OS detection which reports IOS-XE as "Linux".
        for f in findings:
            if f.type == "service":
                d = f.detail.lower() + " " + (f.evidence or "").lower()
                # Cisco IOS SSH: "Service: ssh Cisco SSH 1.25"
                # Cisco telnet: "Service: telnet Cisco router telnetd"
                if "cisco" in d and ("ssh" in d or "telnet" in d or "ios" in d):
                    return "Cisco IOS"
                if "cisco" in d:
                    return "Cisco Device"
                # Juniper
                if "juniper" in d or "junos" in d:
                    return "Juniper JunOS"
                # Arista
                if "arista" in d or "eos" in d:
                    return "Arista EOS"
                # Brocade / Ruckus
                if "brocade" in d or ("ruckus" in d and ("switch" in d or "router" in d)):
                    return "Brocade/Ruckus Device"
                # DVR/NVR surveillance recorders — detect before server Linux
                if "security dvr telnetd" in d or "dvr telnetd" in d:
                    return "DVR (Embedded Surveillance)"
                if "nvr" in d and ("telnetd" in d or "httpd" in d):
                    return "NVR (Embedded Surveillance)"
                if "cross dvr httpd" in d:
                    return "DVR (Embedded Surveillance)"
                # VMware ESXi — detect before server Linux
                if "vmware esxi" in d or "esxi server httpd" in d:
                    return "VMware ESXi"
                # IP Camera — detect before server Linux
                if "hikvision" in d or "hik ipcam" in d or "ipcam" in d:
                    return "IP Camera (Embedded)"
                # Firewalls — explicit service match
                if "watchguard" in d:
                    return "WatchGuard Firewall"
                if "fortinet" in d or "fortigate" in d:
                    return "Fortinet FortiGate"
                if "palo alto" in d or "panorama" in d:
                    return "Palo Alto Firewall"
                if "sonicwall" in d:
                    return "SonicWall Firewall"
        # 1. LDAP RootDSE — most accurate Windows Server detection
        for f in findings:
            if f.type == "os" and f.source == "ldap-rootdse":
                d = f.detail
                m = re.search(r'AD:\s*(.+?)\s*\(functional level', d)
                if m:
                    os_name = m.group(1).strip()
                    domain = ReportGenerator._extract_windows_domain(findings)
                    if domain:
                        return f"{os_name} ({domain})"
                    return os_name
        for f in findings:
            if f.type == "os" and f.source == "ldap-rootdse":
                # Fallback: parse full detail
                if "AD:" in f.detail and "Windows" in f.detail:
                    return f.detail.replace("AD: ", "")
        # 1.5 Nmap OS findings (fallback, less accurate)
        for f in findings:
            if f.type == "os":
                d = f.detail
                m = re.search(r'OS:\s*(.*?)\s*\(accuracy:', d)
                if m:
                    os_name = m.group(1).strip()
                    if "linux" in os_name.lower():
                        has_net_device = any(
                            "cisco" in (sf.detail or "").lower() or
                            "juniper" in (sf.detail or "").lower()
                            for sf in findings if sf.type == "service"
                        )
                        if has_net_device:
                            continue
                    return os_name
                if "windows" in d.lower():
                    return "Windows"
                if "linux" in d.lower():
                    has_net_device = any(
                        "cisco" in (sf.detail or "").lower() or
                        "juniper" in (sf.detail or "").lower()
                        for sf in findings if sf.type == "service"
                    )
                    if not has_net_device:
                        return "Linux"
        # 2. IIS version — accurate Windows Server indicator
        for f in findings:
            if f.type == "service" and "iis" in (f.detail or "").lower():
                m = re.search(r'IIS httpd\s+(\d+\.\d+)', f.detail)
                if m:
                    iis_ver = float(m.group(1))
                    win_ver = {
                        10.0: "Windows Server 2016/2019",
                        8.5: "Windows Server 2012 R2",
                        8.0: "Windows Server 2012",
                        7.5: "Windows Server 2008 R2",
                        7.0: "Windows Server 2008",
                    }.get(iis_ver, f"Windows Server (IIS {m.group(1)})")
                    domain = ReportGenerator._extract_windows_domain(findings)
                    if domain:
                        return f"{win_ver} ({domain})"
                    return win_ver

        # 3. SMB/CIFS OS banners
        for f in findings:
            if f.type == "service" and "microsoft-ds" in f.detail.lower():
                d = f.detail
                windows_os = ""
                # Pattern 1: "microsoft-ds Windows Server 2019 Standard 17763"
                m = re.search(
                    r'microsoft-ds\s+'
                    r'((?:Microsoft\s+)?(?:Windows\s+)?(?:Server\s+)?[\d]{4}\s*'
                    r'(?:R\d{1,2})?\s*'
                    r'(?:-+\s*[\d]{4})?\s*'
                    r'(?:(?:Standard|Enterprise|Datacenter|Professional|Home|Education)\s*)?'
                    r'(?:build\s*\d+)?)',
                    d, re.IGNORECASE
                )
                if m:
                    windows_os = re.sub(r'\s+', ' ', m.group(1)).strip().rstrip("- ")
                    if windows_os and len(windows_os) > 5:
                        # Enrich with domain from LDAP
                        domain = ReportGenerator._extract_windows_domain(findings)
                        if domain:
                            return f"{windows_os} ({domain})"
                        return windows_os
                # Fallback: Pattern 2 for "Microsoft Windows Server 2008 R2" format
                m = re.search(
                    r'(Microsoft\s+)?(Windows\s+(?:Server\s+)?[\d]{4}\s*R\d?)',
                    d, re.IGNORECASE
                )
                if m:
                    windows_os = m.group(0).strip()
                    domain = ReportGenerator._extract_windows_domain(findings)
                    if domain:
                        return f"{windows_os} ({domain})"
                    return windows_os
        # 3. SSH banners (Linux distros, Cisco, other)
        for f in findings:
            if f.type == "service" and "ssh" in f.detail.lower():
                d = f.detail
                # Management interfaces: detect and return
                if "integrated lights-out" in d.lower() or ("ilo" in d.lower() and ("hp" in d.lower() or "management" in d.lower())):
                    m = re.search(r'(iLO\s*\d+)', d, re.IGNORECASE)
                    return f"HP {m.group(1)}" if m else "HP iLO"
                if "idrac" in d.lower():
                    return "Dell iDRAC"
                # Cisco SSH
                if "cisco" in d.lower():
                    return "Cisco IOS"
                # OpenSSH for_Windows_9.5
                if "for_windows" in d.lower() or "for windows" in d.lower():
                    return "Windows (SSH)"
                # Try to extract distro name from SSH banner
                distro_patterns = [
                    ("Ubuntu", r"ubuntu"),
                    ("Debian", r"debian"),
                    ("CentOS", r"centos"),
                    ("Fedora", r"fedora"),
                    ("RHEL", r"rhel"),
                    ("Oracle Linux", r"oracle"),
                    ("Rocky Linux", r"rocky"),
                    ("AlmaLinux", r"alma"),
                    ("FreeBSD", r"freebsd"),
                    ("Kali", r"kali"),
                    ("Raspbian", r"raspbian"),
                ]
                for distro, pattern in distro_patterns:
                    if re.search(pattern, d, re.IGNORECASE):
                        m = re.search(distro + r'[-\s](\S+)', d)
                        if m:
                            return f"{distro} {m.group(1).rstrip('),;')}"
                        return distro
                if "linux" in d.lower():
                    return "Linux"
                if "openssh" in d.lower() or "ssh" in d.lower():
                    # RHEL-family heuristic: rpcbind + OpenSSH + no distro banner
                    has_rpcbind = any(
                        "rpcbind" in (sf.detail or "").lower() for sf in findings
                    )
                    has_cockpit_port = any(
                        sf.type == "open_port" and "9090/tcp" in (sf.detail or "")
                        for sf in findings
                    )
                    has_cockpit_service = any(
                        "cockpit" in (sf.detail or "").lower() for sf in findings
                    )
                    if has_rpcbind and (has_cockpit_port or has_cockpit_service):
                        return "Linux (RHEL-family)"
                    if has_rpcbind:
                        # rpcbind + OpenSSH without distro banner → probable RHEL-family
                        return "Linux (RHEL-family)"
                    return "Linux (SSH)"
        # 3.5 WatchGuard fallback — lighttpd on 80+443 with no other OS indicators
        for f in findings:
            if f.type == "service" and "lighttpd" in (f.detail or "").lower():
                if any(f2.port == 443 and f2.type == "open_port" for f2 in findings):
                    # Only fire if no SSH, no Windows, no server OS detected
                    has_server_indicator = any(
                        "ssh" in (sf.detail or "").lower() or
                        "openssh" in (sf.detail or "").lower() or
                        "microsoft-ds" in (sf.detail or "").lower() or
                        "windows rpc" in (sf.detail or "").lower() or
                        "vmware" in (sf.detail or "").lower() or
                        "esxi" in (sf.detail or "").lower()
                        for sf in findings
                    )
                    if not has_server_indicator:
                        return "WatchGuard Firewall"
        # 4. Management interfaces (iLO, iDRAC)
        for f in findings:
            if f.type == "service":
                d = f.detail.lower()
                if "integrated lights-out" in d or ("ilo" in d and ("hp" in d or "management" in d)):
                    # Extract iLO version if present
                    m = re.search(r'(iLO\s*\d+)', f.detail, re.IGNORECASE)
                    return f"HP {m.group(1)}" if m else "HP iLO"
                if "idrac" in d:
                    return "Dell iDRAC"

        # 5. Windows RPC
        for f in findings:
            if f.type == "service" and "Windows RPC" in f.detail:
                return "Windows"
        # 6. Cisco IOS / network devices
        for f in findings:
            if f.type == "service":
                d = f.detail.lower()
                if "cisco" in d and ("ios" in d or "ssh" in d or "telnet" in d):
                    return "Cisco IOS"
                if "cisco" in d:
                    return "Cisco Device"

        # 7. Printers — prefer probed model over generic detection
        probed_model = ""
        for f in findings:
            if f.type == "printer" and f.source in ("printer_probe_ipp", "printer_probe_pjl"):
                d = f.detail
                if d.startswith("Printer: "):
                    probed_model = d[9:].strip()
                elif d.startswith("Firmware: "):
                    pass  # keep model if already found
        if probed_model:
            return f"Printer: {probed_model}"

        for f in findings:
            if f.type == "service":
                d = f.detail.lower()
                if "jetdirect" in d or "printer" in d:
                    return "Network Printer"

        # 7.5 UPnP / IoT device banners — extract OS from UPnP service strings
        #    e.g. "Portable SDK for UPnP devices 1.6.22 (Linux 3.10.0_hi3536; UPnP 1.0)"
        for f in findings:
            if f.type == "service" and "upnp" in (f.detail or "").lower():
                d = f.detail
                # Extract Linux kernel version from UPnP banner
                m = re.search(r'\(Linux\s+(\S+);', d)
                if m:
                    kernel = m.group(1)
                    chip = ""
                    # Check for HiSilicon chipset suffix
                    cm = re.search(r'_hi\d+', kernel, re.IGNORECASE)
                    if cm:
                        chip = " (HiSilicon)"
                    return f"Linux {kernel}{chip} (Embedded/IoT)"
                # General UPnP device without explicit kernel
                return "Linux (Embedded/IoT)"

        # 8. HTTP Server headers
        for f in findings:
            if f.type == "web_tech" and f.source == "whatweb":
                d = f.evidence or f.detail
                m = re.search(r'Server:\s*([^\r\n]+)', d)
                if m:
                    server = m.group(1).strip()
                    if "win" in server.lower() or "iis" in server.lower():
                        return f"Windows ({server[:40]})"
                    if "ubuntu" in server.lower() or "debian" in server.lower():
                        return server[:60]

        # 9. Heuristic: RHEL-family detection
        #    RHEL/Oracle/Rocky/Alma builds of OpenSSH often omit distro from banner.
        #    Service patterns like rpcbind+cockpit+OpenSSH without distro → RHEL-family.
        has_ssh = any("ssh" in (f.detail or "").lower() for f in findings if f.type == "service")
        has_rpcbind = any("rpcbind" in (f.detail or "").lower() for f in findings)
        has_openssh = any("openssh" in (f.detail or "").lower() for f in findings)
        has_cockpit = any("cockpit" in (f.detail or "").lower() for f in findings)
        has_port_9090 = any(
            f.type == "open_port" and "9090/tcp" in (f.detail or "") for f in findings
        )
        if has_ssh and has_openssh and has_rpcbind and (has_cockpit or has_port_9090):
            return "Linux (RHEL-family)"
        if has_ssh and has_openssh and has_rpcbind:
            # rpcbind+OpenSSH and no distro in SSH → probable RHEL-family
            # Check: is there ANY distro indicator in SSH?
            for f in findings:
                if f.type == "service" and "ssh" in (f.detail or "").lower():
                    d = f.detail.lower()
                    has_distro = any(
                        kw in d for kw in ("ubuntu", "debian", "centos", "fedora",
                                            "rhel", "oracle", "rocky", "alma",
                                            "kali", "raspbian", "freebsd")
                    )
                    if not has_distro:
                        return "Linux (RHEL-family)"
            return "Linux (SSH)"

        # 10. Camera probe enrichment
        for f in findings:
            if f.type == "os" and f.source == "camera_probe_http":
                return f.detail

        # 11. DNS hostname enrichment (from dns_probe module)
        for f in findings:
            if f.type == "os" and f.source == "dns_probe_ptr" and f.detail.startswith("DNS: "):
                dns_name = f.detail[5:].strip()
                # Skip dig/communication error messages
                if dns_name and not dns_name.startswith(";;"):
                    return dns_name

        return "Unknown"

    @staticmethod
    def _extract_windows_domain(findings: list[Finding]) -> str:
        """Extract Active Directory domain from LDAP/Kerberos banners."""
        import re
        for f in findings:
            if f.type == "service":
                d = f.detail or ""
                if "ldap" in d.lower():
                    m = re.search(r'Domain:\s*(\S+)', d)
                    if m:
                        return m.group(1).rstrip(".,;0")
                if "kerberos" in d.lower():
                    m = re.search(r'Domain:\s*(\S+)', d)
                    if m:
                        return m.group(1).rstrip(".,;0")
        return ""

    @staticmethod
    def _detect_hardware(findings: list[Finding], mac_address: str = "",
                         cdp_lldp_devices: list[dict] | None = None) -> str:
        """Detect hardware/device type from findings + MAC OUI + CDP/LLDP.

        Priority: service-specific (iLO/iDRAC/SNMP) > CDP/LLDP > MAC OUI > generic.
        """
        import re

        # 1. Management interfaces (override everything)
        for f in findings:
            if f.type == "service":
                d = f.detail.lower() + (f.evidence or "").lower()
                if re.search(r'\bilo\b|integrated\s+lights.out', d, re.IGNORECASE):
                    m = re.search(r'(iLO\s*\d*)', d, re.IGNORECASE)
                    return f"HP {m.group(1)}" if m else "HP iLO"
                if re.search(r'\bidrac\b', d):
                    m = re.search(r'(iDRAC\s*\d*)', d, re.IGNORECASE)
                    return f"Dell {m.group(1)}" if m else "Dell iDRAC"
                if "vmware" in d or "esxi" in d:
                    return "VMware ESXi"
                if "jetdirect" in d or "printer" in d:
                    return "Network Printer"

        # 2. CDP/LLDP data (best for switches/routers)
        if cdp_lldp_devices:
            # Build IP→device map from CDP/LLDP addresses
            for dev in cdp_lldp_devices:
                platform = dev.get("platform", "")
                dev_id = dev.get("device_id", "")
                if platform:
                    return platform
                if dev_id:
                    return dev_id

        # 3. Cisco device detection (override OUI for network gear)
        for f in findings:
            if f.type == "service":
                d = (f.detail or "").lower()
                if "cisco ios" in d or ("cisco" in d and ("router" in d or "switch" in d or "telnet" in d)):
                    return "Cisco Device"

        # 4. MAC OUI lookup (primary method for physical hardware)
        if mac_address:
            from istrix.utils.oui import oui_lookup
            vendor = oui_lookup(mac_address)
            if vendor:
                return vendor

        # 5. Generic service-based fallback
        for f in findings:
            if f.type == "service":
                d = (f.detail or "").lower()
                if "cisco" in d:
                    return "Cisco Device"
        has_smb = any("microsoft-ds" in (f.detail or "").lower() for f in findings if f.type == "service")
        has_ssh = any("ssh" in (f.detail or "").lower() for f in findings if f.type == "service")
        has_http = any(f.port in {80, 443, 8080, 8443} for f in findings if f.type == "open_port")
        if has_smb and has_ssh:
            return "Multi-role Server"
        if has_smb:
            return "Windows Server"
        if has_ssh and not has_http:
            return "Linux Server"
        return ""

    def _setup_jinja(self) -> Environment:
        if TEMPLATES_DIR.exists():
            return Environment(
                loader=FileSystemLoader(str(TEMPLATES_DIR)),
                autoescape=select_autoescape(["html"]),
            )
        return Environment(enable_async=False)

    # ------------------------------------------------------------------
    # Threat scoring (unchanged logic, preserved from original)
    # ------------------------------------------------------------------

    def _calculate_threat_score(self, by_severity: dict) -> tuple[int, str, str]:
        weights = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
        total_weighted = 0.0
        total_count = 0
        for sev, findings_list in by_severity.items():
            w = weights.get(sev, 0.0)
            total_weighted += w * len(findings_list)
            total_count += len(findings_list)
        if total_count == 0:
            return 0, "None", "#38a169"
        raw = (total_weighted / (total_count * 10.0)) * 100
        score = min(round(raw), 100)
        if score >= 80:
            return score, "CRITICAL", "#e53e3e"
        elif score >= 50:
            return score, "HIGH", "#dd6b20"
        elif score >= 25:
            return score, "MEDIUM", "#d69e2e"
        elif score >= 10:
            return score, "LOW", "#38a169"
        else:
            return score, "INFO", "#718096"

    def _score_rating(self, label: str) -> str:
        ratings = {
            "CRITICAL": (
                "The target exhibits severe vulnerabilities including known exploits (CVSS 9.0-10.0). "
                "Immediate remediation is required. Unauthenticated remote code execution, privilege escalation, "
                "or data exfiltration is likely achievable. Treat as a confirmed breach scenario."
            ),
            "HIGH": (
                "The target has significant security weaknesses (CVSS 7.0-8.9). "
                "Multiple high-severity CVEs or exploitable misconfigurations are present. "
                "Remediation should be prioritized within 1-2 weeks."
            ),
            "MEDIUM": (
                "The target has moderate security issues (CVSS 4.0-6.9). "
                "Vulnerabilities exist but may require specific conditions or local access to exploit. "
                "Address within 30 days as part of routine patching."
            ),
            "LOW": (
                "The target has minimal security concerns (CVSS 0.1-3.9). "
                "Only low-severity findings or informational items detected. "
                "Remediate during the next scheduled maintenance window."
            ),
            "INFO": (
                "No significant vulnerabilities detected. "
                "Informational findings only — these do not represent exploitable weaknesses. "
                "Continue routine security monitoring."
            ),
            "None": "No findings available. No risk assessment can be made.",
        }
        return ratings.get(label, ratings["INFO"])

    def _adjusted_label(self, score: int) -> tuple[str, str]:
        if score >= 80:
            return "CRITICAL", "#e53e3e"
        elif score >= 50:
            return "HIGH", "#dd6b20"
        elif score >= 25:
            return "MEDIUM", "#d69e2e"
        elif score >= 10:
            return "LOW", "#38a169"
        else:
            return "INFO", "#718096"

    # ------------------------------------------------------------------
    # Enriched threats builder (unchanged core logic, per-host callable)
    # ------------------------------------------------------------------

    def _find_os_advice(self, host_os: str) -> dict:
        """Find the most specific remediation advice for an OS string.

        Performs prefix-based matching against REMEDIATION_OS_ADVICE keys
        so that 'Cisco IOS 15.2' matches the 'Cisco IOS' entry.
        Generic Linux heuristics like 'Linux (SSH)' (distro unknown) are
        NOT blindly matched to the apt-based 'Linux' entry — they get
        cross-distro default advice instead.
        """
        # Guard: generic Linux heuristic → cross-distro advice, don't assume apt
        if host_os.startswith("Linux (") and host_os.endswith(")"):
            return self.REMEDIATION_OS_ADVICE.get(
                host_os,
                self.REMEDIATION_OS_ADVICE.get(
                    "unknown",
                    {"general": "Apply latest vendor security patches"},
                ),
            )

        for key in sorted(self.REMEDIATION_OS_ADVICE, key=len, reverse=True):
            if host_os.startswith(key) or host_os == key:
                return self.REMEDIATION_OS_ADVICE[key]
        return self.REMEDIATION_OS_ADVICE["unknown"]

    def _build_enriched_threats(
        self, host_os: str, findings: list[Finding]
    ) -> list[dict]:
        """Build enriched threat items with CVSS, explanations, and remediation commands.

        Sorted by severity: critical > high > medium > low.
        Deduplicated by CVE ID.
        """
        os_advice = self._find_os_advice(host_os)
        seen_cves: set[str] = set()
        items: list[dict] = []

        for f in findings:
            if f.type != "vulnerability" and not f.cve:
                continue
            if f.cve and f.cve in seen_cves:
                continue
            if f.cve:
                seen_cves.add(f.cve)

            cve_info = self._load_vulndb().get(f.cve if f.cve else "", self._DEFAULT_THREAT)
            title = cve_info.get("title") or f.detail[:120]
            summary = cve_info.get("summary", "")
            exploit_narrative = cve_info.get(
                "exploit_narrative",
                "Exploitation details are available in the NVD entry linked below."
            )
            commands = cve_info.get("commands", [])
            cvss = cve_info.get("cvss", "N/A")
            vector = cve_info.get("vector", "N/A")

            title_line = f"{f.cve}: {title}" if f.cve else title

            service_advice = os_advice["general"]
            detail_lower = (f.detail or "").lower()
            if "ssh" in detail_lower:
                service_advice = os_advice.get("ssh", os_advice["general"])
            elif "nginx" in detail_lower:
                service_advice = os_advice.get("nginx", os_advice["general"])
            elif "nfs" in detail_lower or "rpcbind" in detail_lower:
                service_advice = os_advice.get("nfs", os_advice["general"])
            elif "smb" in detail_lower or "microsoft-ds" in detail_lower or "netbios" in detail_lower:
                service_advice = os_advice.get("smb", os_advice["general"])
            elif "rdp" in detail_lower or "ms-wbt-server" in detail_lower:
                service_advice = os_advice.get("rdp", os_advice["general"])
            elif "http" in detail_lower or "www" in detail_lower:
                service_advice = os_advice.get("http", os_advice["general"])
            elif "dns" in detail_lower or "domain" in detail_lower:
                service_advice = os_advice.get("dns", os_advice["general"])
            elif "snmp" in detail_lower:
                service_advice = os_advice.get("snmp", os_advice["general"])

            if not commands:
                # Try OS-aware CVE-specific remediation
                if f.cve and (cve_info is self._DEFAULT_THREAT):
                    commands = generate_remediation_commands(
                        cve_id=f.cve,
                        cve_description=(f.evidence or f.detail),
                        host_os=host_os,
                        finding_detail=f.detail,
                    )
                if not commands:
                    commands = [service_advice]

            items.append({
                "title": title_line,
                "severity": f.severity,
                "cve": f.cve,
                "cvss": cvss,
                "vector": vector,
                "summary": summary,
                "exploit_narrative": exploit_narrative,
                "commands": commands,
                "host": f.host,
                "port": f.port,
                "nvd_url": (
                    f"https://nvd.nist.gov/vuln/detail/{f.cve}" if f.cve else None
                ),
            })

        items.sort(key=lambda x: _SEVERITY_RANK.get(x["severity"], 99))
        return items

    # ------------------------------------------------------------------
    # Build per-host data
    # ------------------------------------------------------------------

    def _build_host_data(self, host_id: str, result: ScanResult) -> _HostData:
        """Pre-compute all per-host metrics and enriched data."""
        findings = result.findings
        host_os = self._detect_os(findings)
        mac_addr = _get_mac_for_ip(host_id)
        host_hardware = self._detect_hardware(findings, mac_addr)

        by_sev: dict[str, list[Finding]] = {
            "critical": [], "high": [], "medium": [], "low": [], "info": []
        }
        for f in findings:
            s = f.severity if f.severity in by_sev else "info"
            by_sev[s].append(f)

        sev_counts = {k: len(v) for k, v in by_sev.items()}
        score, label, color = self._calculate_threat_score(by_sev)
        threats = self._build_enriched_threats(host_os, findings)

        return _HostData(
            host_id=host_id,
            result=result,
            os_name=host_os,
            hardware=host_hardware,
            findings=findings,
            threats=threats,
            sev_counts=sev_counts,
            score=score,
            label=label,
            color=color,
        )

    # ------------------------------------------------------------------
    # Aggregate context
    # ------------------------------------------------------------------

    def _build_context(self) -> dict[str, Any]:
        """Build the full template context for single or aggregate mode."""
        host_data_list = [
            self._build_host_data(hid, sr) for hid, sr in self._raw_results
        ]

        # ── aggregate / combined data ──
        all_findings: list[Finding] = []
        for hd in host_data_list:
            all_findings.extend(hd.findings)

        combined_sev: dict[str, list[Finding]] = {
            "critical": [], "high": [], "medium": [], "low": [], "info": []
        }
        for f in all_findings:
            s = f.severity if f.severity in combined_sev else "info"
            combined_sev[s].append(f)

        combined_sev_counts = {k: len(v) for k, v in combined_sev.items()}

        # Aggregate score
        agg_score, agg_label, agg_color = self._calculate_threat_score(combined_sev)

        # Risk multiplier
        rp = self.config.risk_profile
        multiplier = rp.risk_multiplier()
        adjusted = min(round(agg_score * multiplier), 100)
        adj_label, adj_color = self._adjusted_label(adjusted)

        # Combined threats (deduped by CVE, sorted by severity)
        seen_cves: set[str] = set()
        all_threats: list[dict] = []
        for hd in host_data_list:
            for t in hd.threats:
                key = t["cve"] or t["title"]
                if key not in seen_cves:
                    seen_cves.add(key)
                    all_threats.append(t)
        all_threats.sort(key=lambda x: _SEVERITY_RANK.get(x["severity"], 99))

        # Remediation items: sorted by severity, filtered to vuln/cve items only
        remediation_items: list[dict] = []
        rem_seen: set[str] = set()
        for hd in host_data_list:
            for t in hd.threats:
                key = t["cve"] or t["title"]
                if key not in rem_seen:
                    rem_seen.add(key)
                    remediation_items.append(t)
        remediation_items.sort(key=lambda x: _SEVERITY_RANK.get(x["severity"], 99))

        # Host summary rows for brief / aggregate
        host_summary_rows: list[dict] = []
        for hd in host_data_list:
            host_summary_rows.append({
                "host": hd.host_id,
                "os": hd.os,
                "hardware": hd.hardware,
                "total": len(hd.findings),
                "critical": hd.sev_counts.get("critical", 0),
                "high": hd.sev_counts.get("high", 0),
                "medium": hd.sev_counts.get("medium", 0),
                "low": hd.sev_counts.get("low", 0),
                "score": hd.score,
                "label": hd.score_label,
                "color": hd.score_color,
            })

        # Summary dict (use combined)
        summary = {
            "total_findings": len(all_findings),
            "hosts_scanned": len(host_data_list),
            "ports_open": len({
                f"{f.host}:{f.port}" for f in all_findings if f.port is not None
            }),
            "by_severity": combined_sev_counts,
            "by_type": {},
            "errors": 0,
        }
        for f in all_findings:
            summary["by_type"][f.type] = summary["by_type"].get(f.type, 0) + 1

        branding = self.config.branding
        b_colors = branding.get("colors", {})
        stationery = branding.get("report_stationery", {})

        context: dict[str, Any] = {
            "_level": self.config.level,
            "_is_aggregate": self.is_aggregate,
            "branding": branding,
            "report_date": self.config.report_date,
            "customer_name": self.config.customer_name or "N/A",
            "site_name": self.config.site_name or (
                self.config.results_paths[0].stem if self.config.results_paths else "N/A"
            ),
            "scan_notes": self.config.scan_notes or "Automated security assessment scan.",
            "summary": summary,
            # All findings (serialized)
            "findings": [f.model_dump() for f in all_findings],
            "cve_refs": all_threats,
            "vuln_findings": [
                f.model_dump() for f in all_findings if f.type == "vulnerability"
            ],
            "by_severity": {
                k: [f.model_dump() for f in v] for k, v in combined_sev.items()
            },
            "host_os": host_data_list[0].os if host_data_list else "Unknown",
            "host_hardware": host_data_list[0].hardware if host_data_list else "",
            "host_id": host_data_list[0].host_id if host_data_list else "",
            "remediation": remediation_items,
            "severity_colors": {
                "critical": b_colors.get("critical", "#e53e3e"),
                "high": b_colors.get("high", "#dd6b20"),
                "medium": b_colors.get("medium", "#d69e2e"),
                "low": b_colors.get("low", "#38a169"),
                "info": b_colors.get("info", "#718096"),
            },
            "total_critical": combined_sev_counts.get("critical", 0),
            "total_high": combined_sev_counts.get("high", 0),
            "total_medium": combined_sev_counts.get("medium", 0),
            "total_low": combined_sev_counts.get("low", 0),
            "threat_score": adjusted,
            "technical_score": agg_score,
            "threat_score_label": adj_label,
            "threat_score_color": adj_color,
            "threat_rating_text": self._score_rating(adj_label),
            "risk_profile": rp,
            "risk_multiplier": multiplier,
            "risk_lines": rp.risk_summary_lines(),
            "scope_label": rp.scope_label(),
            # Per-host data for aggregate rendering
            "hosts": [
                {
                    "host_id": hd.host_id,
                    "os": hd.os,
                    "hardware": hd.hardware,
                    "findings": [f.model_dump() for f in hd.findings],
                    "threats": hd.threats,
                    "sev_counts": hd.sev_counts,
                    "score": hd.score,
                    "score_label": hd.score_label,
                    "score_color": hd.score_color,
                    "summary": hd.result.summary(),
                }
                for hd in host_data_list
            ],
            "host_summary": host_summary_rows,
            "stationery": stationery,
        }
        return context

    # ------------------------------------------------------------------
    # Generate entry point
    # ------------------------------------------------------------------

    def generate(self) -> Path:
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        context = self._build_context()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"istrix_report_{self.config.level}_{ts}"
        fmt = self.config.output_format
        if fmt == "json":
            return self._render_json(context, base_name)
        elif fmt == "md":
            return self._render_md(context, base_name)
        elif fmt == "pdf":
            return self._render_pdf(context, base_name)
        else:
            return self._render_html(context, base_name)

    # ------------------------------------------------------------------
    # HTML rendering
    # ------------------------------------------------------------------

    def _render_html(self, context: dict, base_name: str) -> Path:
        html = self._render_html_content(context)
        path = self.config.output_dir / f"{base_name}.html"
        path.write_text(html)
        return path

    def _render_pdf(self, context: dict, base_name: str) -> Path:
        html = self._render_html_content(context)
        pdf_path = self.config.output_dir / f"{base_name}.pdf"
        try:
            from weasyprint import HTML
            HTML(string=html).write_pdf(str(pdf_path))
        except ImportError:
            raise ImportError("weasyprint not installed. Run: pip install istrix[report]")
        return pdf_path

    # ── HTML content builder ───────────────────────────────────────────

    def _render_html_content(self, context: dict) -> str:
        b = context["branding"]
        c = b.get("company", {})
        col = b.get("colors", {})
        stationery = b.get("report_stationery", {})

        # ---- helper: risk lines ----
        def _risk_lines_html(risk_lines: list) -> str:
            if not risk_lines:
                return ""
            rows = ""
            for item in risk_lines:
                if isinstance(item, tuple):
                    rows += (
                        f'<div class="risk-item">{item[0]} '
                        f'{item[1] if len(item) > 1 else ""}</div>'
                    )
                else:
                    rows += f'<div class="risk-item">{item}</div>'
            return rows

        # ---- severity badge helper ----
        def sev_badge(s: str) -> str:
            return f'<span class="severity {s}">{s.upper()}</span>'

        # =================================================================
        # CSS
        # =================================================================
        colors_css = f"""
        :root {{
            --primary: {col.get('primary', '#1a365d')};
            --secondary: {col.get('secondary', '#2b6cb0')};
            --accent: {col.get('accent', '#3182ce')};
            --bg: {col.get('background', '#f7fafc')};
            --text: {col.get('text', '#2d3748')};
            --border: {col.get('border', '#e2e8f0')};
            --critical: {col.get('critical', '#e53e3e')};
            --high: {col.get('high', '#dd6b20')};
            --medium: {col.get('medium', '#d69e2e')};
            --low: {col.get('low', '#38a169')};
            --info: {col.get('info', '#718096')};
            --cmd-bg: #1a202c;
            --cmd-text: #e2e8f0;
            --card-bg: #ffffff;
            --card-border: #e2e8f0;
        }}
        """

        # Preserved existing classes + new ones
        extra_css = """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: """ + stationery.get('font_family', 'system-ui, sans-serif') + """; color: var(--text); background: var(--bg); line-height: 1.6; }
        .container { max-width: 960px; margin: 0 auto; padding: 2rem; }
        .header { background: var(--primary); color: white; padding: 2rem; text-align: center; border-radius: 8px 8px 0 0; }
        .header h1 { font-size: 1.8rem; margin-bottom: 0.25rem; }
        .header .subtitle { opacity: 0.85; font-size: 0.95rem; }
        .meta { background: white; border: 1px solid var(--border); padding: 1.5rem; margin: 1rem 0; border-radius: 8px; }
        .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; }
        .meta-item strong { color: var(--primary); }
        .classification { background: var(--critical); color: white; text-align: center; padding: 0.5rem; font-weight: bold; letter-spacing: 2px; }
        .summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin: 1rem 0; }
        .card { background: white; border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; text-align: center; }
        .card .count { font-size: 2rem; font-weight: bold; }
        .card .label { color: var(--info); font-size: 0.85rem; text-transform: uppercase; }
        .severity-bar { display: flex; height: 8px; border-radius: 4px; overflow: hidden; margin: 1rem 0; }
        .severity-bar div { height: 100%; }
        table.findings { width: 100%; border-collapse: collapse; background: white; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; margin: 1rem 0; }
        table.findings th { background: var(--primary); color: white; padding: 0.6rem 0.75rem; text-align: left; font-size: 0.85rem; }
        table.findings td { padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); font-size: 0.85rem; }
        table.findings tr:hover { background: var(--bg); }
        .severity { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; color: white; }
        .severity.critical { background: var(--critical); }
        .severity.high { background: var(--high); }
        .severity.medium { background: var(--medium); }
        .severity.low { background: var(--low); }
        .severity.info { background: var(--info); }
        .footer { text-align: center; padding: 1.5rem; color: var(--info); font-size: 0.8rem; border-top: 2px solid var(--border); margin-top: 2rem; }
        h2 { color: var(--primary); border-bottom: 2px solid var(--accent); padding-bottom: 0.5rem; margin: 1.5rem 0 1rem; }
        code { background: #edf2f7; padding: 1px 5px; border-radius: 3px; font-size: 0.85em; }
        .score-section { text-align: center; margin: 2rem 0; }
        .score-section h2 { border: none; font-size: 1.3rem; letter-spacing: 2px; }
        .rating-text { max-width: 640px; margin: 1rem auto; color: var(--text); font-size: 0.9rem; line-height: 1.7; text-align: left; }
        .severity-legend { background: white; border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; margin: 1rem 0; }
        .legend-row { padding: 0.35rem 0; font-size: 0.85rem; display: flex; align-items: center; gap: 0.5rem; }
        .legend-dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; flex-shrink: 0; }
        .risk-profile { background: white; border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; margin: 1rem 0; }
        .risk-meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; margin-bottom: 0.75rem; }
        .risk-item { font-size: 0.85rem; padding: 0.2rem 0; }
        .risk-item strong { color: var(--primary); }

        /* ── NEW: threat-card ── */
        .threat-card {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-left: 5px solid var(--critical);
            border-radius: 8px;
            padding: 1.25rem;
            margin: 1rem 0;
        }
        .threat-card.critical { border-left-color: var(--critical); }
        .threat-card.high     { border-left-color: var(--high); }
        .threat-card.medium   { border-left-color: var(--medium); }
        .threat-card.low      { border-left-color: var(--low); }
        .threat-card-header {
            display: flex; align-items: center; gap: 0.75rem;
            margin-bottom: 0.5rem; flex-wrap: wrap;
        }
        .threat-card-header .severity { font-size: 0.8rem; padding: 3px 10px; }
        .cvss-badge {
            background: var(--primary); color: #fff;
            padding: 2px 8px; border-radius: 4px;
            font-size: 0.75rem; font-weight: bold;
        }
        .nvd-link {
            font-size: 0.8rem; color: var(--accent);
            text-decoration: none; font-weight: 600;
        }
        .nvd-link:hover { text-decoration: underline; }
        .threat-card h3 {
            font-size: 1rem; margin: 0.5rem 0 0.25rem;
            color: var(--primary); border: none;
        }
        .threat-description {
            font-size: 0.9rem; line-height: 1.65;
            color: var(--text); margin: 0.5rem 0;
        }
        .threat-impact {
            font-size: 0.85rem; line-height: 1.6;
            background: #fff5f5; border-radius: 6px;
            padding: 0.6rem 0.8rem; margin: 0.5rem 0 0;
        }

        /* ── NEW: cmd-block ── */
        .cmd-block {
            background: var(--cmd-bg); color: var(--cmd-text);
            border-radius: 6px; padding: 1rem; margin: 0.5rem 0;
            font-family: 'Fira Code', 'Consolas', 'Monaco', monospace;
            font-size: 0.8rem; line-height: 1.6;
            overflow-x: auto; white-space: pre-wrap; word-break: break-all;
        }
        .cmd-block code {
            background: transparent; color: inherit;
            padding: 0; font-size: inherit;
        }

        /* ── NEW: remediation-item ── */
        .remediation-item {
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 8px; padding: 1.25rem;
            margin: 1rem 0;
        }
        .remediation-item .rem-header {
            display: flex; align-items: center; gap: 0.75rem;
            margin-bottom: 0.5rem; flex-wrap: wrap;
        }
        .remediation-item h4 {
            font-size: 0.95rem; color: var(--primary);
            margin: 0.25rem 0;
        }
        .remediation-item .rem-desc {
            font-size: 0.85rem; color: var(--text);
            margin: 0.25rem 0 0.5rem;
        }
        .remediation-item .rem-actions p {
            font-size: 0.85rem; margin: 0.5rem 0 0.25rem;
        }

        /* ── NEW: host-summary table ── */
        .host-summary { width: 100%; border-collapse: collapse; margin: 1rem 0; }
        .host-summary th { background: var(--primary); color: white; padding: 0.6rem 0.75rem; text-align: left; font-size: 0.85rem; }
        .host-summary td { padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); font-size: 0.85rem; background: white; }
        .host-summary tr:hover td { background: var(--bg); }

        /* ── NEW: host-section ── */
        .host-section {
            background: white; border: 2px solid var(--secondary);
            border-radius: 10px; padding: 1.5rem; margin: 1.5rem 0;
        }
        .host-section h2 {
            color: var(--secondary); border-bottom-color: var(--accent);
            margin-top: 0; font-size: 1.2rem;
        }
        .host-section .host-meta {
            display: flex; gap: 1.5rem; flex-wrap: wrap;
            font-size: 0.85rem; margin: 0.5rem 0 1rem;
        }
        .host-section .host-meta span { color: var(--info); }
        .host-section .host-meta strong { color: var(--primary); }

        @page {{
            size: {stationery.get('page_size', 'A4')};
            margin: 2cm 1.8cm 2.5cm 1.8cm;
            @bottom-center {{
                content: counter(page);
                font-size: 0.75em;
                color: var(--info);
            }}
        }}
        @page :first {{
            @bottom-center {{ content: none; }}
        }}
        @media print {{
            body {{ background: white; }}
            .container {{ max-width: 100%; padding: 0; }}
            .classification {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
            .header {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
            .severity {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
            .cmd-block {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
            table {{ page-break-inside: avoid; }}
            h2 {{ page-break-after: avoid; }}
            .threat-card {{ page-break-inside: avoid; }}
            .remediation-item {{ page-break-inside: avoid; }}
        }}
        """

        full_css = f"<style>\n{colors_css}\n{extra_css}\n</style>"

        # =================================================================
        # Shared sections
        # =================================================================

        # --- Threat score circle (unchanged from original) ---
        threat_score_html = f"""
        <div class="score-section">
            <svg width="160" height="160" viewBox="0 0 160 160">
                <circle cx="80" cy="80" r="70" fill="none" stroke="var(--border)" stroke-width="12"/>
                <circle cx="80" cy="80" r="70" fill="none" stroke="{context.get('threat_score_color', '#718096')}"
                    stroke-width="12" stroke-dasharray="{context.get('threat_score', 0) * 4.4} 440"
                    stroke-linecap="round" transform="rotate(-90 80 80)" style="transition: stroke-dasharray 0.5s;"/>
                <text x="80" y="70" text-anchor="middle" font-size="36" font-weight="bold" fill="var(--text)">{context.get('threat_score', 0)}</text>
                <text x="80" y="95" text-anchor="middle" font-size="12" fill="var(--info)">of 100</text>
            </svg>
            <h2 style="color: {context.get('threat_score_color', '#718096')}; border: none; margin-top: 0.5rem;">
                {context.get('threat_score_label', 'N/A')} RISK
            </h2>
            <p class="rating-text">{context.get('threat_rating_text', '')}</p>
        </div>"""

        # --- Severity legend ---
        severity_legend = """
        <div class="severity-legend">
            <div class="legend-row"><span class="legend-dot" style="background: var(--critical);"></span> Critical (CVSS 9.0-10.0) — Immediate action required</div>
            <div class="legend-row"><span class="legend-dot" style="background: var(--high);"></span> High (CVSS 7.0-8.9) — Remediate within 1-2 weeks</div>
            <div class="legend-row"><span class="legend-dot" style="background: var(--medium);"></span> Medium (CVSS 4.0-6.9) — Remediate within 30 days</div>
            <div class="legend-row"><span class="legend-dot" style="background: var(--low);"></span> Low (CVSS 0.1-3.9) — Remediate next maintenance</div>
            <div class="legend-row"><span class="legend-dot" style="background: var(--info);"></span> Info — Informational only</div>
        </div>"""

        # --- Executive summary cards + severity bar ---
        exec_cards = f"""
        <h2>Executive Summary</h2>
        <div class="summary-cards">
            <div class="card"><div class="count" style="color: var(--primary);">{context['summary']['hosts_scanned']}</div><div class="label">Hosts Scanned</div></div>
            <div class="card"><div class="count" style="color: var(--primary);">{context['summary']['ports_open']}</div><div class="label">Open Ports</div></div>
            <div class="card"><div class="count" style="color: var(--critical);">{context['total_critical']}</div><div class="label">Critical</div></div>
            <div class="card"><div class="count" style="color: var(--high);">{context['total_high']}</div><div class="label">High</div></div>
            <div class="card"><div class="count" style="color: var(--medium);">{context['total_medium']}</div><div class="label">Medium</div></div>
            <div class="card"><div class="count" style="color: var(--info);">{context['summary']['total_findings']}</div><div class="label">Total Findings</div></div>
        </div>
        <div class="severity-bar">
            <div style="width: {max(context['total_critical'] / max(context['summary']['total_findings'], 1) * 100, 2)}%; background: var(--critical);"></div>
            <div style="width: {max(context['total_high'] / max(context['summary']['total_findings'], 1) * 100, 2)}%; background: var(--high);"></div>
            <div style="width: {max(context['total_medium'] / max(context['summary']['total_findings'], 1) * 100, 2)}%; background: var(--medium);"></div>
            <div style="width: {max(context['total_low'] / max(context['summary']['total_findings'], 1) * 100, 2)}%; background: var(--low);"></div>
            <div style="width: {max((context['summary']['total_findings'] - context['total_critical'] - context['total_high'] - context['total_medium'] - context['total_low']) / max(context['summary']['total_findings'], 1) * 100, 2)}%; background: var(--info);"></div>
        </div>"""

        # --- Risk profile ---
        risk_profile_html = f"""
        <h2>Risk Assessment Profile</h2>
        <div class="risk-profile">
            <div class="risk-meta-grid">
                <div class="risk-item"><strong>Scope:</strong> {context.get('scope_label', 'Unknown')}</div>
                <div class="risk-item"><strong>Technical Score:</strong> {context.get('technical_score', 0)}/100</div>
                <div class="risk-item"><strong>Risk Multiplier:</strong> {context.get('risk_multiplier', 1.0):.2f}x</div>
                <div class="risk-item"><strong>Adjusted Score:</strong> <span style="color:{context.get('threat_score_color', '#718096')}; font-weight:bold; font-size:1.2em;">{context.get('threat_score', 0)}</span>/100</div>
            </div>
            {_risk_lines_html(context.get('risk_lines', []))}
        </div>"""

        # --- Aggregate host summary table ---
        host_summary_html = ""
        if context["_is_aggregate"]:
            rows = ""
            for hs in context.get("host_summary", []):
                hw = hs.get("hardware", "")
                rows += f"""
                <tr>
                    <td><strong>{hs['host']}</strong></td>
                    <td>{hs['os']}</td>
                    <td>{hw}</td>
                    <td>{hs['critical']}</td>
                    <td>{hs['high']}</td>
                    <td>{hs['medium']}</td>
                    <td>{hs['low']}</td>
                    <td>{hs['total']}</td>
                    <td><span style="color:{hs['color']}; font-weight:bold;">{hs['score']} {hs['label']}</span></td>
                </tr>"""
            host_summary_html = f"""
        <h2>Target Hosts Overview</h2>
        <table class="host-summary">
            <thead><tr><th>Host</th><th>OS</th><th>Hardware</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th><th>Threat Score</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>"""

        # --- Detail findings table (per-host or combined) ---
        def _build_findings_table(findings_list: list[dict], max_rows: int = 200) -> str:
            rows = ""
            for f in findings_list[:max_rows]:
                host = f.get("host", "")
                port = str(f.get("port", "")) if f.get("port") else "-"
                proto = f.get("protocol", "-") or "-"
                detail = (f.get("detail", "") or "")[:120]
                sev = f.get("severity", "info")
                cve_str = f' <code>{f["cve"]}</code>' if f.get("cve") else ""
                rows += f"""
            <tr>
                <td>{host}</td>
                <td>{port}</td>
                <td>{proto}</td>
                <td>{detail}{cve_str}</td>
                <td>{sev_badge(sev)}</td>
            </tr>"""
            return f"""
        <table class="findings">
            <thead><tr><th>Host</th><th>Port</th><th>Proto</th><th>Finding</th><th>Severity</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>"""

        # --- Threat cards section ---
        def _build_threat_cards(threats: list[dict]) -> str:
            if not threats:
                return ""
            cards = ""
            for t in threats:
                sev = t.get("severity", "info")
                cve = t.get("cve") or ""
                nvd = t.get("nvd_url") or ""
                title = t.get("title", "Unknown Threat")
                summary = t.get("summary", "")
                exploit = t.get("exploit_narrative", "")
                cvss = t.get("cvss", "N/A")
                vector = t.get("vector", "N/A")
                commands = t.get("commands", [])

                cmd_html = ""
                if commands:
                    cmd_lines = "<br>".join(commands)
                    cmd_html = f'<div class="cmd-block"><code>{cmd_lines}</code></div>'
                else:
                    cmd_html = '<p style="color:#ffa502;font-style:italic;font-size:0.8rem;">Fixes not available yet</p>'

                cards += f"""
        <div class="threat-card {sev}">
            <div class="threat-card-header">
                {sev_badge(sev)}
                <span class="cvss-badge">CVSS {cvss}</span>
                {f'<a class="nvd-link" href="{nvd}" target="_blank" rel="noopener">{cve} ▸ NVD</a>' if nvd else f'<span class="nvd-link">{cve}</span>'}
            </div>
            <h3>{title}</h3>
            <p class="threat-description">{summary}</p>
            <div class="threat-impact">
                <strong>Exploitation &amp; Impact:</strong> {exploit}
            </div>
            {f'<div class="rem-actions"><p><strong>Remediation:</strong></p>{cmd_html}</div>' if cmd_html else ''}
            <p style="margin-top:0.5rem;font-size:0.75rem;color:var(--info);">Vector: {vector}</p>
        </div>"""
            return f"""
        <h2>Threat Assessment — CVE Details</h2>
        <p>Each identified CVE is presented with a description, exploitation narrative, and NVD reference.</p>
        {cards}"""

        # --- Remediation actions section (sorted by severity) ---
        def _build_remediation_section(items: list[dict]) -> str:
            if not items:
                return ""
            sections = ""
            for r in items:
                sev = r.get("severity", "info")
                cve = r.get("cve") or ""
                title = r.get("title", "Unknown")
                # Extract a one-line description from the full title
                one_liner = title.split(": ", 1)[-1] if ": " in title else title
                summary = r.get("summary", "")[:200] + ("..." if len(r.get("summary", "")) > 200 else "")
                commands = r.get("commands", [])

                cmd_html = ""
                if commands:
                    cmd_lines = "\n".join(commands)
                    cmd_html = f'<div class="cmd-block"><code>{cmd_lines}</code></div>'
                else:
                    cmd_html = '<p style="color:var(--medium);font-style:italic;">Fixes not available yet</p>'

                sections += f"""
        <div class="remediation-item">
            <div class="rem-header">
                {sev_badge(sev)}
                {f'<span class="cvss-badge">{cve}</span>' if cve else ''}
            </div>
            <h4>{one_liner}</h4>
            <p class="rem-desc">{summary}</p>
            <div class="rem-actions">
                <p><strong>Recommended Actions:</strong></p>
                {cmd_html}
            </div>
        </div>"""
            return f"""
        <h2>Remediation Actions</h2>
        <p>Actionable remediation steps sorted by severity. Commands can be copy-pasted directly.</p>
        {sections}"""

        # =================================================================
        # Per-host sections (aggregate mode only)
        # =================================================================

        per_host_sections = ""
        if context["_is_aggregate"]:
            for h in context["hosts"]:
                host_findings = h["findings"]
                host_threats = h["threats"]
                sev_c = h["sev_counts"]
                finding_rows_html = _build_findings_table(host_findings, max_rows=200)
                threat_cards_html = _build_threat_cards(host_threats) if host_threats else ""

                per_host_sections += f"""
        <div class="host-section">
            <h2>Host: {h['host_id']} &mdash; {h['os']}</h2>
            <div class="host-meta">
                <span>Total Findings: <strong>{len(host_findings)}</strong></span>
                <span>Critical: <strong style="color:var(--critical);">{sev_c.get('critical',0)}</strong></span>
                <span>High: <strong style="color:var(--high);">{sev_c.get('high',0)}</strong></span>
                <span>Medium: <strong style="color:var(--medium);">{sev_c.get('medium',0)}</strong></span>
                <span>Low: <strong style="color:var(--low);">{sev_c.get('low',0)}</strong></span>
                <span>Threat Score: <strong style="color:{h['score_color']};">{h['score']} {h['score_label']}</strong></span>
            </div>
            {finding_rows_html}
            {threat_cards_html}
        </div>"""

        # =================================================================
        # Assemble level-specific content
        # =================================================================

        level = context.get("_level", "detail")

        # All levels start with the "brief" content
        brief_section = (
            threat_score_html + severity_legend + host_summary_html + risk_profile_html
        )

        # Detail findings (combined or per-host)
        if context["_is_aggregate"]:
            # aggregate: use per-host sections for detail+
            detail_section = per_host_sections
        else:
            detail_section = _build_findings_table(context["findings"])

        # Threat cards
        threat_section = _build_threat_cards(context.get("cve_refs", []))

        # Remediation
        remediation_section = _build_remediation_section(context.get("remediation", []))

        # Level-specific assembly
        if level == "brief":
            extra = brief_section
        elif level == "detail":
            extra = brief_section + detail_section
        elif level == "threat":
            extra = brief_section + detail_section + threat_section
        elif level == "remediation":
            # No threat section, no brief — just detail findings + remediation
            extra = detail_section + remediation_section
        else:
            extra = brief_section + detail_section

        # =================================================================
        # Final HTML
        # =================================================================
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{c.get('name', 'Security')} — Penetration Test Report</title>
{full_css}
</head>
<body>
<div class="container">
    <div class="classification">{stationery.get('classification', 'CONFIDENTIAL')}</div>
    <div class="header">
        <h1>{c.get('name', 'Security')} — Penetration Test Report</h1>
        <div class="subtitle">{c.get('tagline', '')}</div>
    </div>

    <div class="meta">
        <div class="meta-grid">
            <div class="meta-item"><strong>Customer:</strong> {context['customer_name']}</div>
            <div class="meta-item"><strong>Site:</strong> {context['site_name']}</div>
            {f'<div class="meta-item"><strong>Host:</strong> {context.get("host_id", "")}</div>' if context.get('host_id') else ''}
            <div class="meta-item"><strong>Report Date:</strong> {context['report_date']}</div>
            <div class="meta-item"><strong>Scan Tier:</strong> {context['summary'].get('tier', 'N/A')}</div>
            {"" if context.get('_is_aggregate') else f'<div class="meta-item"><strong>Detected OS:</strong> {context.get("host_os", "Unknown")}</div>'}
            {"" if context.get('_is_aggregate') else f'<div class="meta-item"><strong>Hardware:</strong> {context.get("host_hardware", "N/A")}</div>'}
            <div class="meta-item"><strong>Classification:</strong> {stationery.get('classification', 'CONFIDENTIAL')}</div>
        </div>
        <p style="margin-top: 0.75rem; font-style: italic;">{context['scan_notes']}</p>
    </div>

{exec_cards}

{extra}

    <div class="footer">
        <p>{stationery.get('footer', 'Generated by iStrix')}</p>
        <p>{context['report_date']} — {c.get('name', '')}</p>
    </div>
</div>
</body>
</html>"""

    # ------------------------------------------------------------------
    # Markdown rendering
    # ------------------------------------------------------------------

    def _render_md(self, context: dict, base_name: str) -> Path:
        md = self._render_md_content(context)
        path = self.config.output_dir / f"{base_name}.md"
        path.write_text(md)
        return path

    def _render_md_content(self, context: dict) -> str:
        b = context["branding"]
        c = b.get("company", {})
        stationery = b.get("report_stationery", {})

        lines: list[str] = []
        lines.append(f"# {c.get('name', 'Security')} — Penetration Test Report")
        lines.append(f"**{c.get('tagline', '')}**")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## Scan Information")
        lines.append(f"- **Customer:** {context['customer_name']}")
        lines.append(f"- **Site:** {context['site_name']}")
        if context.get('host_id'):
            lines.append(f"- **Host:** {context['host_id']}")
        lines.append(f"- **Date:** {context['report_date']}")
        if not context.get('_is_aggregate'):
            lines.append(f"- **Detected OS:** {context.get('host_os', 'Unknown')}")
            lines.append(f"- **Hardware:** {context.get('host_hardware', 'N/A')}")
        lines.append(f"- **Notes:** {context['scan_notes']}")
        lines.append("")
        lines.append("## Executive Summary")
        lines.append(f"- **Hosts Scanned:** {context['summary']['hosts_scanned']}")
        lines.append(f"- **Open Ports:** {context['summary']['ports_open']}")
        lines.append(
            f"- **Critical:** {context['total_critical']} | "
            f"**High:** {context['total_high']} | "
            f"**Medium:** {context['total_medium']} | "
            f"**Low:** {context['total_low']}"
        )
        lines.append(f"- **Total Findings:** {context['summary']['total_findings']}")
        lines.append(f"- **Threat Score:** {context['threat_score']}/100 — **{context['threat_score_label']}**")
        lines.append("")

        # Host summary for aggregate
        if context["_is_aggregate"] and context.get("host_summary"):
            lines.append("## Target Hosts Overview")
            lines.append("| Host | OS | Critical | High | Medium | Low | Total | Score |")
            lines.append("|------|----|----------|------|--------|-----|-------|-------|")
            for hs in context["host_summary"]:
                lines.append(
                    f"| {hs['host']} | {hs['os']} | {hs['critical']} | {hs['high']} | "
                    f"{hs['medium']} | {hs['low']} | {hs['total']} | "
                    f"{hs['score']} {hs['label']} |"
                )
            lines.append("")

        level = context.get("_level", "detail")

        # Findings (per-host in aggregate)
        if context["_is_aggregate"]:
            for h in context["hosts"]:
                lines.append(f"## Host: {h['host_id']} — {h['os']}")
                lines.append(
                    f"- Findings: {len(h['findings'])} | "
                    f"Critical: {h['sev_counts'].get('critical',0)} | "
                    f"High: {h['sev_counts'].get('high',0)} | "
                    f"Score: {h['score']} {h['score_label']}"
                )
                lines.append("")
                lines.append("| Host | Port | Proto | Finding | Severity |")
                lines.append("|------|------|-------|---------|----------|")
                for f in h["findings"][:200]:
                    host = f.get("host", "")
                    port = str(f.get("port", "")) if f.get("port") else "-"
                    proto = f.get("protocol", "-") or "-"
                    detail = (f.get("detail", "") or "")[:80]
                    sev = f.get("severity", "info")
                    cve_str = f" ({f['cve']})" if f.get("cve") else ""
                    lines.append(f"| {host} | {port} | {proto} | {detail}{cve_str} | **{sev.upper()}** |")
                lines.append("")
        else:
            lines.append("## Detailed Findings")
            lines.append("| Host | Port | Proto | Finding | Severity |")
            lines.append("|------|------|-------|---------|----------|")
            for f in context["findings"][:200]:
                host = f.get("host", "")
                port = str(f.get("port", "")) if f.get("port") else "-"
                proto = f.get("protocol", "-") or "-"
                detail = (f.get("detail", "") or "")[:80]
                sev = f.get("severity", "info")
                cve_str = f" ({f['cve']})" if f.get("cve") else ""
                lines.append(f"| {host} | {port} | {proto} | {detail}{cve_str} | **{sev.upper()}** |")
            lines.append("")

        # Threat cards
        if level in ("threat",) and context.get("cve_refs"):
            lines.append("## Threat Assessment — CVE Details")
            for cve_ref in context["cve_refs"]:
                cve = cve_ref.get("cve", "")
                title = cve_ref.get("title", "")
                summary = cve_ref.get("summary", "")
                exploit = cve_ref.get("exploit_narrative", "")
                nvd = cve_ref.get("nvd_url", "")
                cvss = cve_ref.get("cvss", "N/A")
                sev = cve_ref.get("severity", "info")
                lines.append(f"### {cve}: {title}" if cve else f"### {title}")
                lines.append(f"- **Severity:** {sev.upper()} | **CVSS:** {cvss}")
                if nvd:
                    lines.append(f"- **NVD:** [{cve}]({nvd})")
                lines.append("")
                lines.append(summary)
                lines.append("")
                if exploit:
                    lines.append(f"**Exploitation & Impact:** {exploit}")
                    lines.append("")
                commands = cve_ref.get("commands", [])
                if commands:
                    lines.append("**Remediation:**")
                    for cmd in commands:
                        lines.append(f"- `{cmd}`")
                    lines.append("")
                else:
                    lines.append("*Fixes not available yet*")
                    lines.append("")
                lines.append("---")
                lines.append("")

        # Remediation
        if level in ("remediation",) and context.get("remediation"):
            lines.append("## Remediation Actions")
            lines.append("")
            for r in context["remediation"]:
                sev = r.get("severity", "info")
                cve = r.get("cve", "")
                title = r.get("title", "")
                one_liner = title.split(": ", 1)[-1] if ": " in title else title
                summary = r.get("summary", "")[:200]
                commands = r.get("commands", [])
                lines.append(f"### {sev.upper()} — {cve}: {one_liner}" if cve else f"### {sev.upper()} — {one_liner}")
                lines.append("")
                lines.append(summary)
                lines.append("")
                if commands:
                    lines.append("**Commands:**")
                    lines.append("```bash")
                    for cmd in commands:
                        lines.append(cmd)
                    lines.append("```")
                    lines.append("")
                else:
                    lines.append("_Fixes not available yet_")
                    lines.append("")
                lines.append("---")
                lines.append("")

        lines.append("")
        lines.append(f"*{stationery.get('footer', 'Generated by iStrix')}*")
        lines.append(f"*{context['report_date']} — {c.get('name', '')}*")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # JSON rendering
    # ------------------------------------------------------------------

    def _render_json(self, context: dict, base_name: str) -> Path:
        serializable = {
            k: v
            for k, v in context.items()
            if isinstance(v, (str, int, float, bool, list, dict, type(None)))
        }
        path = self.config.output_dir / f"{base_name}.json"
        path.write_text(_std_json.dumps(serializable, indent=2, default=str))
        return path


# ──────────────────────────────────────────────────────────────────────────────
# Convenience function (updated signature)
# ──────────────────────────────────────────────────────────────────────────────


def generate_report(
    results_paths: list[str],
    level: str = "detail",
    output_format: str = "html",
    output_dir: str = ".",
    customer_name: str = "",
    site_name: str = "",
    scan_notes: str = "",
    risk_profile: RiskProfile | None = None,
) -> Path:
    """Generate a professional pentest report from scan results.

    Supports single-host and multi-host aggregate reports.

    Args:
        results_paths: List of paths to iStrix JSON result files.
            Single element = per-host report. Multiple = aggregate report.
        level: Report level — brief, detail, threat, or remediation.
        output_format: Output format — html, pdf, md, or json.
        output_dir: Directory to write report to.
        customer_name: Customer name for the report header.
        site_name: Site name for the report header.
        scan_notes: Notes about the scan to include.
        risk_profile: Risk assessment criteria (scope, data sensitivity, etc.).

    Returns:
        Path to the generated report file.
    """
    config = ReportConfig(
        results_paths=results_paths,
        level=level,
        output_format=output_format,
        output_dir=output_dir,
        customer_name=customer_name,
        site_name=site_name,
        scan_notes=scan_notes,
        risk_profile=risk_profile,
    )
    generator = ReportGenerator(config)
    return generator.generate()


def generate_report_index(
    output_dir: str = ".",
    customer_name: str = "",
    site_name: str = "",
    scan_summary: dict | None = None,
    scan_notes: str = "",
) -> Path:
    """Generate an index.html page listing all reports in the output directory.

    Args:
        output_dir: Directory containing generated reports.
        customer_name: Customer name for the page header.
        site_name: Site name for the page header.
        scan_summary: Optional dict with scan stats (hosts_scanned, total_findings,
                      by_severity, scan_date, tier, target, subnets_discovered).
        scan_notes: Optional notes about the scan job.
    Returns:
        Path to the generated index.html.
    """
    from pathlib import Path as _Path
    from collections import defaultdict

    out = _Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    groups: dict[str, list[dict]] = defaultdict(list)
    type_files: dict[str, dict[str, list[_Path]]] = defaultdict(lambda: defaultdict(list))
    for f in sorted(out.glob("istrix_report_*.*")):
        name = f.stem
        tail = name.replace("istrix_report_", "", 1)
        parts = tail.split("_", 1)
        if len(parts) < 2:
            continue
        report_type = parts[0]
        fmt = f.suffix.lstrip(".")
        type_files[report_type][fmt].append(f)

    type_order = {"brief": 0, "detail": 1, "threat": 2, "remediation": 3}
    for report_type in sorted(type_files, key=lambda t: type_order.get(t, 99)):
        fmt_map = type_files[report_type]
        html_files = sorted(fmt_map.get("html", []))
        pdf_files = sorted(fmt_map.get("pdf", []), key=lambda p: p.stem)
        md_files = sorted(fmt_map.get("md", []), key=lambda p: p.stem)
        for i, hf in enumerate(html_files):
            host_info = ""
            pdf_rel = str(pdf_files[i].relative_to(out)) if i < len(pdf_files) else None
            md_rel = str(md_files[i].relative_to(out)) if i < len(md_files) else None
            groups[report_type].append({
                "type": report_type.title(),
                "type_key": report_type,
                "host": host_info or site_name or "scan",
                "basename": hf.stem,
                "html": str(hf.relative_to(out)),
                "pdf": pdf_rel,
                "md": md_rel,
            })

    sorted_groups = sorted(groups.items(), key=lambda x: type_order.get(x[0], 99))

    # Collect per-host directories — detect subnet grouping
    host_dirs: list[str] = []
    subnet_groups: dict[str, list[str]] = {}

    for d in sorted(out.iterdir(), key=lambda p: p.name):
        if d.is_dir() and (d / "index.html").exists() and "." in d.name:
            host_dirs.append(d.name)
        elif d.is_dir():
            hosts_inside = sorted(
                [s for s in d.iterdir() if s.is_dir() and "." in s.name],
                key=lambda p: _ip_sort_key(p.name),
            )
            if hosts_inside:
                subnet_groups[d.name] = [h.name for h in hosts_inside]

    rows = ""
    # Subnet-aware: show subnet groups with hosts inside
    if subnet_groups:
        if (out / "forest-map.html").exists():
            rows += '<tr style="background:#1a365d;"><td colspan="3"><a href="forest-map.html" style="color:white;font-weight:bold;"> Forest Map — AD Topology</a></td></tr>'
        rows += f'<tr style="background:var(--bg);"><td colspan="3"><strong>Per-Host Reports ({sum(len(v) for v in subnet_groups.values())} hosts across {len(subnet_groups)} subnets)</strong></td></tr>'
        def _subnet_sort(name):
            for hd in subnet_groups.get(name, []):
                try:
                    return tuple(int(o) for o in hd.split("."))
                except ValueError:
                    pass
            import re as _re
            m = _re.match(r'(\d+)\.(\d+)\.(\d+)', name)
            if m:
                return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
            return (255, 255, 255)
        for subnet_name in sorted(subnet_groups, key=_subnet_sort):
            sub_hosts = subnet_groups[subnet_name]
            ip_prefix = ""
            if sub_hosts:
                octets = sub_hosts[0].split(".")[:3]
                ip_prefix = ".".join(octets)
            label = f"{subnet_name}"
            if ip_prefix:
                label = f"{ip_prefix}.0/24 — {subnet_name}"
            rows += (
                f'<tr style="background:#1a365d;">'
                f'<td colspan="2">'
                f'<a href="{subnet_name}/index.html" style="color:white;font-weight:bold;">'
                f' {label} — {len(sub_hosts)} hosts</a>'
                f'</td>'
                f'<td class="fmts"><a href="{subnet_name}/index.html" class="fmt-html">Open →</a></td>'
                f'</tr>'
            )
    elif host_dirs:
        if (out / "forest-map.html").exists():
            rows += '<tr style="background:#1a365d;"><td colspan="3"><a href="forest-map.html" style="color:white;font-weight:bold;"> Forest Map</a></td></tr>'
        rows += f'<tr style="background:var(--bg);"><td colspan="3"><strong>Per-Host Reports ({len(host_dirs)} hosts)</strong></td></tr>'
        for hd in sorted(host_dirs, key=_ip_sort_key):
            rows += f'<tr><td colspan="2"><a href="{hd}/index.html">{hd}</a></td>'
            rows += f'<td class="fmts"><a href="{hd}/index.html" class="fmt-html">Open →</a></td></tr>'

    # Aggregate report files (always shown)
    for type_key, reports in sorted_groups:
        for i, r in enumerate(reports):
            html_link = f'<a href=\"{r["html"]}\" class=\"fmt-html\" target=\"_blank\">HTML</a>'
            pdf_link = f'<a href=\"{r["pdf"]}\" class=\"fmt-pdf\" target=\"_blank\">PDF</a>' if r["pdf"] else '<span class=\"fmt-pdf missing\">—</span>'
            md_link = f'<a href=\"{r["md"]}\" class=\"fmt-md\" target=\"_blank\">MD</a>' if r["md"] else '<span class=\"fmt-md missing\">—</span>'
            rows += "<tr>"
            rows += f'<td><strong>{r["type"]}</strong></td>'
            rows += f'<td>{r["host"]}</td>'
            rows += f'<td class=\"fmts\">{html_link} {pdf_link} {md_link}</td>'
            rows += "</tr>"

    # --- Build scan job summary section ---
    scan_job_html = ""
    if scan_summary:
        ss = scan_summary
        sev = ss.get("by_severity", {})
        total = ss.get("total_findings", ss.get("hosts_scanned", 0))
        crit = sev.get("critical", 0)
        high = sev.get("high", 0)
        med = sev.get("medium", 0)
        low = sev.get("low", 0)
        info_val = sev.get("info", max(0, total - crit - high - med - low))
        # severity bar widths
        def _pct(n): return max(n / max(total, 1) * 100, 2)
        scan_meta = ""
        if ss.get("scan_date"):
            scan_meta += f'<div class="sm-item"><strong>Date</strong> {ss["scan_date"]}</div>'
        if ss.get("tier"):
            scan_meta += f'<div class="sm-item"><strong>Tier</strong> {ss["tier"]}</div>'
        if ss.get("target"):
            target_str = ss["target"]
            if ss.get("subnets_discovered"):
                target_str += f' → {ss["subnets_discovered"]} subnets (DNS forest discovery)'
            scan_meta += f'<div class="sm-item"><strong>Target</strong> {target_str}</div>'
        scan_meta += f'<div class="sm-item"><strong>Hosts</strong> {ss.get("hosts_scanned", "—")}</div>'
        scan_meta += f'<div class="sm-item"><strong>Findings</strong> {total:,}</div>'
        if scan_notes:
            scan_meta += f'<div class="sm-item" style="grid-column:1/-1;font-style:italic;color:var(--info);">{scan_notes}</div>'
        scan_job_html = f"""
    <div class="summary-section">
        <h2>Scan Job</h2>
        <div class="scan-meta">{scan_meta}</div>
    </div>
    <div class="summary-section">
        <h2>Findings by Severity</h2>
        <div class="summary-cards">
            <div class="card"><div class="count" style="color:var(--critical);">{crit:,}</div><div class="label">Critical</div></div>
            <div class="card"><div class="count" style="color:var(--high);">{high:,}</div><div class="label">High</div></div>
            <div class="card"><div class="count" style="color:var(--medium);">{med:,}</div><div class="label">Medium</div></div>
            <div class="card"><div class="count" style="color:var(--low);">{low:,}</div><div class="label">Low</div></div>
            <div class="card"><div class="count" style="color:var(--info);">{info_val:,}</div><div class="label">Info</div></div>
        </div>
        <div class="severity-bar">
            <div style="width:{_pct(crit):.1f}%;background:var(--critical);"></div>
            <div style="width:{_pct(high):.1f}%;background:var(--high);"></div>
            <div style="width:{_pct(med):.1f}%;background:var(--medium);"></div>
            <div style="width:{_pct(low):.1f}%;background:var(--low);"></div>
            <div style="width:{_pct(info_val):.1f}%;background:var(--info);"></div>
        </div>
    </div>"""

    # --- Build disclaimer section ---
    disclaimer_html = """
    <div class="disclaimer">
        <h2>Disclaimer</h2>
        <p>This is an automated penetration test report generated by iStrix operating in
        manual mode. No AI was used in scanning, testing, or report generation. Findings
        are produced by deterministic tooling (nmap, NVD CVE database, in-house
        hardware/OS fingerprinting). Manual validation of all findings is recommended.</p>
        <p>iStrix uses AI exclusively for the vector-based CVE semantic search engine
        which matches vague service banners to known vulnerabilities.</p>
        <p>Learn more: <a href="istrix.html">istrix.html</a></p>
        <div class="warning">
            <h3>Remediation Warning</h3>
            <p>The remediation engine provides suggestions only, intended for qualified
            security professionals. <strong>DO NOT attempt remediation without professional
            assistance.</strong></p>
            <p><strong class="danger">Improper execution can RENDER YOUR EQUIPMENT
            INOPERABLE and cause TOTAL DATA LOSS.</strong></p>
            <p><strong>YOU ASSUME ALL RISKS</strong> if you perform remediation yourself.
            By using any information in this report, you agree to hold FCS llc and its
            agents harmless from any damages, losses, or claims arising from its use.</p>
        </div>
    </div>"""

    # --- Build the HTML ---
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>iStrix Report Index — {customer_name or site_name or 'Scan'}</title>
<style>
:root {{
    --primary: #1a365d; --accent: #3182ce; --bg: #f7fafc; --text: #2d3748;
    --border: #e2e8f0; --info: #718096; --critical: #e53e3e; --high: #dd6b20;
    --medium: #d69e2e; --low: #38a169;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: system-ui, -apple-system, sans-serif; color: var(--text); background: var(--bg); line-height: 1.6; }}
.container {{ max-width: 860px; margin: 2rem auto; padding: 0 1rem; }}
.header {{ background: var(--primary); color: white; padding: 1.5rem; border-radius: 8px 8px 0 0; text-align: center; }}
.header h1 {{ font-size: 1.4rem; }}
.header .subtitle {{ opacity: 0.75; font-size: 0.85rem; margin-top: 0.25rem; }}
.header .branding {{ font-size: 0.75rem; opacity: 0.6; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 0.5rem; }}
.content {{ background: white; border: 1px solid var(--border); border-top: none; padding: 1.5rem; border-radius: 0 0 8px 8px; }}
.classification {{ background: var(--critical); color: white; text-align: center; padding: 0.4rem; font-weight: bold; letter-spacing: 2px; font-size: 0.8rem; border-radius: 8px 8px 0 0; }}
.summary-section {{ margin-bottom: 1.5rem; }}
.summary-section h2 {{ font-size: 1rem; color: var(--primary); border-bottom: 2px solid var(--accent); padding-bottom: 0.3rem; margin-bottom: 0.75rem; }}
.scan-meta {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0.4rem 1rem; font-size: 0.9rem; }}
.sm-item strong {{ color: var(--primary); }}
.summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 0.75rem; }}
.card {{ background: #f7fafc; border: 1px solid var(--border); border-radius: 6px; padding: 0.75rem; text-align: center; }}
.card .count {{ font-size: 1.5rem; font-weight: bold; }}
.card .label {{ color: var(--info); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.5px; }}
.severity-bar {{ display: flex; height: 8px; border-radius: 4px; overflow: hidden; margin-top: 0.75rem; }}
.severity-bar div {{ height: 100%; }}
.disclaimer {{ background: #fffbeb; border: 1px solid #f6e05e; border-radius: 6px; padding: 1rem; margin-bottom: 1.5rem; font-size: 0.85rem; line-height: 1.5; }}
.disclaimer h2 {{ font-size: 1rem; color: var(--primary); margin-bottom: 0.5rem; }}
.disclaimer h3 {{ font-size: 0.9rem; color: var(--critical); margin: 0.75rem 0 0.25rem; }}
.disclaimer p {{ margin-bottom: 0.4rem; }}
.warning {{ background: #fff5f5; border: 1px solid #fc8181; border-radius: 4px; padding: 0.75rem; margin-top: 0.5rem; }}
.danger {{ color: var(--critical); font-weight: bold; }}
table {{ width: 100%; border-collapse: collapse; }}
th {{ background: var(--primary); color: white; padding: 0.6rem 0.75rem; text-align: left; font-size: 0.85rem; }}
td {{ padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
tr:hover {{ background: var(--bg); }}
.fmts {{ white-space: nowrap; }}
.fmts a {{ display: inline-block; padding: 3px 10px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; text-decoration: none; margin-right: 4px; }}
.fmt-html {{ background: #e2e8f0; color: var(--primary); }}
.fmt-pdf {{ background: #fed7d7; color: #c53030; }}
.fmt-md {{ background: #c6f6d5; color: #276749; }}
.fmts .missing {{ opacity: 0.3; font-size: 0.8rem; }}
.filters {{ margin-bottom: 1rem; display: flex; gap: 0.5rem; flex-wrap: wrap; }}
.filters button {{ padding: 0.4rem 1rem; border: 1px solid var(--border); border-radius: 4px; background: white; cursor: pointer; font-size: 0.85rem; }}
.filters button.active {{ background: var(--primary); color: white; border-color: var(--primary); }}
.filters button:hover {{ background: var(--accent); color: white; }}
.footer {{ text-align: center; padding: 1.5rem; color: var(--info); font-size: 0.8rem; margin-top: 1.5rem; border-top: 2px solid var(--border); }}
.footer a {{ color: var(--accent); text-decoration: none; }}
.footer a:hover {{ text-decoration: underline; }}
</style>
<script>
function filterFormat(fmt) {{
    document.querySelectorAll('.filters button').forEach(b => b.classList.remove('active'));
    document.getElementById('btn-' + fmt).classList.add('active');
    document.querySelectorAll('.fmts a').forEach(a => a.style.opacity = '1');
    if (fmt !== 'all') {{
        document.querySelectorAll('.fmts a:not(.fmt-' + fmt + ')').forEach(a => a.style.opacity = '0.25');
    }}
}}
</script>
</head>
<body>
<div class="container">
    <div class="classification">CONFIDENTIAL</div>
    <div class="header">
        <div class="branding">FCS llc — Data and Compute Infrastructure Specialist</div>
        <h1>Penetration Test Report Index</h1>
        <div class="subtitle">{customer_name or 'Security Assessment'} — {site_name or 'Scan Results'}</div>
    </div>
    <div class="content">
        {scan_job_html}
        {disclaimer_html}
        <div class="filters">
            <button id="btn-all" class="active" onclick="filterFormat('all')">All Formats</button>
            <button id="btn-html" onclick="filterFormat('html')">HTML</button>
            <button id="btn-pdf" onclick="filterFormat('pdf')">PDF</button>
            <button id="btn-md" onclick="filterFormat('md')">Markdown</button>
        </div>
        <table>
            <thead><tr><th>Report Type</th><th>Source</th><th>Formats</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </div>
    <div class="footer">
        <p>&copy; {ss.get("year", "2026") if scan_summary else "2026"} FCS llc. All rights reserved.</p>
        <p>Generated by <a href="istrix.html">iStrix</a> — AI-Powered Pentest Orchestration Toolkit (Apache 2.0)</p>
    </div>
</div>
</body>
</html>"""

    index_path = out / "index.html"
    index_path.write_text(html)
    return index_path


def generate_per_host_reports(
    results_path: str,
    levels: list[str] | None = None,
    formats: list[str] | None = None,
    output_dir: str = ".",
    customer_name: str = "",
    site_name: str = "",
    scan_notes: str = "",
    risk_profile: RiskProfile | None = None,
    max_workers: int | None = None,
    subnet_map: dict[str, str] | None = None,
) -> list[Path]:
    """Generate per-host reports organized in subdirectories + aggregate brief.

    When subnet_map is provided (e.g., from DNS forest discovery), hosts are
    grouped under subnet directories: reports/<site>/<host_ip>/.
    The top-level index lists subnets; each subnet dir has its own per-host index.

    Args:
        results_path: Path to the JSON scan results.
        levels: Report levels (default: all 4).
        formats: Output formats (default: html, pdf, md).
        output_dir: Base output directory.
        customer_name, site_name, scan_notes: Report metadata.
        risk_profile: Risk assessment criteria.
        max_workers: Max parallel workers (None = sequential).
        subnet_map: {subnet_cidr: site_name} for subnet grouping.

    Returns:
        List of paths to all generated report files.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import json as _std_json

    if levels is None:
        levels = ["brief", "detail", "threat", "remediation"]
    if formats is None:
        formats = ["html", "pdf", "md"]

    sr = load_from_json(results_path)
    hosts: dict[str, list] = {}
    for f in sr.findings:
        hosts.setdefault(f.host, []).append(f)

    # Compute scan summary for index + about pages
    sev_counts: dict[str, int] = {}
    for f in sr.findings:
        sv = f.severity if hasattr(f, "severity") else getattr(f, "severity", "info")
        sev_counts[sv] = sev_counts.get(sv, 0) + 1
    valid_hosts = {h for h in hosts if h not in ("0.0.0.0", "127.0.0.1")}
    subnet_count = len({".".join(h.split(".")[:3]) for h in valid_hosts if "." in h})
    scan_summary = {
        "hosts_scanned": len(valid_hosts),
        "total_findings": len(sr.findings),
        "by_severity": sev_counts,
        "scan_date": getattr(sr, "started_at", "") or "",
        "tier": getattr(sr.config, "tier", "N/A") if hasattr(sr, "config") else "N/A",
        "target": ", ".join(getattr(sr.config, "targets", ["N/A"])) if hasattr(sr, "config") else "N/A",
        "subnets_discovered": subnet_count,
        "year": __import__("datetime").datetime.now().year,
    }

    if len(hosts) <= 1:
        return [generate_report(
            results_paths=[results_path],
            level="detail",
            output_format=formats[0],
            output_dir=output_dir,
            customer_name=customer_name,
            site_name=site_name,
            scan_notes=scan_notes,
            risk_profile=risk_profile,
        )]

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    generated: list[Path] = []

    # 0. Clean old per-host report files (only for formats being generated)
    for d in out.iterdir():
        if d.is_dir() and "." in d.name:  # per-host dirs like 10.0.0.x
            for fmt in formats:
                for old_file in d.glob(f"istrix_report_*.{fmt}"):
                    try:
                        old_file.unlink()
                    except OSError:
                        pass

    # Clean old aggregate reports (only for formats being generated)
    for fmt in formats:
        for old_file in out.glob(f"istrix_report_*.{fmt}"):
            try:
                old_file.unlink()
            except OSError:
                pass

    # 1. Aggregate reports (all levels, uses is_aggregate gating)
    for lvl in levels:
        for fmt in formats:
            try:
                p = generate_report(
                    results_paths=[results_path],
                    level=lvl,
                    output_format=fmt,
                    output_dir=str(out),
                    customer_name=customer_name,
                    site_name=site_name,
                    scan_notes=scan_notes,
                    risk_profile=risk_profile,
                )
                generated.append(p)
            except Exception:
                pass

    # 2. Per-host reports — prepare host JSONs first (fast)
    # Build IP → site lookup from subnet_map
    ip_to_site: dict[str, str] = {}
    if subnet_map:
        for sn_cidr, site in subnet_map.items():
            try:
                parts = sn_cidr.split("/")
                net = parts[0].split(".")
                prefix = int(parts[1]) if len(parts) > 1 else 24
                octets = min(3, max(1, prefix // 8))  # /24→3, /16→2, /8→1
                base = ".".join(net[:octets])
                ip_to_site[base] = site
            except (ValueError, IndexError):
                base = ".".join(sn_cidr.split("/")[0].split(".")[:3])
                ip_to_site[base] = site

    host_entries: list[tuple[str, Path, list]] = []
    for host_ip in sorted(hosts, key=_ip_sort_key):
        if host_ip in ("0.0.0.0", "127.0.0.1"):  # skip invalid host placeholders
            continue
        host_findings = hosts[host_ip]

        # Determine host directory: under subnet folder if available
        # Match against ip_to_site using progressively shorter prefixes
        host_octets = host_ip.split(".")
        ip_prefix = ""
        for n in (3, 2, 1):
            candidate = ".".join(host_octets[:n])
            if candidate in ip_to_site:
                ip_prefix = candidate
                break
        site = ip_to_site.get(ip_prefix, "")
        if site and subnet_map:
            host_dir = out / site / host_ip
        else:
            host_dir = out / host_ip
        host_dir.mkdir(parents=True, exist_ok=True)
        host_config = ScanConfig(tier="N/A", targets=[host_ip])
        host_result = ScanResult(config=host_config, findings=host_findings)
        host_json = host_dir / f"{host_ip}.json"
        host_json.write_text(_std_json.dumps({
            "version": "0.1.0",
            "config": host_config.model_dump(),
            "findings": [f.model_dump() for f in host_findings],
            "summary": host_result.summary(),
            "errors": [],
        }, indent=2, default=str))
        host_entries.append((host_ip, host_json, host_findings))

    # --- Report generation task runner ---
    def _gen_one(host_json: Path, host_dir: Path, lvl: str, fmt: str) -> bool:
        try:
            generate_report(
                results_paths=[str(host_json)],
                level=lvl,
                output_format=fmt,
                output_dir=str(host_dir),
                customer_name=customer_name,
                site_name=site_name,
                scan_notes=scan_notes,
                risk_profile=risk_profile,
            )
            return True
        except Exception:
            return False

    if max_workers:
        non_pdf_fmts = [f for f in formats if f != "pdf"]
        has_pdf = "pdf" in formats

        # Phase 2a: HTML + MD in parallel (I/O-bound, many workers)
        if non_pdf_fmts:
            tasks = []
            for _host_ip, host_json, _findings in host_entries:
                host_dir = host_json.parent
                for lvl in levels:
                    for fmt in non_pdf_fmts:
                        tasks.append((host_json, host_dir, lvl, fmt))

            done = 0
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {ex.submit(_gen_one, *t): t for t in tasks}
                for _ in as_completed(futures):
                    done += 1
            generated.extend([Path("")] * (len(host_entries) * len(levels) * len(non_pdf_fmts)))

        # Phase 2b: PDF in parallel (CPU-bound, weasyprint caps at ~3.5 cores)
        if has_pdf:
            tasks = []
            for _host_ip, host_json, _findings in host_entries:
                host_dir = host_json.parent
                for lvl in levels:
                    tasks.append((host_json, host_dir, lvl, "pdf"))

            done = 0
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {ex.submit(_gen_one, *t): t for t in tasks}
                for _ in as_completed(futures):
                    done += 1
            generated.extend([Path("")] * (len(host_entries) * len(levels)))
    else:
        # Sequential mode
        for _host_ip, host_json, _findings in host_entries:
            host_dir = host_json.parent
            for lvl in levels:
                for fmt in formats:
                    try:
                        p = generate_report(
                            results_paths=[str(host_json)],
                            level=lvl,
                            output_format=fmt,
                            output_dir=str(host_dir),
                            customer_name=customer_name,
                            site_name=site_name,
                            scan_notes=scan_notes,
                            risk_profile=risk_profile,
                        )
                        generated.append(p)
                    except Exception:
                        pass

    # 3. Index page
    try:
        idx = generate_report_index(
            output_dir=str(out),
            customer_name=customer_name,
            site_name=site_name,
            scan_summary=scan_summary,
            scan_notes=scan_notes,
        )
        generated.append(idx)
    except Exception:
        pass

    # 4. Per-host index pages
    for host_ip in sorted(hosts, key=_ip_sort_key):
        if host_ip in ("0.0.0.0", "127.0.0.1"):
            continue
        host_octets = host_ip.split(".")
        ip_prefix = ""
        for n in (3, 2, 1):
            cand = ".".join(host_octets[:n])
            if cand in ip_to_site:
                ip_prefix = cand
                break
        site = ip_to_site.get(ip_prefix, "")
        host_dir = out / site / host_ip if site else out / host_ip
        try:
            idx = generate_report_index(
                output_dir=str(host_dir),
                customer_name=customer_name,
                site_name=f"{site_name}/{host_ip}",
            )
            generated.append(idx)
        except Exception:
            pass

    # 4.5 Per-subnet index pages (when subnet_map active)
    if subnet_map:
        subnet_sites = set()
        for host_ip in sorted(hosts, key=_ip_sort_key):
            if host_ip in ("0.0.0.0", "127.0.0.1"):
                continue
            host_octets = host_ip.split(".")
            ip_prefix = ""
            for n in (3, 2, 1):
                cand = ".".join(host_octets[:n])
                if cand in ip_to_site:
                    ip_prefix = cand
                    break
            site = ip_to_site.get(ip_prefix, "")
            if site and site not in subnet_sites:
                subnet_sites.add(site)
                subnet_dir = out / site
                try:
                    idx = generate_report_index(
                        output_dir=str(subnet_dir),
                        customer_name=customer_name,
                        site_name=f"{site_name}/{site}",
                    )
                    generated.append(idx)
                except Exception:
                    pass

    # 5. Host summary page
    try:
        summary_path = generate_host_summary_page(
            results_path=results_path,
            output_dir=str(out),
            customer_name=customer_name,
            site_name=site_name,
        )
        generated.append(summary_path)
    except Exception:
        pass

    # 6. Forest map (if DNS probe data available)
    try:
        fm_path = generate_forest_map(
            scan_results=[(str(out), results_path)],
            dns_subnets={},
            output_dir=str(out),
            customer_name=customer_name,
        )
        if fm_path:
            generated.append(fm_path)
    except Exception:
        pass

    # 7. About iStrix page
    try:
        about_path = generate_istrix_about(
            output_dir=str(out),
            customer_name=customer_name,
            site_name=site_name,
            scan_summary=scan_summary,
        )
        generated.append(about_path)
    except Exception:
        pass

    return generated


# ------------------------------------------------------------------
# About iStrix page
# ------------------------------------------------------------------

def generate_istrix_about(
    output_dir: str = ".",
    customer_name: str = "",
    site_name: str = "",
    scan_summary: dict | None = None,
) -> Path:
    """Generate an istrix.html page describing iStrix features and capabilities."""
    from pathlib import Path as _Path

    out = _Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    ss = scan_summary or {}
    year = ss.get("year", __import__("datetime").datetime.now().year)
    hosts = ss.get("hosts_scanned", "—")
    findings = ss.get("total_findings", "—")
    tier = ss.get("tier", "N/A")
    target = ss.get("target", "N/A")
    subnets = ss.get("subnets_discovered", "—")
    scan_date = ss.get("scan_date", "")

    scan_context = ""
    if scan_summary:
        scan_context = f"""
    <div class="section">
        <h2>This Report</h2>
        <div class="meta-grid">
            <div class="m-item"><strong>Scan</strong> {customer_name} / {site_name}</div>
            <div class="m-item"><strong>Tier</strong> {tier}</div>
            <div class="m-item"><strong>Target</strong> {target} &rarr; {subnets} subnets (DNS forest discovery)</div>
            <div class="m-item"><strong>Hosts</strong> {hosts}</div>
            <div class="m-item"><strong>Findings</strong> {findings:,}</div>
            <div class="m-item"><strong>Date</strong> {scan_date}</div>
        </div>
    </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>About iStrix — Pentest Orchestration Toolkit</title>
<style>
:root {{
    --primary: #1a365d; --accent: #3182ce; --bg: #f7fafc; --text: #2d3748;
    --border: #e2e8f0; --info: #718096; --critical: #e53e3e; --high: #dd6b20;
    --medium: #d69e2e; --low: #38a169;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: system-ui, -apple-system, sans-serif; color: var(--text); background: var(--bg); line-height: 1.6; }}
.container {{ max-width: 860px; margin: 2rem auto; padding: 0 1rem; }}
.header {{ background: var(--primary); color: white; padding: 2rem; text-align: center; border-radius: 8px 8px 0 0; }}
.header h1 {{ font-size: 1.6rem; }}
.header .subtitle {{ opacity: 0.75; font-size: 0.9rem; margin-top: 0.25rem; }}
.header .branding {{ font-size: 0.75rem; opacity: 0.6; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 0.5rem; }}
.content {{ background: white; border: 1px solid var(--border); border-top: none; padding: 2rem; border-radius: 0 0 8px 8px; }}
.classification {{ background: var(--critical); color: white; text-align: center; padding: 0.4rem; font-weight: bold; letter-spacing: 2px; font-size: 0.8rem; border-radius: 8px 8px 0 0; }}
.section {{ margin-bottom: 2rem; }}
.section h2 {{ font-size: 1.1rem; color: var(--primary); border-bottom: 2px solid var(--accent); padding-bottom: 0.3rem; margin-bottom: 1rem; }}
.section h3 {{ font-size: 0.95rem; color: var(--primary); margin: 1rem 0 0.5rem; }}
.section p {{ margin-bottom: 0.6rem; font-size: 0.9rem; }}
.cap-grid {{ display: grid; grid-template-columns: 1fr; gap: 1rem; }}
.cap-card {{ background: #f7fafc; border: 1px solid var(--border); border-left: 4px solid var(--accent); border-radius: 6px; padding: 1rem; }}
.cap-card h4 {{ font-size: 0.9rem; color: var(--primary); margin-bottom: 0.4rem; }}
.cap-card ul {{ list-style: none; padding: 0; font-size: 0.85rem; }}
.cap-card li {{ padding: 0.15rem 0; }}
.cap-card li::before {{ content: "• "; color: var(--accent); }}
.cap-note {{ font-size: 0.85rem; color: var(--info); font-style: italic; margin-top: 0.5rem; }}
.warning {{ background: #fff5f5; border: 1px solid #fc8181; border-radius: 6px; padding: 1rem; margin: 1rem 0; }}
.warning h3 {{ color: var(--critical); font-size: 0.9rem; margin-bottom: 0.25rem; }}
.danger {{ color: var(--critical); font-weight: bold; }}
.meta-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0.4rem 1rem; font-size: 0.9rem; }}
.m-item strong {{ color: var(--primary); }}
.footer {{ text-align: center; padding: 1.5rem; color: var(--info); font-size: 0.8rem; margin-top: 1.5rem; border-top: 2px solid var(--border); }}
.footer a {{ color: var(--accent); text-decoration: none; }}
.footer a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<div class="container">
    <div class="classification">CONFIDENTIAL</div>
    <div class="header">
        <div class="branding">FCS llc — Data and Compute Infrastructure Specialist</div>
        <h1>iStrix</h1>
        <div class="subtitle">AI-Powered Penetration Test Orchestration Toolkit</div>
        <div style="margin-top:0.5rem;opacity:0.6;font-size:0.8rem;">Apache 2.0 License</div>
    </div>
    <div class="content">
        <div class="section">
            <h2>What Is iStrix?</h2>
            <p>iStrix is an open-source penetration testing orchestration toolkit combining
            nmap-based network scanning, CVE enrichment, OS-aware remediation, and professional
            report generation into a single CLI and API.</p>

            <h3>AI Usage</h3>
            <p>iStrix does <strong>NOT</strong> use AI for any scanning, testing, or reporting
            operations. All security assessments run in fully deterministic manual mode using
            industry-standard tools (nmap, NVD CVE database, in-house hardware/OS fingerprinting).</p>
            <p>AI is employed exclusively for the vector database that powers semantic CVE search.
            When regex-based matching fails to identify a CVE from a service banner, the vector
            engine finds known vulnerabilities by semantic similarity — e.g., matching
            regreSSHion from vague SSH descriptions at 76% accuracy.</p>
        </div>

        <div class="section">
            <h2>Key Capabilities</h2>
            <div class="cap-grid">
                <div class="cap-card">
                    <h4>Network Scanning (nmap)</h4>
                    <ul>
                        <li>5 tiered profiles: quick &rarr; aggressive</li>
                        <li>Parallel workers with adaptive tuning</li>
                        <li>CIDR expansion + incremental save/resume</li>
                        <li>DNS-based Active Directory forest auto-discovery</li>
                    </ul>
                </div>
                <div class="cap-card">
                    <h4>In-House Hardware &amp; OS Fingerprinting</h4>
                    <ul>
                        <li>LDAP RootDSE for authoritative Windows Server version (bypasses nmap OS guesses)</li>
                        <li>IIS httpd version &rarr; Server 2016/2019 identification</li>
                        <li>NetBIOS name resolution for AD domain enumeration</li>
                        <li>PJL/IPP printer model extraction (HP, Canon, Brother, etc.)</li>
                        <li>CDP/LLDP/SNMP network device discovery (Cisco, Juniper)</li>
                        <li>UPnP banner parsing for embedded/IoT devices</li>
                    </ul>
                    <p class="cap-note">This multi-layered profiling produces more accurate target
                    identification than nmap OS detection alone, in turn feeding more precise
                    remediation advice.</p>
                </div>
                <div class="cap-card">
                    <h4>OS-Aware Remediation Engine</h4>
                    <ul>
                        <li>7 OS families + RHEL sub-family + printer vendors + embedded/IoT</li>
                        <li>Correct package manager per platform: dnf vs apt vs winget vs IOS vs firmware</li>
                        <li>Auto-generated fix-version upgrade commands</li>
                        <li>Vendor-specific printer firmware upgrade URLs (HP, Canon, Brother, Epson, Xerox)</li>
                    </ul>
                </div>
                <div class="cap-card">
                    <h4>CVE Enrichment</h4>
                    <ul>
                        <li>NVD API integration via nvdlib (CVSS &ge; 7.0)</li>
                        <li>Vector-based semantic CVE search as fallback</li>
                        <li>Auto-sync vulndb with product-specific remediation commands</li>
                    </ul>
                </div>
                <div class="cap-card">
                    <h4>Professional Reporting</h4>
                    <ul>
                        <li>4 report levels: brief, detail, threat, remediation</li>
                        <li>3 output formats: HTML, PDF, Markdown</li>
                        <li>Per-host, per-subnet, and aggregate report generation</li>
                        <li>Subnet-aware organization with AD forest topology maps</li>
                        <li>Risk scoring with 12 assessment criteria</li>
                    </ul>
                </div>
                <div class="cap-card">
                    <h4>Platform &amp; Integration</h4>
                    <ul>
                        <li>FastAPI REST API (17 routes + WebSocket) on port 8443</li>
                        <li>PostgreSQL + pgvector for CVE storage and vector search</li>
                        <li>Plugin system with auto-discovery</li>
                        <li>Dark-theme GUI dashboard</li>
                        <li>AI planning/consultation via OpenRouter</li>
                    </ul>
                </div>
            </div>
        </div>

        <div class="warning">
            <h3>Disclaimer &amp; Liability</h3>
            <p>The remediation engine provides suggestions only, intended for qualified
            security professionals. <strong>DO NOT attempt remediation without professional
            assistance.</strong></p>
            <p><strong class="danger">Improper execution can RENDER YOUR EQUIPMENT
            INOPERABLE and cause TOTAL DATA LOSS.</strong></p>
            <p><strong>YOU ASSUME ALL RISKS</strong> if you perform remediation yourself.
            By using any information in this report, you agree to hold FCS llc and its
            agents harmless from any damages, losses, or claims arising from its use.</p>
        </div>

        {scan_context}

        <div class="section">
            <h2>Author &amp; Copyright</h2>
            <div class="meta-grid">
                <div class="m-item"><strong>Main Author</strong> Shing Wong (swong)</div>
                <div class="m-item"><strong>Copyright</strong> &copy; {year} FCS llc</div>
                <div class="m-item"><strong>License</strong> Apache 2.0</div>
                <div class="m-item"><strong>Contact</strong> info@fcsllc.us</div>
                <div class="m-item" style="grid-column:1/-1;"><strong>Repository</strong> github.com/ShingWong/istrix</div>
            </div>
        </div>
    </div>
    <div class="footer">
        <p>&copy; {year} FCS llc. All rights reserved.</p>
        <p><a href="index.html">Report Index</a> &mdash; Generated by iStrix (Apache 2.0)</p>
    </div>
</div>
</body>
</html>"""

    about_path = out / "istrix.html"
    about_path.write_text(html)
    return about_path


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

_ARP_CACHE: dict[str, str] | None = None


def _load_arp_table() -> dict[str, str]:
    """Load IP→MAC mappings from /proc/net/arp."""
    arp: dict[str, str] = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)  # skip header
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    arp[parts[0]] = parts[3]
    except Exception:
        pass
    return arp


def _ip_sort_key(ip_str: str) -> tuple:
    """Sort IP addresses numerically: 10.0.0.2 before 10.0.0.112."""
    try:
        return tuple(int(octet) for octet in ip_str.split("."))
    except (ValueError, AttributeError):
        return (255, 255, 255, 255)  # put unparseable at end


def _get_mac_for_ip(ip: str) -> str:
    """Get MAC address for an IP from the ARP table."""
    return _load_arp_table().get(ip, "")


def generate_host_summary_page(
    results_path: str,
    output_dir: str = ".",
    customer_name: str = "",
    site_name: str = "",
) -> Path:
    """Generate a standalone hosts_summary.html with all hosts sorted by IP.

    Shows threat scores, OS, hardware, and finding counts in a single table.
    """
    from collections import defaultdict

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    sr = load_from_json(results_path)
    hosts: dict[str, list[Finding]] = defaultdict(list)
    for f in sr.findings:
        hosts[f.host].append(f)

    weights = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}

    host_rows = []
    for host_ip in sorted(hosts, key=_ip_sort_key):
        if host_ip in ("0.0.0.0", "127.0.0.1"):  # skip invalid host placeholders
            continue
        f_list = hosts[host_ip]
        os_name = ReportGenerator._detect_os(f_list)
        mac_addr = _get_mac_for_ip(host_ip)
        hardware = ReportGenerator._detect_hardware(f_list, mac_addr)
        by_sev = defaultdict(int)
        for f in f_list:
            by_sev[f.severity] += 1
        total = len(f_list)
        score = sum(weights.get(s, 0) * c for s, c in by_sev.items())
        if score < 1:
            label, color = "None", "#38a169"
        elif score < 20:
            label, color = "Low", "#38a169"
        elif score < 50:
            label, color = "Medium", "#d69e2e"
        elif score < 100:
            label, color = "High", "#dd6b20"
        else:
            label, color = "Critical", "#e53e3e"

        # Collect open ports summary
        ports = sorted({f.port for f in f_list if f.port and f.type == "open_port"})
        ports_str = ", ".join(str(p) for p in ports[:20])
        if len(ports) > 20:
            ports_str += f" (+{len(ports) - 20} more)"

        host_rows.append({
            "ip": host_ip,
            "os": os_name,
            "hardware": hardware,
            "total": total,
            "critical": by_sev.get("critical", 0),
            "high": by_sev.get("high", 0),
            "medium": by_sev.get("medium", 0),
            "low": by_sev.get("low", 0),
            "info": by_sev.get("info", 0),
            "score": score,
            "label": label,
            "color": color,
            "ports": ports_str,
        })

    rows_html = ""
    for r in host_rows:
        rows_html += f"""
        <tr class="sev-{r['label'].lower()}">
            <td><a href="{r['ip']}/index.html"><strong>{r['ip']}</strong></a></td>
            <td>{r['os']}</td>
            <td>{r['hardware']}</td>
            <td class="num">{r['critical']}</td>
            <td class="num">{r['high']}</td>
            <td class="num">{r['medium']}</td>
            <td class="num">{r['low']}</td>
            <td class="num">{r['info']}</td>
            <td class="num"><strong>{r['total']}</strong></td>
            <td><span class="score" style="color:{r['color']}; font-weight:bold;">{r['score']} {r['label']}</span></td>
            <td class="ports">{r['ports']}</td>
        </tr>"""

    totals = {
        "critical": sum(r["critical"] for r in host_rows),
        "high": sum(r["high"] for r in host_rows),
        "medium": sum(r["medium"] for r in host_rows),
        "low": sum(r["low"] for r in host_rows),
        "info": sum(r["info"] for r in host_rows),
        "total": sum(r["total"] for r in host_rows),
        "hosts": len(host_rows),
    }
    max_score = max((r["score"] for r in host_rows), default=0)
    max_score_ip = next((r["ip"] for r in host_rows if r["score"] == max_score), "")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Host Summary — {customer_name or site_name or 'iStrix Scan'}</title>
<style>
:root {{
    --primary: #1a365d; --accent: #3182ce; --bg: #f7fafc; --text: #2d3748;
    --border: #e2e8f0; --info: #718096;
    --critical: #e53e3e; --high: #dd6b20; --medium: #d69e2e; --low: #38a169;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
       color: var(--text); background: var(--bg); line-height: 1.6; font-size: 13px; }}
.container {{ max-width: 1600px; margin: 0 auto; padding: 1rem; }}
.header {{ background: var(--primary); color: white; padding: 1rem 1.5rem; border-radius: 8px 8px 0 0; }}
.header h1 {{ font-size: 1.2rem; }}
.header p {{ opacity: 0.8; font-size: 0.85rem; }}
.content {{ background: white; border: 1px solid var(--border); border-top: none; padding: 1rem; border-radius: 0 0 8px 8px; overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
th {{ background: var(--primary); color: white; padding: 6px 8px; text-align: left; position: sticky; top: 0; z-index: 1; white-space: nowrap; cursor: pointer; }}
th:hover {{ background: var(--accent); }}
td {{ padding: 4px 8px; border-bottom: 1px solid var(--border); white-space: nowrap; }}
tr:hover {{ background: #edf2f7; }}
tr.sev-critical {{ background: #fff5f5; }}
tr.sev-high {{ background: #fffaf0; }}
.num {{ text-align: right; }}
.ports {{ font-size: 10px; color: var(--info); max-width: 400px; overflow: hidden; text-overflow: ellipsis; }}
.score {{ white-space: nowrap; }}
.summary-bar {{ display: flex; gap: 1.5rem; flex-wrap: wrap; margin-bottom: 1rem; padding: 0.75rem; background: #f0f4f8; border-radius: 6px; font-size: 12px; }}
.summary-bar .stat {{ text-align: center; }}
.summary-bar .val {{ font-size: 1.2rem; font-weight: bold; }}
a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
input[type=text] {{ width: 100%; padding: 8px; border: 1px solid var(--border); border-radius: 4px; font-size: 13px; margin-bottom: 0.75rem; }}
@media print {{ body {{ font-size: 10px; }} table {{ font-size: 9px; }} }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Host Summary — {customer_name or site_name or 'iStrix Scan'}</h1>
        <p>{totals['hosts']} hosts scanned | {totals['total']:,} total findings</p>
    </div>
    <div class="content">
        <div class="summary-bar">
            <div class="stat"><div class="val" style="color:var(--critical)">{totals['critical']}</div>Critical</div>
            <div class="stat"><div class="val" style="color:var(--high)">{totals['high']}</div>High</div>
            <div class="stat"><div class="val" style="color:var(--medium)">{totals['medium']}</div>Medium</div>
            <div class="stat"><div class="val" style="color:var(--low)">{totals['low']}</div>Low</div>
            <div class="stat"><div class="val" style="color:var(--info)">{totals['info']}</div>Info</div>
            <div class="stat"><div class="val">{totals['total']:,}</div>Total</div>
            <div class="stat"><div class="val" style="color:{next((r['color'] for r in host_rows if r['ip']==max_score_ip),'var(--info)')}">{max_score}</div>Max Score ({max_score_ip})</div>
        </div>
        <input type="text" id="filter" placeholder="Filter by IP, OS, or hardware..." onkeyup="filterTable()">
        <table id="hostTable">
            <thead><tr>
                <th onclick="sortTable(0)">IP</th>
                <th onclick="sortTable(1)">OS</th>
                <th onclick="sortTable(2)">Hardware</th>
                <th onclick="sortTable(3)">Crit</th>
                <th onclick="sortTable(4)">High</th>
                <th onclick="sortTable(5)">Med</th>
                <th onclick="sortTable(6)">Low</th>
                <th onclick="sortTable(7)">Info</th>
                <th onclick="sortTable(8)">Total</th>
                <th onclick="sortTable(9)">Score</th>
                <th>Open Ports</th>
            </tr></thead>
            <tbody>{rows_html}</tbody>
        </table>
    </div>
</div>
<script>
function filterTable() {{
    var input = document.getElementById('filter');
    var filter = input.value.toUpperCase();
    var table = document.getElementById('hostTable');
    var tr = table.getElementsByTagName('tr');
    for (var i = 1; i < tr.length; i++) {{
        var td = tr[i].getElementsByTagName('td');
        var show = false;
        for (var j = 0; j < Math.min(td.length, 3); j++) {{
            if (td[j] && td[j].textContent.toUpperCase().indexOf(filter) > -1) {{ show = true; break; }}
        }}
        tr[i].style.display = show ? '' : 'none';
    }}
}}
function sortTable(col) {{
    var table = document.getElementById('hostTable');
    var tbody = table.getElementsByTagName('tbody')[0];
    var rows = Array.from(tbody.getElementsByTagName('tr'));
    var asc = table.getAttribute('data-sort-col') != col || table.getAttribute('data-sort-dir') == 'desc';
    table.setAttribute('data-sort-col', col);
    table.setAttribute('data-sort-dir', asc ? 'asc' : 'desc');
    rows.sort(function(a, b) {{
        var ca = a.getElementsByTagName('td')[col].textContent.trim();
        var cb = b.getElementsByTagName('td')[col].textContent.trim();
        var na = parseFloat(ca), nb = parseFloat(cb);
        if (!isNaN(na) && !isNaN(nb)) return asc ? na - nb : nb - na;
        return asc ? ca.localeCompare(cb) : cb.localeCompare(ca);
    }});
    rows.forEach(function(r) {{ tbody.appendChild(r); }});
}}
</script>
</body>
</html>"""

    path = out / "hosts_summary.html"
    path.write_text(html)
    return path


# ------------------------------------------------------------------
# Forest map generator
# ------------------------------------------------------------------

def generate_forest_map(
    scan_results: list[tuple[str, str]],  # (label, results_path) for scanned subnets
    dns_subnets: dict[str, dict],         # subnet → {dc, sites} from DNS probe
    output_dir: str = ".",
    customer_name: str = "",
) -> Path | None:
    """Generate an interactive forest map showing AD topology + security health.

    Args:
        scan_results: List of (label, results_json_path) for scanned subnets.
        dns_subnets: Dict of discovered subnet info from DNS probe:
            {'10.0.0.0/24': {'dc': 'dc01-example', 'hosts': 129, 'sites': ['SiteA', 'SiteB', ...]}}
        output_dir: Output directory.
        customer_name: Customer name for the page header.

    Returns:
        Path to generated forest-map.html, or None if no data.
    """
    from collections import defaultdict

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    weights = {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}
    nodes: list[dict] = []

    # Process scanned subnets
    for label, results_path in scan_results:
        rp = Path(results_path)
        if not rp.exists():
            continue
        sr = load_from_json(str(rp))
        all_hosts: set[str] = set()
        by_sev = defaultdict(int)
        for f in sr.findings:
            all_hosts.add(f.host)
            by_sev[f.severity] += 1

        host_count = len(all_hosts)
        total = len(sr.findings)
        score = sum(weights.get(s, 0) * c for s, c in by_sev.items())

        if score < 1:
            label_txt, color = "Clean", "#38a169"
        elif score < 200:
            label_txt, color = "Low", "#38a169"
        elif score < 600:
            label_txt, color = "Medium", "#d69e2e"
        elif score < 2000:
            label_txt, color = "High", "#dd6b20"
        else:
            label_txt, color = "Critical", "#e53e3e"

        nodes.append({
            "name": label,
            "type": "scanned",
            "hosts": host_count,
            "total": total,
            "critical": by_sev.get("critical", 0),
            "high": by_sev.get("high", 0),
            "medium": by_sev.get("medium", 0),
            "score": score,
            "label": label_txt,
            "color": color,
            "link": f"{label}/index.html",
        })

    # Process unscanned subnets from DNS
    for subnet, info in dns_subnets.items():
        if any(n["name"] == subnet for n in nodes):
            continue
        nodes.append({
            "name": subnet,
            "type": "unscanned",
            "hosts": info.get("hosts", 0),
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "score": 0,
            "label": "Unscanned",
            "color": "#718096",
            "dc": info.get("dc", ""),
            "sites": ", ".join(info.get("sites", [])),
        })

    if not nodes:
        return None

    # Sort: scanned first (by critical desc), then unscanned
    scanned = sorted([n for n in nodes if n["type"] == "scanned"],
                     key=lambda n: (-n["critical"], -n["high"]))
    unscanned = sorted([n for n in nodes if n["type"] == "unscanned"],
                       key=lambda n: n["name"])
    ordered = scanned + unscanned

    # ── Build HTML ──────────────────────────────────────────────────

    # Subnet node cards
    card_html = ""
    for n in ordered:
        if n["type"] == "scanned":
            metric_html = f"""
            <div class="card-metrics">
                <span class="m m-crit">{n["critical"]}</span>
                <span class="m m-high">{n["high"]}</span>
                <span class="m m-med">{n["medium"]}</span>
                <span class="m" style="color:#718096">{n["total"]}</span>
            </div>
            <div class="card-score" style="color:{n['color']}">{n["score"]} {n["label"]}</div>
            """
        else:
            metric_html = f"""
            <div class="card-meta">
                <span>DC: {n.get('dc', '?')}</span>
                <span>{n.get('sites', '?')}</span>
            </div>
            <div class="card-score unscanned">{n["label"]}</div>
            """

        link = n.get("link", "#")
        card_html += f"""
        <a href="{link}" class="card {'scanned' if n['type'] == 'scanned' else ''}"
           style="border-left-color:{n['color']}">
            <div class="card-name">{n['name']}</div>
            <div class="card-hosts">{n['hosts']} hosts</div>
            {metric_html}
        </a>"""

    # Summary bar
    total_hosts = sum(n["hosts"] for n in nodes if isinstance(n["hosts"], int))
    total_crit = sum(n["critical"] for n in nodes if isinstance(n["critical"], int))
    total_high = sum(n["high"] for n in nodes if isinstance(n["high"], int))
    total_findings = sum(n["total"] for n in nodes if isinstance(n["total"], int))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AD Forest Map — {customer_name or 'iStrix'}</title>
<style>
:root {{
    --primary: #1a365d; --accent: #3182ce; --bg: #0f1419; --text: #e2e8f0;
    --border: #2d3748; --card-bg: #1a2332; --card-hover: #243044;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: system-ui, -apple-system, sans-serif; color: var(--text);
        background: var(--bg); line-height: 1.6; min-height: 100vh; }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 2rem 1.5rem; }}
.header {{ text-align: center; margin-bottom: 2.5rem; }}
.header h1 {{ font-size: 1.6rem; color: white; }}
.header p {{ color: #718096; margin-top: 0.5rem; font-size: 0.9rem; }}
.forest-root {{ display: flex; flex-direction: column; align-items: center; margin-bottom: 2rem; }}
.root-node {{ background: linear-gradient(135deg, #1a365d, #2b6cb0); color: white;
    padding: 1.2rem 2.5rem; border-radius: 16px; text-align: center; font-size: 1.2rem;
    font-weight: 700; box-shadow: 0 4px 24px rgba(43,108,176,0.3); }}
.connector {{ width: 3px; height: 40px; background: linear-gradient(to bottom, #2b6cb0, #4a5568); }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
        gap: 1rem; }}
.card {{ display: block; text-decoration: none; color: var(--text);
         background: var(--card-bg); border: 1px solid var(--border);
         border-left: 5px solid #718096; border-radius: 10px;
         padding: 1.25rem; transition: all 0.15s; }}
.card.scanned:hover {{ background: var(--card-hover); border-color: var(--accent);
                         transform: translateY(-2px); box-shadow: 0 6px 20px rgba(0,0,0,0.3); }}
.card-name {{ font-size: 1.1rem; font-weight: 600; color: white; margin-bottom: 0.25rem; }}
.card-hosts {{ color: #718096; font-size: 0.85rem; margin-bottom: 0.75rem; }}
.card-metrics {{ display: flex; gap: 0.75rem; font-size: 0.9rem; margin-bottom: 0.5rem; }}
.m {{ background: #2d3748; padding: 2px 8px; border-radius: 4px; font-weight: 600; }}
.m-crit {{ color: #fc8181; }}
.m-high {{ color: #f6ad55; }}
.m-med {{ color: #f6e05e; }}
.card-meta {{ font-size: 0.85rem; color: #718096; margin-bottom: 0.5rem; }}
.card-meta span {{ display: block; }}
.card-score {{ font-weight: 700; font-size: 0.95rem; text-transform: uppercase; letter-spacing: 0.5px; }}
.card-score.unscanned {{ color: #718096; }}
.summary-bar {{ display: flex; gap: 1.5rem; flex-wrap: wrap; margin-bottom: 2rem;
               justify-content: center; padding: 1rem; background: var(--card-bg);
               border-radius: 10px; border: 1px solid var(--border); }}
.stat {{ text-align: center; }}
.stat .val {{ font-size: 1.5rem; font-weight: bold; }}
.stat .lbl {{ font-size: 0.8rem; color: #718096; }}
.legend {{ display: flex; gap: 1.5rem; justify-content: center; margin-bottom: 1.5rem; }}
.legend span {{ display: flex; align-items: center; gap: 0.5rem; font-size: 0.85rem; }}
.legend .dot {{ width: 10px; height: 10px; border-radius: 50%; }}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>Active Directory Forest Map</h1>
        <p>{customer_name} — {len(scanned)} subnet{'s' if len(scanned) != 1 else ''} scanned,
           {len(unscanned)} discovered via DNS — {total_hosts} total hosts</p>
    </div>

    <div class="summary-bar">
        <div class="stat"><div class="val" style="color:#fc8181">{total_crit}</div><div class="lbl">Critical</div></div>
        <div class="stat"><div class="val" style="color:#f6ad55">{total_high}</div><div class="lbl">High</div></div>
        <div class="stat"><div class="val">{total_findings:,}</div><div class="lbl">Findings</div></div>
        <div class="stat"><div class="val" style="color:#2b6cb0">{len(scanned)}</div><div class="lbl">Scanned</div></div>
        <div class="stat"><div class="val" style="color:#718096">{len(unscanned)}</div><div class="lbl">To Scan</div></div>
    </div>

    <div class="legend">
        <span><span class="dot" style="background:#fc8181"></span>Critical</span>
        <span><span class="dot" style="background:#f6ad55"></span>High Risk</span>
        <span><span class="dot" style="background:#38a169"></span>Low Risk</span>
        <span><span class="dot" style="background:#718096"></span>Unscanned</span>
    </div>

    <div class="forest-root">
        <div class="root-node">example.corp.local</div>
        <div class="connector"></div>
    </div>

    <div class="grid">
        {card_html}
    </div>
</div>
</body>
</html>"""

    path = out / "forest-map.html"
    path.write_text(html)
    return path
