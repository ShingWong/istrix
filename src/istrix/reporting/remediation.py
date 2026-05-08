"""OS-aware remediation command generator.

Maps CVE descriptions to product-specific upgrade/patch commands
based on the detected host OS, ensuring Windows servers get Windows
commands, Cisco devices get IOS commands, etc.

Now incorporates specific fix version detection from CVE descriptions
via knowledge.patches module.
"""

import re

from istrix.knowledge.patches import extract_fixed_version, _generate_upgrade_commands

# Product → OS → command template
# Patterns are matched against CVE description or detail text
# Family keys (Linux, RHEL) match via prefix on host_os in _resolve_os_commands
_RHEL_COMMANDS = {
    "openssh": [
        "dnf update openssh-server -y",
        "sshd -t && systemctl restart sshd",
    ],
    "nginx": [
        "dnf update nginx -y",
        "nginx -t && systemctl restart nginx",
    ],
    "apache|httpd": [
        "dnf update httpd -y",
        "httpd -t && systemctl restart httpd",
    ],
    "bind|dns": [
        "dnf update bind -y",
        "rndc reload",
    ],
    "mysql|mariadb": [
        "dnf update mysql-server -y",
        "systemctl restart mysqld",
    ],
    "postgresql": [
        "dnf update postgresql-server -y",
        "systemctl restart postgresql",
    ],
    "kernel|linux kernel": [
        "dnf update kernel -y && reboot",
    ],
}

_RHEL_PRODUCT_MAP: dict[str, str] = {
    "openssh": "openssh",
    "nginx": "nginx",
    "apache": "apache|httpd",
    "httpd": "apache|httpd",
    "bind": "bind|dns",
    "dns": "bind|dns",
    "mysql": "mysql|mariadb",
    "mariadb": "mysql|mariadb",
    "postgresql": "postgresql",
    "kernel": "kernel|linux kernel",
}

_PRODUCT_REMEDIATION = {
    "openssh": {
        "Linux": [
            "apt update && apt install --only-upgrade openssh-server openssh-client -y",
            "sshd -t && systemctl restart sshd",
        ],
        "Windows": [
            "winget upgrade OpenSSH.OpenSSH-Server",
            "OR: Install via Windows Settings → Optional Features → OpenSSH Server → Update",
            "Restart-Service sshd",
        ],
        "Cisco IOS": [
            "Verify IOS image supports fixed SSH version: show version | include SSH",
            "Upgrade IOS via: software install file flash:<image.bin> activate commit",
        ],
        "default": [
            "Upgrade OpenSSH to the latest version >= 9.8",
            "Restart the SSH service after upgrading",
        ],
    },
    "nginx": {
        "Linux": [
            "apt update && apt install --only-upgrade nginx -y",
            "nginx -t && systemctl restart nginx",
        ],
        "Windows": [
            "winget upgrade nginx",
            "OR download latest from https://nginx.org/en/download.html",
            "nginx -s reload",
        ],
        "default": [
            "Upgrade nginx to the latest stable version",
            "nginx -t && nginx -s reload",
        ],
    },
    "apache": {
        "Linux": [
            "apt update && apt install --only-upgrade apache2 -y",
            "apache2ctl configtest && systemctl restart apache2",
        ],
        "Windows": [
            "Download latest Apache from https://httpd.apache.org/download.cgi",
            "Run the MSI installer to upgrade",
            "httpd -k restart",
        ],
        "default": [
            "Upgrade Apache HTTP Server to the latest version",
            "Restart the web server after upgrading",
        ],
    },
    "iis|microsoft-ds|smb|netbios|ms-wbt-server|rdp|windows": {
        "Windows": [
            "Run Windows Update: Settings → Windows Update → Check for updates",
            "Install all cumulative updates and security patches",
            "Reboot if required: Restart-Computer -Force",
        ],
        "default": [
            "This vulnerability affects Windows services",
            "Apply the latest Windows security updates",
        ],
    },
    "bind|dns": {
        "Linux": [
            "apt update && apt install --only-upgrade bind9 -y",
            "rndc reload",
        ],
        "Windows": [
            "Apply DNS Server updates via Windows Update",
            "Verify: Get-WindowsFeature DNS",
        ],
        "default": [
            "Upgrade DNS server software to the latest version",
        ],
    },
    "mysql|mariadb": {
        "Linux": [
            "apt update && apt install --only-upgrade mysql-server -y",
            "systemctl restart mysql",
        ],
        "Windows": [
            "Download latest MySQL from https://dev.mysql.com/downloads/",
            "Run the MySQL Installer to upgrade",
        ],
        "default": [
            "Upgrade MySQL/MariaDB to the latest version",
        ],
    },
    "postgresql": {
        "Linux": [
            "apt update && apt install --only-upgrade postgresql -y",
            "pg_ctlcluster $(pg_lsclusters -h | head -1 | awk '{print $1, $2}') restart",
        ],
        "default": [
            "Upgrade PostgreSQL to the latest version",
        ],
    },
    "kernel|linux kernel": {
        "Linux": [
            "apt update && apt upgrade -y && reboot",
        ],
        "default": [
            "Apply the latest kernel security patches from your OS vendor",
        ],
    },
    "cisco ios|cisco nx-os|cisco ios-xe": {
        "Cisco IOS": [
            "Verify current version: show version",
            "Check Cisco PSIRT: https://sec.cloudapps.cisco.com/security/center/",
            "Upgrade: software install file flash:<image.bin> activate commit",
        ],
        "default": [
            "Refer to Cisco Security Advisories for patch information",
        ],
    },
}


def _is_rhel_family(host_os: str) -> bool:
    """Check if host_os indicates a RHEL-family distro (uses dnf, not apt)."""
    rhel_indicators = (
        "oracle linux", "oraclelinux",
        "rocky linux", "rockylinux",
        "almalinux", "alma linux",
        "red hat", "rhel", "redhat",
        "centos", "fedora",
        "linux (rhel-family)",
    )
    return any(ind in host_os.lower() for ind in rhel_indicators)


def generate_remediation_commands(
    cve_id: str,
    cve_description: str,
    host_os: str,
    finding_detail: str = "",
) -> list[str]:
    """Generate OS-aware remediation commands for a CVE.

    Matches the CVE description and finding detail against known products,
    then returns OS-specific or generic remediation commands.

    Args:
        cve_id: The CVE identifier (e.g. CVE-2024-6387).
        cve_description: Description from NVD/nmap.
        host_os: Detected OS (e.g. "Windows Server 2019", "Linux", "Cisco IOS").
        finding_detail: Original finding detail from nmap.

    Returns:
        List of remediation command strings.
    """
    search_text = (cve_description + " " + finding_detail).lower()

    # 0. Try to extract a specific fix version from the CVE description
    fixed_version = extract_fixed_version(cve_description)
    if fixed_version:
        product = _extract_product(search_text)
        current_version = _extract_current_version(finding_detail, product) if product else ""
        if product:
            patch_cmds = _generate_upgrade_commands(
                product, current_version, fixed_version, host_os, cve_id
            )
            if patch_cmds:
                return patch_cmds

    # 1. RHEL-family: use dnf-based commands mapped from known products
    if _is_rhel_family(host_os):
        for product_keyword in sorted(_RHEL_PRODUCT_MAP, key=len, reverse=True):
            if product_keyword in search_text:
                rhel_key = _RHEL_PRODUCT_MAP[product_keyword]
                if rhel_key in _RHEL_COMMANDS:
                    return list(_RHEL_COMMANDS[rhel_key])
                break

    # 2. Match known product patterns
    for product_pattern, os_commands in _PRODUCT_REMEDIATION.items():
        if _match_product(product_pattern, search_text):
            return _resolve_os_commands(os_commands, host_os)

    # 3. Vector search fallback — semantic CVE matching
    return _vector_remediation_fallback(cve_id, cve_description, host_os, search_text)


def _vector_remediation_fallback(
    cve_id: str,
    cve_description: str,
    host_os: str,
    search_text: str = "",
) -> list[str]:
    """Try vector-based semantic search for unknown CVEs.

    When regex/product matching fails, query the vector index for
    semantically similar known CVEs whose remediation commands can
    be adapted.
    """
    try:
        from istrix.knowledge.vector import get_vector_search
    except ImportError:
        return _generic_os_advice(host_os)

    vs = get_vector_search()
    if not vs._built:
        vs.build_index()

    best, score = vs.find_closest(cve_description, min_score=0.55)
    if best is None or score < 0.55:
        return _generic_os_advice(host_os)

    # Found a similar CVE — adapt its commands to the current OS
    cmds: list[str] = []
    cmds.append(f"[Vector match: {best.cve_id} (similarity: {score:.0%})]")
    cmds.append(f"Similar CVE: {best.title or best.cve_id}")
    cmds.append(f"CVSS: {best.cvss}")

    # Use the matched CVE's commands, filtered through OS-aware resolution
    if best.commands:
        # Map the known commands to the current OS
        os_cmds = _resolve_os_commands({"Linux": best.commands}, host_os)
        cmds.extend(os_cmds if os_cmds != best.commands else best.commands)
    else:
        cmds.append("No specific commands available — review vendor advisory.")

    cmds.append(f"NVD: https://nvd.nist.gov/vuln/detail/{cve_id}")
    return cmds


def _extract_product(text: str) -> str:
    """Extract product name from CVE description/finding text."""
    products = [
        ("openssh", "OpenSSH"), ("nginx", "nginx"), ("apache", "Apache"),
        ("lighttpd", "lighttpd"), ("filezilla", "FileZilla"),
        ("mysql", "MySQL"), ("mariadb", "MariaDB"),
        ("postgresql", "PostgreSQL"), ("bind", "BIND"), ("php", "PHP"),
        ("microsoft", "Microsoft"), ("cisco", "Cisco"), ("juniper", "Juniper"),
        ("vmware", "VMware"), ("linux kernel", "Linux Kernel"),
    ]
    for keyword, name in products:
        if keyword in text:
            return name
    return ""


def _extract_current_version(text: str, product: str) -> str:
    """Extract the currently installed version from a finding detail."""
    if not product:
        return ""
    # Try to find "product version" pattern
    m = re.search(rf"{re.escape(product)}\s+(\S+)", text, re.IGNORECASE)
    if not m:
        m = re.search(r"version[=:\s]+(\S+)", text, re.IGNORECASE)
    if m:
        v = m.group(1).rstrip("),;.")
        if re.match(r"\d+(?:\.\d+)+", v):  # Must look like a version
            return v
    return ""


def _match_product(pattern: str, text: str) -> bool:
    """Match a product pattern (regex) against search text."""
    return bool(re.search(pattern, text, re.IGNORECASE))


def _resolve_os_commands(os_commands: dict, host_os: str) -> list[str]:
    """Find the best OS-specific command set for the given host OS.

    When host_os is a generic heuristic like 'Linux (SSH)' (distro unknown),
    this avoids blindly matching the 'Linux' prefix which assumes apt-based distros.
    Instead it returns cross-distro defaults.
    """
    # Exact match
    if host_os in os_commands:
        return list(os_commands[host_os])

    # Generic Linux heuristic (distro unknown) → skip apt-specific match, use default
    if host_os.startswith("Linux (") and host_os.endswith(")"):
        return list(os_commands.get("default", ["Apply vendor security patches"]))
    # Embedded/IoT Linux without known distro (e.g. "Linux 3.10.0_hi3536 (HiSilicon) (Embedded/IoT)")
    if host_os.startswith("Linux ") and "embedded" in host_os.lower():
        return list(os_commands.get("default", ["Apply vendor security patches"]))
    # Printer devices → firmware-based, never apt
    if "printer" in host_os.lower() or "jetdirect" in host_os.lower():
        return _printer_os_advice(host_os)
    # Camera/NVR devices → firmware-based
    if "camera:" in host_os.lower() or "ipcamera" in host_os.lower() or \
       "nvr" in host_os.lower() or "dvr" in host_os.lower() or \
       "hi3536" in host_os.lower() or "hi3516" in host_os.lower():
        return _camera_os_advice(host_os)
    # Firewall devices → firmware-based, never apt/dnf or server commands
    if any(kw in host_os.lower() for kw in (
        "watchguard", "fortinet", "fortigate", "palo alto",
        "sonicwall", "firewall",
    )):
        return _firewall_os_advice(host_os)

    # Prefix match (e.g. "Windows Server 2019" matches "Windows")
    for key in sorted(os_commands, key=len, reverse=True):
        if key == "default":
            continue
        if host_os.startswith(key) or key.lower() in host_os.lower():
            return list(os_commands[key])

    # Default
    return list(os_commands.get("default", ["Apply vendor security patches"]))


def _generic_os_advice(host_os: str) -> list[str]:
    """Fallback generic OS advice."""
    os_lower = host_os.lower()
    if "windows" in os_lower:
        return [
            "Run Windows Update and apply all security patches",
            "Review Microsoft Security Response Center (MSRC) for this CVE",
            "Install latest cumulative update and reboot if required",
        ]
    if "cisco" in os_lower or "ios" in os_lower:
        return [
            "Check Cisco Security Advisories at https://sec.cloudapps.cisco.com/security/center/",
            "Upgrade IOS/NX-OS to a fixed version",
            "Verify: show version | include System image",
        ]
    if "rhel" in os_lower or "centos" in os_lower or "fedora" in os_lower or \
       "oracle" in os_lower or "rocky" in os_lower or "alma" in os_lower or \
       "red hat" in os_lower or "rhel-family" in os_lower:
        return [
            "dnf update -y",
            "Check Red Hat / Oracle CVE database for advisory",
        ]
    if "embedded" in os_lower or "iot" in os_lower:
        return [
            "This is an embedded/IoT device. Updates may require vendor firmware.",
            "Check manufacturer's support site for firmware updates.",
        ]
    if "printer" in os_lower or "jetdirect" in os_lower:
        return _printer_os_advice(host_os)
    if any(kw in os_lower for kw in ("watchguard", "fortinet", "fortigate",
        "palo alto", "sonicwall", "firewall")):
        return _firewall_os_advice(host_os)
    # Firewall devices → firmware-based
    if any(kw in os_lower for kw in ("watchguard", "fortinet", "fortigate",
        "palo alto", "sonicwall", "firewall")):
        return _firewall_os_advice(host_os)
    if "camera:" in os_lower or "ipcamera" in os_lower or "nvr" in os_lower or "dvr" in os_lower or \
       "hi3536" in os_lower or "hi3516" in os_lower:
        return _camera_os_advice(host_os)
    if "linux" in os_lower or "ubuntu" in os_lower or "debian" in os_lower:
        return [
            "apt update && apt upgrade -y",
            "Check Ubuntu USN or Debian DSA for this CVE",
        ]
    return ["Apply the latest vendor security patches for this CVE"]


def _printer_os_advice(host_os: str) -> list[str]:
    """Vendor-specific printer remediation."""
    os_lower = host_os.lower()
    if "hp" in os_lower:
        return [
            "Download firmware from HP Support: https://support.hp.com/us-en/drivers/printers",
            "Apply via printer web interface (EWS) or HP Web Jetadmin",
            "Disable unused services (SNMP, FTP, Telnet) via EWS → Security",
        ]
    if "canon" in os_lower:
        return [
            "Download firmware from Canon Support: https://www.usa.canon.com/support",
            "Apply via printer Remote UI or USB firmware update",
        ]
    if "brother" in os_lower:
        return [
            "Download firmware from Brother Support: https://support.brother.com",
            "Apply via printer web interface or BRAdmin tool",
        ]
    if "epson" in os_lower:
        return [
            "Download firmware from Epson Support: https://epson.com/support",
            "Apply via printer web interface or Epson Firmware Update Tool",
        ]
    if "xerox" in os_lower:
        return [
            "Download firmware from Xerox Support: https://www.support.xerox.com",
            "Apply via CentreWare Internet Services (CWIS)",
        ]
    # Generic printer
    return [
        "This is a network printer. Apply firmware updates via manufacturer.",
        "Check manufacturer support site for firmware downloads.",
        "Disable unused services (SNMP, FTP, Telnet) via printer web interface.",
    ]


def _firewall_os_advice(host_os: str) -> list[str]:
    """Vendor-specific firewall remediation."""
    os_lower = host_os.lower()
    if "watchguard" in os_lower:
        return [
            "Update WatchGuard Fireware OS via WatchGuard System Manager",
            "Download: https://www.watchguard.com/wgrd-support/release-notes",
            "Apply via Web UI: System → Upgrade OS",
            "Also update security services: Gateway AV, IPS, Application Control",
        ]
    if "fortinet" in os_lower or "fortigate" in os_lower:
        return [
            "Update FortiOS via FortiGate web interface or FortiManager",
            "Download: https://support.fortinet.com",
            "Apply via CLI: execute restore image tftp <image> <tftp_server>",
            "Follow Fortinet PSIRT advisories for critical CVEs",
        ]
    if "palo alto" in os_lower:
        return [
            "Update PAN-OS via Panorama or web interface",
            "Download: https://support.paloaltonetworks.com",
            "Apply via Device → Software → Install",
            "Review Palo Alto Security Advisories before upgrading",
        ]
    if "sonicwall" in os_lower:
        return [
            "Update SonicOS via SonicWall web interface",
            "Download: https://www.sonicwall.com/support",
            "Apply via System → Settings → Firmware",
        ]
    return [
        "Apply firewall firmware/OS updates via manufacturer support",
        "Review vendor security advisories for CVEs",
        "Harden: disable unused management interfaces, restrict admin access",
    ]


def _camera_os_advice(host_os: str) -> list[str]:
    """Vendor-specific camera/NVR remediation."""
    os_lower = host_os.lower()
    if "dahua" in os_lower:
        return [
            "Download firmware from Dahua Security: https://www.dahuasecurity.com/support/downloadCenter",
            "Apply via camera web interface: Settings → System → Upgrade",
            "Ensure camera is on a VLAN isolated from business network",
        ]
    if "hikvision" in os_lower:
        return [
            "Download firmware from Hikvision Portal: https://www.hikvision.com/en/support/download/firmware/",
            "Apply via web interface: Configuration → System → Maintenance → Upgrade",
            "Consider using Hikvision Batch Configuration Tool for mass updates",
        ]
    if "uniview" in os_lower:
        return [
            "Download firmware from Uniview: https://www.uniview.com/Download/",
            "Apply via web interface or EZTools utility",
        ]
    if "reolink" in os_lower:
        return [
            "Download firmware from Reolink: https://reolink.com/download-center/",
            "Apply via Reolink Client or web interface: Settings → System → Maintenance",
        ]
    if "xiongmai" in os_lower or "netsurveillance" in os_lower or "hi3536" in os_lower:
        return [
            "Generic Chinese camera/NVR (HiSilicon SoC). Check OEM vendor for firmware.",
            "Common OEMs: Xiongmai, Topsee, Sricam, Ucam",
            "Many use the XMEye P2P protocol — disable cloud access if not needed",
            "Isolate cameras on a dedicated VLAN — these are frequently backdoored",
        ]
    if "nvr" in os_lower or "dvr" in os_lower:
        # NVR/DVR detected via camera_probe
        if "hi3536" in os_lower or "hi3516" in os_lower:
            return [
                "HiSilicon-based NVR/DVR. Check OEM vendor for firmware updates.",
                "Common platforms: Xiongmai, Dahua OEM, Hikvision OEM",
                "Disable P2P/cloud features via web interface if not required",
                "Update via web interface or USB flash drive",
            ]
        return [
            "Network Video Recorder detected. Apply firmware updates via manufacturer.",
            "Check NVR web interface: System → Maintenance → Firmware Upgrade",
            "Ensure NVR recording streams are encrypted",
        ]
    # Generic IP camera
    return [
        "IP Camera / Surveillance device detected.",
        "Apply firmware updates via manufacturer's support site.",
        "Isolate cameras on a dedicated VLAN — commonly targeted entry points.",
        "Disable UPnP, P2P cloud access, and Telnet if not required.",
    ]
