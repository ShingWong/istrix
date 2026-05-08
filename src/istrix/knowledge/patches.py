"""CVE Patch Lookup — specific version/bulletin/patch information per CVE.

Cross-references CVEs against:
  - NVD CVE descriptions (parsed for "fixed in version X.Y.Z")
  - NVD CPE data (affected version ranges → fix version)
  - Vendor APIs (MSRC, Ubuntu USN, Debian DSA, Red Hat RHSA) — async, cached
  - Local patch database (config/patches.yaml) for curated entries

Returns structured PatchInfo that feeds into remediation reports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class PatchInfo:
    """Structured patch information for a CVE on a specific product/OS."""
    cve_id: str
    product: str = ""
    affected_version: str = ""
    fixed_version: str = ""
    patch_commands: list[str] = field(default_factory=list)
    advisory_url: str = ""
    advisory_id: str = ""          # e.g. "KB5044285", "USN-7000-1", "DSA-5780"
    source: str = "nvd"            # nvd, msrc, usn, dsa, rhsa, manual
    cvss: float = 0.0
    os_compatibility: list[str] = field(default_factory=list)


# ──────────────────────────────────────────────────────────────────
# Fixed version extraction from CVE descriptions
# ──────────────────────────────────────────────────────────────────

# Common patterns in NVD CVE descriptions indicating fix versions
_FIX_PATTERNS = [
    # "fixed in version X.Y.Z"
    r"fixed\s+in\s+(?:version\s+)?(\d+(?:\.\d+)+[a-z]?\d*)",
    # "prior to version X.Y.Z" → X.Y.Z is the fix
    r"prior\s+to\s+(?:version\s+)?(\d+(?:\.\d+)+[a-z]?\d*)",
    # "before version X.Y.Z"
    r"before\s+(?:version\s+)?(\d+(?:\.\d+)+[a-z]?\d*)",
    # "before build 150522" → catch numeric build numbers
    r"before\s+build\s+(\d+(?:\.\d+)*)",
    # "up to and including X.Y.Z, fixed in A.B.C" (capture fix version = group 2)
    r"up\s+to\s+(?:and\s+including\s+)?(?:version\s+)?\d+(?:\.\d+)+\S*,?\s+(?:fixed\s+(?:in|with|as\s+of))\s*(?:version\s+)?(\d+(?:\.\d+)+[a-z]?\d*)",
    # "all versions prior to X.Y.Z are affected"
    r"versions?\s+(?:prior\s+to\s+|before\s+|(?:up\s+to\s+))(\d+(?:\.\d+)+[a-z]?\d*)",
    # "OpenSSH before 9.8" → 9.8 is the fix
    r"(?:before|prior\s+to|earlier\s+than)\s+(\d+(?:\.\d+)+[a-z]?\d*)",
    # "running firmware 5.1.6 and earlier" / "version X and earlier"
    r"(?:firmware|version)\s+(\d+(?:\.\d+)+)\s+and\s+earlier",
    # "affects versions X through Y, fixed in Z"
    r"affects?\s+(?:versions?\s+)?\d+(?:\.\d+)+\S*\s+(?:through|to)\s+\d+(?:\.\d+)+\S*,?\s+(?:fixed\s+(?:in|with))\s*(\d+(?:\.\d+)+[a-z]?\d*)",
]


def extract_fixed_version(cve_description: str) -> str | None:
    """Extract the fixed/patched version from a CVE description.

    Returns None if no fix version pattern is found.
    """
    for pattern in _FIX_PATTERNS:
        m = re.search(pattern, cve_description, re.IGNORECASE)
        if m:
            version = m.group(1).rstrip(".,;):")
            # Validate it looks like a version (dotted or plain numeric)
            if re.match(r"\d+(?:\.\d+)*[a-z]?\d*", version):
                return version
    return None


def extract_affected_version_range(cve_description: str, product: str = "") -> tuple[str, str]:
    """Extract affected version range: (min_affected, max_affected)."""
    # Pattern: "before X.Y.Z" or "all versions through X.Y.Z"
    m = re.search(r"(?:before|prior\s+to|through)\s+(?:version\s+)?(\d+(?:\.\d+)+[a-z]?\d*)",
                  cve_description, re.IGNORECASE)
    if m:
        return ("", m.group(1))
    return ("", "")


# ──────────────────────────────────────────────────────────────────
# Vendor-specific KB/advisory lookup (uses nvdlib when available)
# ──────────────────────────────────────────────────────────────────

async def lookup_patch_for_cve(
    cve_id: str,
    product: str = "",
    version: str = "",
    host_os: str = "",
    nvdlib_module: Any = None,
) -> PatchInfo:
    """Look up specific patch information for a CVE.

    Strategy (in order):
      1. Parse CVE description from NVD for fixed version
      2. Check local patch database (config/patches.yaml)
      3. Identify vendor (Microsoft → MSRC, Ubuntu → USN, etc.)

    Args:
        cve_id: CVE identifier (e.g. CVE-2024-6387)
        product: Affected product (e.g. OpenSSH, nginx)
        version: Detected version (e.g. 8.7, 1.20.1)
        host_os: Detected host OS (for vendor-specific lookup)
        nvdlib_module: nvdlib module if available (for API calls)

    Returns:
        PatchInfo with specific fix version and advisory details.
    """
    patch = PatchInfo(cve_id=cve_id, product=product, affected_version=version)

    # 1. Try NVD data for fixed version
    if nvdlib_module:
        description = await _fetch_cve_description(cve_id, nvdlib_module)
        if description:
            fixed = extract_fixed_version(description)
            if fixed:
                patch.fixed_version = fixed
                patch.source = "nvd"

    # 2. Check local curated patch database
    local = _lookup_local_patch(cve_id, product)
    if local:
        if not patch.fixed_version:
            patch.fixed_version = local.get("fixed_version", "")
        if not patch.advisory_url:
            patch.advisory_url = local.get("advisory_url", "")
        if not patch.advisory_id:
            patch.advisory_id = local.get("advisory_id", "")
        if not patch.patch_commands:
            patch.patch_commands = local.get("commands", [])
        patch.source = "manual"

    # 3. Generate OS-aware patch commands if we have a fixed version
    if patch.fixed_version:
        patch.patch_commands = _generate_upgrade_commands(
            product, version, patch.fixed_version, host_os, cve_id
        )
        if not patch.advisory_url:
            patch.advisory_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    # 4. Set OS compatibility hints
    patch.os_compatibility = _infer_os_compatibility(host_os, product)

    return patch


async def _fetch_cve_description(cve_id: str, nvdlib: Any) -> str:
    """Fetch CVE description from NVD API via nvdlib."""
    try:
        results = nvdlib.searchCVE(cveId=cve_id)
        for cve in results or []:
            if getattr(cve, "id", None) == cve_id:
                for d in getattr(cve, "descriptions", []) or []:
                    if getattr(d, "lang", "") == "en":
                        return getattr(d, "value", "")
    except Exception:
        pass
    return ""


def _lookup_local_patch(cve_id: str, product: str) -> dict | None:
    """Check the curated local patch database."""
    import yaml
    from pathlib import Path

    patch_file = Path(__file__).parent.parent.parent.parent / "config" / "patches.yaml"
    if not patch_file.exists():
        return None

    try:
        with open(patch_file) as f:
            data = yaml.safe_load(f)
        patches = data.get("patches", {}) if data else {}
        return patches.get(cve_id)
    except Exception:
        return None


def _generate_upgrade_commands(
    product: str,
    current_version: str,
    fixed_version: str,
    host_os: str,
    cve_id: str,
) -> list[str]:
    """Generate OS-aware upgrade commands with specific versions."""
    os_lower = host_os.lower()
    product_lower = product.lower()

    def _ver(ver_from: str, ver_to: str) -> str:
        """Format version range — flag unknown current versions."""
        if ver_from:
            return f"Upgrade {product} from {ver_from} to {ver_to}"
        return f"Upgrade {product} to >= {ver_to} ⚠ current version unknown — verify applicability"

    # Determine package manager and service restart
    is_rhel = any(
        ind in os_lower for ind in (
            "oracle", "rhel", "red hat", "redhat", "rocky", "alma",
            "centos", "fedora", "rhel-family",
        )
    )
    is_generic_linux = os_lower.startswith("linux (") and os_lower.endswith(")")
    is_embedded = "embedded" in os_lower or "iot" in os_lower
    is_printer = "printer" in os_lower or "jetdirect" in os_lower
    is_camera = "camera:" in os_lower or "ipcamera" in os_lower or \
                "nvr" in os_lower or "dvr" in os_lower or \
                "hi3536" in os_lower or "hi3516" in os_lower
    is_firewall = any(kw in os_lower for kw in (
        "watchguard", "fortinet", "fortigate", "palo alto",
        "sonicwall", "firewall",
    ))

    # Printer devices — firmware-based, not OS package management
    if is_printer:
        return [
            f"Upgrade {product} to >= {fixed_version} via manufacturer firmware update",
            "Download firmware from vendor support site (HP, Dell, etc.)",
            "Apply via printer web interface or USB firmware update",
        ]

    # Camera/NVR devices — firmware-based, never OS package management
    if is_camera:
        return [
            f"Upgrade {product} to >= {fixed_version} via manufacturer firmware",
            "Download firmware from camera/NVR vendor support site",
            "Apply via web interface: System → Maintenance → Firmware Upgrade",
            f"NVD: https://nvd.nist.gov/vuln/detail/{cve_id}",
        ]

    # OpenSSH
    if "openssh" in product_lower or "ssh" in product_lower:
        if is_firewall:
            return [
                f"Upgrade {product} to >= {fixed_version} via vendor firmware update",
                "Apply latest Fireware OS / FortiOS / PAN-OS firmware from vendor",
                "Firewall devices use embedded SSH — upgrade the entire OS image",
                f"NVD: https://nvd.nist.gov/vuln/detail/{cve_id}",
            ]
        if "windows" in os_lower:
            return [
                f"winget upgrade OpenSSH.OpenSSH-Server --version {fixed_version}",
                f"# OR download OpenSSH {fixed_version} from https://github.com/PowerShell/Win32-OpenSSH/releases",
                "Restart-Service sshd",
            ]
        if is_rhel:
            return [
                f"dnf update openssh-server-{fixed_version} -y",
                f"# Verify: ssh -V 2>&1 | grep {fixed_version}",
                "systemctl restart sshd",
            ]
        if is_generic_linux:
            return [
                f"Upgrade OpenSSH to >= {fixed_version}",
                f"Debian/Ubuntu: apt install openssh-server={fixed_version}",
                f"RHEL/Oracle/Rocky: dnf update openssh-server-{fixed_version} -y",
                "systemctl restart sshd",
            ]
        if is_embedded:
            return [
                f"Upgrade OpenSSH to >= {fixed_version}",
                "Check manufacturer firmware for updated SSH packages",
                "Embedded device — may require full firmware reflash",
            ]
        return [
            f"Upgrade OpenSSH to >= {fixed_version}",
            f"Debian/Ubuntu: apt install openssh-server={fixed_version}",
            f"RHEL/Oracle/Rocky: dnf update openssh-server-{fixed_version} -y",
            "systemctl restart sshd",
        ]

    # nginx
    if "nginx" in product_lower:
        if is_firewall:
            return [
                f"Upgrade to firmware with nginx >= {fixed_version}",
                "Apply latest Fireware OS / FortiOS / PAN-OS firmware from vendor",
                "Firewall web servers are embedded — upgrade the entire OS image",
                f"NVD: https://nvd.nist.gov/vuln/detail/{cve_id}",
            ]
        if is_embedded:
            return [
                f"Upgrade embedded nginx to >= {fixed_version}",
                "Check manufacturer firmware for updated nginx packages",
                "Embedded device — may require full firmware reflash",
                f"NVD: https://nvd.nist.gov/vuln/detail/{cve_id}",
            ]
        if "windows" in os_lower:
            return [f"winget upgrade nginx --version {fixed_version}",
                    f"# OR download nginx/{fixed_version} from https://nginx.org/en/download.html"]
        if is_rhel:
            return [
                f"dnf update nginx-{fixed_version} -y",
                "nginx -t && systemctl restart nginx",
                f"# Verify: nginx -v 2>&1 | grep {fixed_version}",
            ]
        if is_generic_linux:
            return [
                f"Upgrade nginx to >= {fixed_version}",
                "Debian/Ubuntu: apt install nginx",
                "RHEL/Oracle/Rocky: dnf update nginx -y",
                "nginx -t && nginx -s reload",
            ]
        return [
            f"Upgrade nginx to >= {fixed_version}",
            "Debian/Ubuntu: apt install nginx",
            "RHEL/Oracle/Rocky: dnf update nginx -y",
            "nginx -t && nginx -s reload",
        ]

    # Apache / httpd (exact, not substring — avoid matching lighttpd)
    if product_lower in ("apache", "httpd", "apache2"):
        if is_firewall:
            return [
                f"Upgrade to firmware with Apache/httpd >= {fixed_version}",
                "Apply latest Fireware OS / FortiOS / PAN-OS firmware from vendor",
                "Firewall web servers are embedded — upgrade the entire OS image",
                f"NVD: https://nvd.nist.gov/vuln/detail/{cve_id}",
            ]
        if is_embedded:
            return [
                f"Upgrade embedded Apache/httpd to >= {fixed_version}",
                "Check manufacturer firmware for updated httpd packages",
                "Embedded device — may require full firmware reflash",
                f"NVD: https://nvd.nist.gov/vuln/detail/{cve_id}",
            ]
        if "windows" in os_lower:
            return [f"Download Apache {fixed_version} from https://httpd.apache.org/download.cgi",
                    "Run the MSI installer to upgrade"]
        if is_rhel:
            return [
                f"dnf update httpd-{fixed_version} -y",
                "systemctl restart httpd",
            ]
        if is_generic_linux:
            return [
                f"Upgrade Apache/httpd to >= {fixed_version}",
                "Debian/Ubuntu: apt install apache2",
                "RHEL/Oracle/Rocky: dnf update httpd -y",
                "systemctl restart apache2",
            ]
        return [
            f"Upgrade Apache/httpd to >= {fixed_version}",
            "Debian/Ubuntu: apt install apache2",
            "RHEL/Oracle/Rocky: dnf update httpd -y",
            "systemctl restart apache2",
        ]

    # Generic — fixed version known
    if fixed_version:
        if is_firewall:
            return [
                _ver(current_version, fixed_version) + " via firmware update",
                "Apply latest Fireware OS / FortiOS / PAN-OS firmware from vendor",
                "Firewall devices run embedded software — upgrade the entire OS image",
                f"NVD: https://nvd.nist.gov/vuln/detail/{cve_id}",
            ]
        if is_embedded:
            return [
                _ver(current_version, fixed_version),
                "This is an embedded/IoT device. Check manufacturer for firmware updates.",
                "Embedded device — may require full firmware reflash or vendor image.",
                f"NVD: https://nvd.nist.gov/vuln/detail/{cve_id}",
            ]
        if is_printer:
            return [
                _ver(current_version, fixed_version) + " via printer firmware update",
                "Download firmware from manufacturer support site",
                "Apply via printer web interface or USB firmware update",
                f"NVD: https://nvd.nist.gov/vuln/detail/{cve_id}",
            ]
        if is_camera:
            return [
                _ver(current_version, fixed_version) + " via camera firmware",
                "Download firmware from camera/NVR vendor support site",
                "Apply via web interface: System → Maintenance → Firmware Upgrade",
                f"NVD: https://nvd.nist.gov/vuln/detail/{cve_id}",
            ]
        if "windows" in os_lower:
            return [
                _ver(current_version, fixed_version),
                "Check vendor site for specific download/update instructions",
                f"NVD: https://nvd.nist.gov/vuln/detail/{cve_id}",
            ]
        if is_rhel:
            return [
                _ver(current_version, fixed_version),
                f"dnf update {product} -y",
                f"NVD: https://nvd.nist.gov/vuln/detail/{cve_id}",
            ]
        if is_generic_linux:
            return [
                _ver(current_version, fixed_version),
                f"Debian/Ubuntu: apt install {product}",
                f"RHEL/Oracle/Rocky: dnf update {product} -y",
                f"NVD: https://nvd.nist.gov/vuln/detail/{cve_id}",
            ]
        return [
            _ver(current_version, fixed_version),
            f"Debian/Ubuntu: apt install {product}",
            f"RHEL/Oracle/Rocky: dnf update {product} -y",
            f"NVD: https://nvd.nist.gov/vuln/detail/{cve_id}",
        ]

    return []


def _infer_os_compatibility(host_os: str, product: str) -> list[str]:
    """Infer which OS families this patch applies to."""
    os_lower = host_os.lower()
    compat = []
    if "windows" in os_lower:
        compat = ["Windows"]
    elif "linux" in os_lower or "ubuntu" in os_lower or "debian" in os_lower:
        compat = ["Linux"]
    elif "cisco" in os_lower or "ios" in os_lower:
        compat = ["Cisco"]
    return compat
