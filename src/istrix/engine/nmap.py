"""nmap integration via subprocess with XML parsing."""

import os
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from istrix.models.finding import Finding


NMAP_PATH: str | None = None


def _get_nmap_path() -> str | None:
    """Locate nmap binary on the system."""
    global NMAP_PATH
    if NMAP_PATH is None:
        NMAP_PATH = shutil.which("nmap")
    return NMAP_PATH


def nmap_available() -> bool:
    """Check if nmap is installed and accessible."""
    return _get_nmap_path() is not None


def run_nmap(
    target: str,
    flags: str = "-sS -T4 -F",
    timeout: int = 300,
) -> list[Finding]:
    """Run nmap against a target with given flags.

    Args:
        target: IP address, hostname, or CIDR
        flags: nmap command-line flags (without -oX)
        timeout: Maximum runtime in seconds

    Returns:
        List of Finding objects parsed from nmap XML output

    Raises:
        FileNotFoundError: If nmap is not installed
        subprocess.TimeoutExpired: If scan exceeds timeout
    """
    nmap_path = _get_nmap_path()
    if nmap_path is None:
        raise FileNotFoundError(
            "nmap is not installed. Install it with: apt install nmap"
        )

    # If non-root, try sudo first (SYN scans + OS detection require root).
    # If sudo fails, fall back to TCP connect (-sT) with OS detection stripped.
    if os.geteuid() != 0:
        try:
            result = subprocess.run(
                ["sudo", "-n", nmap_path, "-oX", "-"] + flags.split() + [target],
                capture_output=True, text=True, timeout=timeout,
            )
            if result.returncode == 0 or result.stdout.strip():
                return parse_nmap_xml(result.stdout, target)
        except (subprocess.TimeoutExpired, PermissionError, FileNotFoundError):
            pass
        # Sudo failed — strip privileged flags and retry
        if "-sS" in flags:
            flags = flags.replace("-sS", "-sT")
        flags = flags.replace(" -O", "").replace("-O ", "").replace("-O", "")

    cmd = [nmap_path, "-oX", "-"] + flags.split() + [target]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise

    if result.returncode != 0 and not result.stdout.strip():
        raise RuntimeError(
            f"nmap failed (exit code {result.returncode}): {result.stderr}"
        )

    return parse_nmap_xml(result.stdout, target)


def parse_nmap_xml(xml_output: str, target_hint: str = "") -> list[Finding]:
    """Parse nmap XML output (-oX -) into Finding objects.

    Extracts:
    - Host IP addresses
    - Hostnames (PTR, user-supplied)
    - Open/filtered ports with service info
    - OS detection matches
    - NSE script output (vuln scripts)

    Args:
        xml_output: Raw XML string from nmap -oX -
        target_hint: Original target string for hostname fallback

    Returns:
        List of Finding objects
    """
    findings: list[Finding] = []
    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        root = ET.fromstring(xml_output.strip())
    except ET.ParseError as e:
        raise ValueError(f"Failed to parse nmap XML: {e}")

    for host_elem in root.findall("host"):
        host_ip = _extract_ip(host_elem)
        hostnames = _extract_hostnames(host_elem)

        if not host_ip:
            continue

        for hostname in hostnames:
            findings.append(Finding(
                type="dns",
                host=host_ip,
                detail=f"Hostname: {hostname}",
                source="nmap",
                timestamp=timestamp,
            ))

        for port_elem in host_elem.findall(".//port"):
            findings.extend(_parse_port(port_elem, host_ip, timestamp))

        for os_elem in host_elem.findall("os"):
            findings.extend(_parse_os(os_elem, host_ip, timestamp))

        for script_elem in host_elem.findall(".//script"):
            findings.extend(_parse_script(script_elem, host_ip, timestamp))

    return findings


def _extract_ip(host_elem: ET.Element) -> str:
    addr_elem = host_elem.find("address")
    if addr_elem is not None:
        return addr_elem.get("addr", "")
    return ""


def _extract_hostnames(host_elem: ET.Element) -> list[str]:
    hostnames: list[str] = []
    hostnames_elem = host_elem.find("hostnames")
    if hostnames_elem is not None:
        for hn in hostnames_elem.findall("hostname"):
            name = hn.get("name", "")
            if name:
                hostnames.append(name)
    return hostnames


def _parse_port(port_elem: ET.Element, host_ip: str, timestamp: str) -> list[Finding]:
    findings: list[Finding] = []

    port_id = port_elem.get("portid", "")
    protocol = port_elem.get("protocol", "")
    state_elem = port_elem.find("state")
    state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

    if state not in ("open", "open|filtered", "filtered"):
        return findings

    port_num = int(port_id) if port_id.isdigit() else None

    findings.append(Finding(
        type="open_port",
        host=host_ip,
        port=port_num,
        protocol=protocol,
        detail=f"Port {port_id}/{protocol} is {state}",
        severity="info",
        source="nmap",
        timestamp=timestamp,
    ))

    service_elem = port_elem.find("service")
    if service_elem is not None:
        service_name = service_elem.get("name", "unknown")
        product = service_elem.get("product", "")
        version = service_elem.get("version", "")
        extrainfo = service_elem.get("extrainfo", "")

        detail_parts = [f"Service: {service_name}"]
        if product:
            detail_parts.append(product)
        if version:
            detail_parts.append(version)
        if extrainfo:
            detail_parts.append(f"({extrainfo})")

        findings.append(Finding(
            type="service",
            host=host_ip,
            port=port_num,
            protocol=protocol,
            detail=" ".join(detail_parts),
            severity="info",
            source="nmap",
            evidence=f"product={product} version={version} extrainfo={extrainfo}",
            timestamp=timestamp,
        ))

    return findings


def _parse_os(os_elem: ET.Element, host_ip: str, timestamp: str) -> list[Finding]:
    findings: list[Finding] = []

    for osmatch in os_elem.findall("osmatch"):
        name = osmatch.get("name", "")
        accuracy = osmatch.get("accuracy", "")
        osclass = osmatch.find("osclass")
        vendor = osclass.get("vendor", "") if osclass is not None else ""
        osfamily = osclass.get("osfamily", "") if osclass is not None else ""
        osgen = osclass.get("osgen", "") if osclass is not None else ""

        detail = f"OS: {name} (accuracy: {accuracy}%)"
        if vendor:
            detail += f" vendor={vendor}"
        if osfamily:
            detail += f" family={osfamily}"
        if osgen:
            detail += f" gen={osgen}"

        findings.append(Finding(
            type="os",
            host=host_ip,
            detail=detail,
            severity="info",
            source="nmap",
            timestamp=timestamp,
        ))
        break

    return findings


def _parse_script(script_elem: ET.Element, host_ip: str, timestamp: str) -> list[Finding]:
    findings: list[Finding] = []

    script_id = script_elem.get("id", "")
    script_output = script_elem.get("output", "")

    if not script_output:
        return findings

    is_vuln = "vuln" in script_id.lower() or "CVE" in script_output
    is_cdp = script_id.startswith("broadcast-cdp") or script_id.startswith("cdp-")
    is_lldp = script_id.startswith("broadcast-lldp") or script_id.startswith("lldp-")
    is_snmp = script_id.startswith("snmp-")
    is_ldap_rootdse = "ldap-rootdse" in script_id.lower()
    is_discovery = is_cdp or is_lldp or is_snmp

    # CDP/LLDP/SNMP: extract device identity info
    if is_discovery:
        findings.extend(_parse_discovery_script(script_id, script_output, host_ip, timestamp))
        return findings

    # LDAP RootDSE: extract AD domain + functional level
    if is_ldap_rootdse:
        findings.extend(_parse_ldap_rootdse(script_output, host_ip, timestamp))
        return findings

    severity = _classify_severity(script_output, is_vuln)
    cve_ids = _extract_cves(script_output)
    primary_cve = cve_ids[0] if cve_ids else None

    finding_type = "vulnerability" if (is_vuln and severity in ("critical", "high", "medium")) else "other"

    findings.append(Finding(
        type=finding_type,
        host=host_ip,
        detail=f"[{script_id}] {script_output[:200]}",
        severity=severity,
        source="nmap",
        cve=primary_cve,
        evidence=script_output[:500],
        timestamp=timestamp,
    ))

    if cve_ids:
        for cve in cve_ids:
            findings.append(Finding(
                type="vulnerability",
                host=host_ip,
                detail=f"CVE identified by nmap {script_id}: {cve}",
                severity=severity,
                source="nmap",
                cve=cve,
                timestamp=timestamp,
            ))

    return findings


def _parse_ldap_rootdse(
    output: str, host_ip: str, timestamp: str
) -> list[Finding]:
    """Parse ldap-rootdse NSE script output for AD domain + functional level."""
    findings: list[Finding] = []

    func_level = ""
    domain = ""
    fqdn = ""

    for line in output.splitlines():
        line = line.strip()
        if "domainFunctionality:" in line:
            func_level = line.split(":", 1)[1].strip()
        elif "rootDomainNamingContext:" in line:
            raw = line.split(":", 1)[1].strip()
            domain = raw.replace("DC=", "").replace(",", ".")
        elif "ldapServiceName:" in line:
            raw = line.split(":", 1)[1].strip()
            # Format: example.corp.local:dc01-example$@EXAMPLE.CORP.LOCAL
            fqdn = raw.split(":")[0].strip() if ":" in raw else raw

    if domain:
        findings.append(Finding(
            type="service",
            host=host_ip, port=389,
            detail=f"Active Directory Domain: {domain}",
            source="ldap-rootdse",
            timestamp=timestamp,
        ))

    if func_level:
        # Map functional level to Windows Server version
        level_map = {
            "0": "Windows 2000",
            "2": "Windows Server 2003",
            "3": "Windows Server 2008",
            "4": "Windows Server 2008 R2",
            "5": "Windows Server 2012",
            "6": "Windows Server 2012 R2",
            "7": "Windows Server 2016/2019",
            "8": "Windows Server 2022",
        }
        win_ver = level_map.get(func_level, f"Windows (FL {func_level})")
        findings.append(Finding(
            type="os",
            host=host_ip, port=389,
            detail=f"AD: {win_ver} (functional level {func_level})",
            source="ldap-rootdse",
            timestamp=timestamp,
        ))

    if fqdn:
        findings.append(Finding(
            type="service",
            host=host_ip, port=389,
            detail=f"LDAP FQDN: {fqdn}",
            source="ldap-rootdse",
            timestamp=timestamp,
        ))

    return findings


def _parse_discovery_script(
    script_id: str, output: str, host_ip: str, timestamp: str
) -> list[Finding]:
    """Parse CDP/LLDP/SNMP discovery script output for device identity.

    Extracts device platform, software version, and management addresses
    for accurate OS/hardware classification of network gear.
    """
    import re
    findings: list[Finding] = []

    protocol = "cdp" if ("cdp" in script_id.lower()) else \
               "lldp" if ("lldp" in script_id.lower()) else \
               "snmp" if ("snmp" in script_id.lower()) else "discovery"

    # Extract platform / OS name
    platform = ""
    # CDP: "Platform: cisco WS-C3750E-24TD-S, Capabilities: Router Switch"
    m = re.search(r'(?:Platform|Device\s+ID):\s*(.+?)(?:,|$)', output)
    if m:
        platform = m.group(1).strip()
    # SNMP: "sysDescr: Cisco IOS Software, C3750E Software..."
    if not platform:
        m = re.search(r'(?:sysDescr|System\s+Description):\s*(.+?)(?:\n|$)', output)
        if m:
            platform = m.group(1).strip()[:120]

    # Extract software version
    version = ""
    m = re.search(r'(?:Version|Software\s+Version):\s*(\S+)', output)
    if m:
        version = m.group(1).strip()

    # Extract device vendor
    vendor = ""
    if "cisco" in output.lower():
        vendor = "Cisco"
    elif "juniper" in output.lower():
        vendor = "Juniper"
    elif "arista" in output.lower():
        vendor = "Arista"
    elif "hp" in output.lower() or "hewlett" in output.lower():
        vendor = "HP"
    elif "brocade" in output.lower() or "ruckus" in output.lower():
        vendor = "Brocade/Ruckus"

    if platform or vendor:
        os_detail = f"OS: {vendor} {platform}" if vendor else f"OS: {platform}"
        if version:
            os_detail += f" ({version})"
        findings.append(Finding(
            type="os",
            host=host_ip,
            detail=os_detail[:200],
            severity="info",
            source=f"nmap/{protocol}",
            evidence=output[:500],
            timestamp=timestamp,
        ))

    # Store full discovery output for hardware detection
    findings.append(Finding(
        type="other",
        host=host_ip,
        detail=f"[{protocol}-discovery] {output[:200]}",
        severity="info",
        source=f"nmap/{protocol}",
        evidence=output[:800],
        timestamp=timestamp,
    ))

    return findings


def _classify_severity(output: str, is_vuln: bool) -> str:
    """Classify severity from nmap script output based on CVSS scores and keywords."""
    import re

    cvss_match = re.findall(r'(\d+\.\d+)\s*https?://', output)
    if cvss_match:
        try:
            max_score = max(float(s) for s in cvss_match)
        except ValueError:
            max_score = 0.0
        if max_score >= 9.0:
            return "critical"
        elif max_score >= 7.0:
            return "high"
        elif max_score >= 4.0:
            return "medium"
        elif max_score >= 0.1:
            return "low"

    if not is_vuln:
        return "info"

    if "EXPLOIT" in output or "exploit available" in output.lower():
        return "high"
    if "vulnerability" in output.lower() or "CVE" in output:
        return "medium"

    return "info"


def _extract_cves(output: str) -> list[str]:
    """Extract CVE IDs from nmap script output."""
    import re
    cve_pattern = r'CVE-\d{4}-\d{4,}'
    return list(dict.fromkeys(re.findall(cve_pattern, output)))
