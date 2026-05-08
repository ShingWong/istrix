"""Windows probe module — NetBIOS name queries for workstation/server detection.

Probes UDP port 137 (NetBIOS Name Service) on Windows hosts to extract
computer name, domain/workgroup, and server role. Works without auth.
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone

from istrix.engine.modules.base import ScanModule
from istrix.models.finding import Finding


class WindowsProbeModule(ScanModule):
    """Probe Windows hosts via NetBIOS NS (UDP 137) for computer name + domain.

    When Windows services are detected (SMB 445, RPC 135, Kerberos 88),
    queries NetBIOS to reveal the computer's NetBIOS name, domain membership,
    and whether it acts as a file server or workstation.
    """

    name = "windows_probe"
    description = "NetBIOS probe for Windows computer name, domain, and server role"
    consumed_types = ["open_port", "service"]
    produced_types = ["os", "service"]
    optional = True

    _TIMEOUT = 3

    def run(self, findings: list[Finding]) -> list[Finding]:
        results: list[Finding] = []
        timestamp = datetime.now(timezone.utc).isoformat()

        hosts = set(f.host for f in findings if f.host)
        for host in hosts:
            host_findings = [f for f in findings if f.host == host]
            if not self._is_windows_host(host_findings):
                continue

            nb_info = self._probe_netbios(host, timestamp)
            if nb_info:
                results.extend(nb_info)

        return results

    def _is_windows_host(self, findings: list[Finding]) -> bool:
        """Check if host has Windows-typical services."""
        for f in findings:
            if f.type == "service":
                d = (f.detail or "").lower()
                if any(kw in d for kw in (
                    "microsoft", "windows", "msrpc", "microsoft-ds",
                    "kerberos", "ms-wbt-server", "active directory",
                    "iis", "dameware",
                )):
                    return True
        return False

    # ── NetBIOS probe ────────────────────────────────────────────────

    def _probe_netbios(self, host: str, ts: str) -> list[Finding]:
        """Query NetBIOS Name Service (UDP 137) for computer name + domain."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self._TIMEOUT)

            # NetBIOS Node Status query (* query)
            query = bytes([
                0x12, 0x34,  # transaction id
                0x00, 0x00,  # flags
                0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x20,  # name length (32)
                # Encoded '*' (32 bytes of CKAAAAAAAA...)
                0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00,
                0x00, 0x21, 0x00, 0x01,  # type=NBSTAT, class=IN
            ])

            sock.sendto(query, (host, 137))
            try:
                resp, _ = sock.recvfrom(1024)
            except socket.timeout:
                sock.close()
                return []
            sock.close()

            if len(resp) < 60:
                return []

            # Parse NetBIOS name entries (start at byte 57)
            names: list[tuple[str, str]] = []
            for i in range(57, len(resp) - 14, 18):
                if i + 16 > len(resp):
                    break
                name = resp[i:i + 15].rstrip(b" \x00").decode("ascii", errors="replace")
                flags = resp[i + 15]
                if name:
                    role = {
                        0x00: "workstation",
                        0x20: "file server",
                        0x1C: "domain controller",
                        0x1B: "domain master",
                        0x03: "messenger",
                        0x1E: "browser",
                    }.get(flags, "")
                    names.append((name, role))

            if not names:
                return []

            findings: list[Finding] = []
            comp_name = ""
            domain = ""
            roles: list[str] = []

            for name, role in names:
                if role == "workstation":
                    comp_name = comp_name or name
                elif role in ("domain controller", "domain master"):
                    domain = domain or name
                    comp_name = comp_name or name
                elif role == "file server":
                    comp_name = comp_name or name
                    roles.append(role)
                elif role:
                    roles.append(role)
                elif not comp_name and name.isprintable():
                    domain = domain or name  # might be domain

            # Build NetBIOS summary
            nb_parts = [f"NetBIOS: {comp_name}"] if comp_name else []
            if domain:
                nb_parts.append(f"domain={domain}")
            if roles:
                nb_parts.append(f"roles={','.join(roles)}")

            if nb_parts:
                findings.append(Finding(
                    type="service",
                    host=host, port=137,
                    detail=", ".join(nb_parts),
                    source="windows_probe_nb",
                    timestamp=ts,
                ))

            # Create OS finding with computer name
            if comp_name:
                os_parts = [f"NetBIOS: {comp_name}"]
                if domain:
                    os_parts.append(f"({domain})")
                findings.append(Finding(
                    type="os",
                    host=host, port=137,
                    detail=" ".join(os_parts),
                    source="windows_probe_nb",
                    timestamp=ts,
                ))

            return findings

        except (OSError, socket.timeout):
            return []
