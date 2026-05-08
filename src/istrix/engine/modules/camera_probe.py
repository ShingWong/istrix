"""Camera/NVR probe module — fingerprint IP cameras via HTTP and ONVIF.

Many Chinese cameras share the same HiSilicon/Goke SoC with near-identical
web interfaces (jQuery + hash-bundled JS). This module probes HTTP endpoints
and gSOAP/ONVIF ports to extract model and firmware info.
"""

from __future__ import annotations

import re
import socket
from datetime import datetime, timezone

from istrix.engine.modules.base import ScanModule
from istrix.models.finding import Finding


class CameraProbeModule(ScanModule):
    """Probe IP cameras and NVRs for brand, model, and firmware version."""

    name = "camera_probe"
    description = "Probe IP cameras/NVRs via HTTP and ONVIF for device identity"
    consumed_types = ["open_port", "service"]
    produced_types = ["os", "service"]
    optional = True

    _TIMEOUT = 4
    _MAX_RECV = 65536

    # Known camera brand signatures in HTTP responses
    _HTTP_FINGERPRINTS = {
        "Dahua": [r'Dahua', r'dahua', r'DH-IPC', r'DH-NVR', r'DHI-', r'/cgi-bin/magicBox'],
        "Hikvision": [r'Hikvision', r'hikvision', r'DS-2CD', r'/ISAPI/', r'doc/page/login'],
        "Uniview": [r'Uniview', r'uniview', r'IPC\d{4,}', r'/SDK/'],
        "Tiandy": [r'Tiandy', r'tiandy', r'TC-'],
        "Xiongmai": [r'Xiongmai', r'NetSurveillance', r'/web/xmweb'],
        "Reolink": [r'Reolink', r'reolink', r'RLN\d'],
    }

    def run(self, findings: list[Finding]) -> list[Finding]:
        results: list[Finding] = []
        timestamp = datetime.now(timezone.utc).isoformat()

        # Identify camera hosts: have RTSP (554), gSOAP, UPnP with HiSilicon
        cam_hosts: set[str] = set()
        for f in findings:
            if f.type != "service":
                continue
            d = (f.detail or "").lower()
            if any(kw in d for kw in (
                "rtsp", "gsoap", "hi3536", "hi3516", "hi3518",
                "botvac", "onvif", "ndmps", "tcpwrapped",
            )):
                cam_hosts.add(f.host)

        for host in cam_hosts:
            # HTTP probe on port 80
            http_info = self._probe_http(host, 80, timestamp)
            if http_info:
                results.extend(http_info)

        return results

    def _probe_http(self, host: str, port: int, ts: str) -> list[Finding]:
        """Probe HTTP for camera web interface and device info."""
        findings: list[Finding] = []
        text = self._http_get(host, port, "/")

        if not text:
            return findings

        # 1. Brand fingerprint from HTTP body
        brand = ""
        for vendor, patterns in self._HTTP_FINGERPRINTS.items():
            for pat in patterns:
                if re.search(pat, text, re.IGNORECASE):
                    brand = vendor
                    break
            if brand:
                break

        # 2. Title extraction
        title = ""
        tm = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE)
        if tm:
            title = tm.group(1).strip()

        # 3. Script fingerprint (NVR/DVR common.js pattern)
        is_nvr = bool(re.search(r'"NVRDVR"|"nvr"|"dvr"', text, re.IGNORECASE))

        # 4. Build enriched OS finding
        if brand or title:
            os_parts = []
            if brand:
                os_parts.append(f"Camera: {brand}")
            if title:
                os_parts.append(f"({title})")
            if is_nvr:
                os_parts.append("[NVR/DVR]")

            findings.append(Finding(
                type="os", host=host, port=port,
                detail=" ".join(os_parts),
                source="camera_probe_http",
                timestamp=ts,
            ))

        # 5. Report chipset from UPnP (already in findings, just enrich)
        # That's handled by the UPnP OS detection in generator.py

        return findings

    def _http_get(self, host: str, port: int, path: str) -> str:
        """Simple HTTP GET returning response body as string."""
        try:
            s = socket.socket()
            s.settimeout(self._TIMEOUT)
            s.connect((host, port))
            s.sendall(
                f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
                "Accept: text/html,*/*\r\n\r\n".encode()
            )
            resp = b""
            while True:
                try:
                    chunk = s.recv(8192)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) > self._MAX_RECV:
                        break
                except socket.timeout:
                    break
            s.close()
            # Return body after headers
            if b"\r\n\r\n" in resp:
                return resp.split(b"\r\n\r\n", 1)[1].decode("utf-8", errors="replace")
            return resp.decode("utf-8", errors="replace")
        except Exception:
            return ""
