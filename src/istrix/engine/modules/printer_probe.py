"""Printer probe module — IPP + PJL device fingerprinting.

Probes detected printer services (IPP port 631, JetDirect port 9100)
to extract make, model, firmware version, and serial number.
Uses raw TCP/HTTP sockets — no additional dependencies.
"""

from __future__ import annotations

import re
import socket
from datetime import datetime, timezone

from istrix.engine.modules.base import ScanModule
from istrix.models.finding import Finding

_IPP_GET_ATTRS = (
    b"POST / HTTP/1.1\r\n"
    b"Host: printer\r\n"
    b"Content-Type: application/ipp\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"\r\n"
)

_PJL_INFO_ID = b"@PJL INFO ID\r\n"
_PJL_EOJ = b"\x1b%-12345X"


class PrinterProbeModule(ScanModule):
    """Probe printers via IPP and PJL to extract model/firmware details.

    When printer services are detected (jetdirect on 9100, ipp/cups on 631),
    sends lightweight probes to query device identity and firmware version.
    """

    name = "printer_probe"
    description = "Probe printers via IPP (631) and PJL (9100) for model + firmware"
    consumed_types = ["open_port", "service"]
    produced_types = ["printer", "os"]
    optional = True

    _TIMEOUT = 5

    def run(self, findings: list[Finding]) -> list[Finding]:
        results: list[Finding] = []
        timestamp = datetime.now(timezone.utc).isoformat()

        for f in findings:
            if f.type != "service":
                continue
            port = f.port
            detail_lower = (f.detail or "").lower()
            host = f.host

            # IPP / CUPS on port 631
            if port == 631 and ("ipp" in detail_lower or "cups" in detail_lower or "http" in detail_lower):
                info = self._probe_ipp(host, port, timestamp)
                if info:
                    results.extend(info)

            # PJL / JetDirect on port 9100
            if port == 9100 and ("jetdirect" in detail_lower or "printer" in detail_lower or "pjl" in detail_lower):
                info = self._probe_pjl(host, port, timestamp)
                if info:
                    results.extend(info)

        return results

    # ── IPP probe ────────────────────────────────────────────────────

    def _probe_ipp(self, host: str, port: int, ts: str) -> list[Finding]:
        """Send IPP Get-Printer-Attributes and parse printer info."""
        try:
            sock = socket.create_connection((host, port), timeout=self._TIMEOUT)
            try:
                # Minimal IPP Get-Printer-Attributes request
                # Operation: 0x000B (Get-Printer-Attributes), version 2.0
                req_grp = (
                    b"\x01\x01"  # begin-attributes-group (operation)
                    b"\x47"      # charset: value-tag
                    b"\x00\x12"  # name-length
                    b"attributes-charset"
                    b"\x00\x05"  # value-length
                    b"utf-8"
                    b"\x48"      # natural-language: value-tag
                    b"\x00\x1b"  # name-length
                    b"attributes-natural-language"
                    b"\x00\x02"  # value-length
                    b"en"
                    b"\x45"      # printer-uri: uri value-tag  
                    b"\x00\x0b"  # name-length
                    b"printer-uri"
                    b"\x00\x0f"  # value-length
                    b"ipp://localhost/"
                    b"\x03"      # end-of-attributes
                )
                payload = req_grp + b"\x03"  # end-of-attributes + end
                chunk = f"{len(payload):X}\r\n".encode() + payload + b"\r\n0\r\n\r\n"

                http_req = (
                    b"POST / HTTP/1.1\r\n"
                    b"Host: " + host.encode() + b"\r\n"
                    b"Content-Type: application/ipp\r\n"
                    b"Transfer-Encoding: chunked\r\n"
                    b"\r\n"
                    + chunk
                )

                sock.sendall(http_req)
                resp = b""
                while True:
                    try:
                        chunk_data = sock.recv(4096)
                        if not chunk_data:
                            break
                        resp += chunk_data
                        if b"\r\n\r\n" in resp:
                            # Wait for full body
                            if len(resp) > 4096:
                                break
                    except socket.timeout:
                        break
            finally:
                sock.close()

            body = self._extract_http_body(resp)
            if not body:
                return []

            info = self._parse_ipp_attributes(body)
            if not info:
                return []

            findings: list[Finding] = []
            if info.get("model"):
                findings.append(Finding(
                    type="printer",
                    host=host, port=port,
                    detail=f"Printer: {info['model']}",
                    source="printer_probe_ipp",
                    timestamp=ts,
                ))
            if info.get("firmware"):
                findings.append(Finding(
                    type="printer",
                    host=host, port=port,
                    detail=f"Firmware: {info['firmware']}",
                    source="printer_probe_ipp",
                    timestamp=ts,
                ))
            if info.get("model"):
                findings.append(Finding(
                    type="os",
                    host=host, port=port,
                    detail=f"Printer: {info['model']}",
                    source="printer_probe_ipp",
                    timestamp=ts,
                ))
            return findings

        except (OSError, socket.timeout):
            return []

    # ── PJL probe ────────────────────────────────────────────────────

    def _probe_pjl(self, host: str, port: int, ts: str) -> list[Finding]:
        """Send PJL INFO ID and parse printer identity."""
        try:
            sock = socket.create_connection((host, port), timeout=self._TIMEOUT)
            try:
                sock.settimeout(3)
                # UEL + PJL INFO ID + UEL
                sock.sendall(_PJL_EOJ + _PJL_INFO_ID + _PJL_EOJ)
                resp = b""
                while True:
                    try:
                        chunk = sock.recv(1024)
                        if not chunk:
                            break
                        resp += chunk
                    except socket.timeout:
                        break
            finally:
                sock.close()

            text = resp.decode("ascii", errors="replace")
            info = self._parse_pjl_response(text)
            if not info:
                return []

            findings: list[Finding] = []
            if info.get("model"):
                findings.append(Finding(
                    type="printer",
                    host=host, port=port,
                    detail=f"Printer: {info['model']}",
                    source="printer_probe_pjl",
                    timestamp=ts,
                ))
            if info.get("firmware"):
                findings.append(Finding(
                    type="printer",
                    host=host, port=port,
                    detail=f"Firmware: {info['firmware']}",
                    source="printer_probe_pjl",
                    timestamp=ts,
                ))
            if info.get("serial"):
                findings.append(Finding(
                    type="printer",
                    host=host, port=port,
                    detail=f"Serial: {info['serial']}",
                    source="printer_probe_pjl",
                    timestamp=ts,
                ))
            if info.get("model"):
                findings.append(Finding(
                    type="os",
                    host=host, port=port,
                    detail=f"Printer: {info['model']}",
                    source="printer_probe_pjl",
                    timestamp=ts,
                ))
            return findings

        except (OSError, socket.timeout):
            return []

    # ── Parsers ──────────────────────────────────────────────────────

    @staticmethod
    def _extract_http_body(resp: bytes) -> bytes:
        """Extract body from HTTP response."""
        try:
            text = resp.decode("ascii", errors="replace")
            parts = text.split("\r\n\r\n", 1)
            if len(parts) < 2:
                return b""
            raw = parts[1].encode("ascii", errors="replace")
            # Handle chunked encoding
            if "Transfer-Encoding: chunked" in parts[0]:
                return PrinterProbeModule._dechunk(raw)
            return raw
        except Exception:
            return b""

    @staticmethod
    def _dechunk(data: bytes) -> bytes:
        """Simple HTTP chunked transfer decoder."""
        out = bytearray()
        while data:
            header_end = data.find(b"\r\n")
            if header_end < 0:
                break
            chunk_size = int(data[:header_end], 16)
            if chunk_size == 0:
                break
            start = header_end + 2
            out.extend(data[start:start + chunk_size])
            data = data[start + chunk_size + 2:]  # skip chunk data + \r\n
        return bytes(out)

    @staticmethod
    def _parse_ipp_attributes(body: bytes) -> dict[str, str]:
        """Extract printer make/model and firmware from IPP attributes."""
        info: dict[str, str] = {}
        # IPP attribute binary parsing
        # Simpler: just search for known attribute names
        for attr_name in ["printer-make-and-model", "printer-firmware-name",
                          "printer-firmware-version"]:
            m = re.search(
                r"\x44"  # keyword value-tag
                + chr(len(attr_name)).encode("utf-8").decode("latin-1")
                + attr_name
                + r"(.{0,2})([\x20-\x7e]{2,80})",
                body.decode("latin-1"),
            )
            if m:
                value = m.group(2).strip("\x00")
                if attr_name == "printer-make-and-model":
                    info["model"] = value
                else:
                    info["firmware"] = value
        return info

    @staticmethod
    def _parse_pjl_response(text: str) -> dict[str, str]:
        """Extract model and serial from PJL INFO ID response."""
        info: dict[str, str] = {}
        # Example response:
        # @PJL INFO ID
        # "HP LaserJet Pro M404n"
        # <CR><LF><FF>
        for line in text.splitlines():
            line = line.strip().strip('"')
            if not line or line.startswith("@PJL") or line.startswith("\x0c"):
                continue
            # First meaningful line is the model
            if "model" not in info:
                # Try to extract firmware version from lines
                m = re.search(r"firmware[:\s]+([\w.]+)", line, re.IGNORECASE)
                if m:
                    info["firmware"] = m.group(1)
                    continue
                m = re.search(r"serial[:\s]+([\w-]+)", line, re.IGNORECASE)
                if m:
                    info["serial"] = m.group(1)
                    continue
                if re.match(r"^[\w\s.-]{4,40}$", line):
                    info["model"] = line
            else:
                m = re.search(r"firmware[:\s]+([\w.]+)", line, re.IGNORECASE)
                if m:
                    info["firmware"] = m.group(1)
                m = re.search(r"serial[:\s]+([\w-]+)", line, re.IGNORECASE)
                if m:
                    info["serial"] = m.group(1)
        return info
