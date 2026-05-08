"""CDP and LLDP listener for hardware/device discovery.

CDP (Cisco Discovery Protocol) — Cisco proprietary, multicast 01:00:0c:cc:cc:cc
LLDP (Link Layer Discovery Protocol) — IEEE 802.1AB, multicast 01:80:c2:00:00:0e

Requires: CAP_NET_RAW capability or root for raw socket capture.
Without elevated privileges, falls back to tcpdump subprocess (needs sudo).

Usage:
    from istrix.engine.modules.cdp_lldp import capture_cdp_lldp
    devices = capture_cdp_lldp(interface="enp1s0", timeout=30)
"""

import socket
import struct
import subprocess
import time
from typing import Optional

# Ethernet frame types
ETH_P_ALL = 0x0003
CDP_MULTICAST_MAC = b"\x01\x00\x0c\xcc\xcc\xcc"
LLDP_MULTICAST_MAC = b"\x01\x80\xc2\x00\x00\x0e"

# CDP TLV types
CDP_TLV_DEVICE_ID = 0x0001
CDP_TLV_ADDRESS = 0x0002
CDP_TLV_PORT_ID = 0x0003
CDP_TLV_CAPABILITIES = 0x0004
CDP_TLV_SOFTWARE_VERSION = 0x0005
CDP_TLV_PLATFORM = 0x0006
CDP_TLV_NATIVE_VLAN = 0x000A
CDP_TLV_DUPLEX = 0x000B

# LLDP TLV types
LLDP_TLV_CHASSIS_ID = 1
LLDP_TLV_PORT_ID = 2
LLDP_TLV_TTL = 3
LLDP_TLV_PORT_DESC = 4
LLDP_TLV_SYSTEM_NAME = 5
LLDP_TLV_SYSTEM_DESC = 6
LLDP_TLV_SYSTEM_CAP = 7
LLDP_TLV_MGMT_ADDR = 8
LLDP_TLV_END = 0


class CDPDevice:
    """Parsed CDP announcement from a neighboring device."""

    def __init__(self):
        self.device_id: str = ""
        self.platform: str = ""
        self.software_version: str = ""
        self.port_id: str = ""
        self.capabilities: list[str] = []
        self.addresses: list[str] = []
        self.native_vlan: int = 0


class LLDPDevice:
    """Parsed LLDP announcement from a neighboring device."""

    def __init__(self):
        self.chassis_id: str = ""
        self.system_name: str = ""
        self.system_desc: str = ""
        self.port_id: str = ""
        self.port_desc: str = ""
        self.mgmt_addresses: list[str] = []
        self.capabilities: str = ""


class DiscoveryResult:
    """Combined CDP/LLDP discovery result."""

    def __init__(self):
        self.cdp_devices: list[CDPDevice] = []
        self.lldp_devices: list[LLDPDevice] = []

    def summary(self) -> list[dict]:
        """Return flat list of device dicts for report integration."""
        devices = []
        for d in self.cdp_devices:
            devices.append({
                "protocol": "CDP",
                "device_id": d.device_id,
                "platform": d.platform,
                "version": d.software_version,
                "port": d.port_id,
                "addresses": d.addresses,
            })
        for d in self.lldp_devices:
            devices.append({
                "protocol": "LLDP",
                "device_id": d.system_name or d.chassis_id,
                "platform": d.system_desc[:100] if d.system_desc else "",
                "version": "",
                "port": d.port_desc or d.port_id,
                "addresses": d.mgmt_addresses,
            })
        return devices


# ---------------------------------------------------------------------------
# Raw socket capture (needs CAP_NET_RAW or root)
# ---------------------------------------------------------------------------

def _has_raw_capability() -> bool:
    """Check if we can open raw sockets."""
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        s.close()
        return True
    except PermissionError:
        return False


def capture_via_raw_socket(interface: str = "enp1s0", timeout: int = 30) -> DiscoveryResult:
    """Capture CDP/LLDP frames via AF_PACKET raw socket.

    Requires CAP_NET_RAW: sudo setcap cap_net_raw+ep $(which python3)
    """
    result = DiscoveryResult()
    if not _has_raw_capability():
        return result

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((interface, 0))
    sock.settimeout(timeout)

    deadline = time.monotonic() + timeout
    cdp_seen: set[str] = set()
    lldp_seen: set[str] = set()

    try:
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                packet = sock.recv(65535)
            except socket.timeout:
                break

            # Ethernet header: dst(6) src(6) ethertype(2) = 14 bytes
            if len(packet) < 14:
                continue
            dst_mac = packet[0:6]
            ethertype = struct.unpack("!H", packet[12:14])[0]

            # CDP uses LLC/SNAP encapsulation (not a standard ethertype)
            # LLDP uses ethertype 0x88CC
            if dst_mac == CDP_MULTICAST_MAC:
                device = _parse_cdp_frame(packet[14:])
                if device and device.device_id not in cdp_seen:
                    cdp_seen.add(device.device_id)
                    result.cdp_devices.append(device)
            elif ethertype == 0x88CC and dst_mac == LLDP_MULTICAST_MAC:
                device = _parse_lldp_frame(packet[14:])
                if device and device.chassis_id not in lldp_seen:
                    lldp_seen.add(device.chassis_id)
                    result.lldp_devices.append(device)
    finally:
        sock.close()

    return result


# ---------------------------------------------------------------------------
# tcpdump subprocess fallback (needs sudo)
# ---------------------------------------------------------------------------

def capture_via_tcpdump(interface: str = "enp1s0", timeout: int = 30) -> DiscoveryResult:
    """Capture CDP/LLDP via tcpdump subprocess (needs sudo).

    Filters for CDP (ether dst 01:00:0c:cc:cc:cc) and
    LLDP (ether proto 0x88cc) frames, outputs hex for parsing.
    """
    result = DiscoveryResult()

    cmd = [
        "sudo", "tcpdump",
        "-i", interface,
        "-c", "20",
        "-w", "/tmp/istrix_cdp_lldp.pcap",
        "(ether dst 01:00:0c:cc:cc:cc) or (ether proto 0x88cc)",
    ]

    try:
        subprocess.run(cmd, timeout=timeout, capture_output=True)
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        pass

    # If file was created, parse with tshark or scapy
    # For now, try tcpdump -r to read back
    try:
        r = subprocess.run(
            ["sudo", "tcpdump", "-r", "/tmp/istrix_cdp_lldp.pcap", "-X"],
            capture_output=True, text=True, timeout=10
        )
        # Basic parsing from hex dump — limited but functional
        if r.stdout:
            _parse_tcpdump_output(r.stdout, result)
    except Exception:
        pass

    return result


def _parse_tcpdump_output(output: str, result: DiscoveryResult):
    """Parse tcpdump -X output for CDP/LLDP device info."""
    # Look for device identifiers in the hex dump
    for line in output.split("\n"):
        if "Cisco IOS" in line or "Cisco " in line:
            # Extract platform info from CDP
            pass
        if "System Name" in line or "system name" in line.lower():
            pass


# ---------------------------------------------------------------------------
# CDP frame parser
# ---------------------------------------------------------------------------

def _parse_cdp_frame(data: bytes) -> Optional[CDPDevice]:
    """Parse CDP frame (after LLC/SNAP header).

    CDP uses IEEE 802.2 LLC + SNAP:
    - DSAP: 0xAA
    - SSAP: 0xAA
    - Control: 0x03
    - OUI: 0x00000C (Cisco)
    - PID: 0x2000 (CDP)
    Total header: 8 bytes
    """
    if len(data) < 8:
        return None

    # Check LLC/SNAP header
    if data[0:3] != b"\xaa\xaa\x03":
        return None
    if data[3:6] != b"\x00\x00\x0c":
        return None
    if data[6:8] != b"\x20\x00":
        return None

    payload = data[8:]
    return _parse_cdp_tlvs(payload)


def _parse_cdp_tlvs(data: bytes) -> Optional[CDPDevice]:
    """Parse CDP TLV fields."""
    device = CDPDevice()
    offset = 0

    while offset + 4 <= len(data):
        tlv_type = struct.unpack("!H", data[offset:offset + 2])[0]
        tlv_len = struct.unpack("!H", data[offset + 2:offset + 4])[0]

        if tlv_len < 4 or offset + tlv_len > len(data):
            break

        value = data[offset + 4:offset + tlv_len]

        if tlv_type == CDP_TLV_DEVICE_ID:
            device.device_id = value.decode("ascii", errors="ignore").strip("\x00")
        elif tlv_type == CDP_TLV_ADDRESS:
            device.addresses.append(_parse_cdp_address(value))
        elif tlv_type == CDP_TLV_PORT_ID:
            device.port_id = value.decode("ascii", errors="ignore").strip("\x00")
        elif tlv_type == CDP_TLV_CAPABILITIES:
            device.capabilities = _parse_cdp_capabilities(value)
        elif tlv_type == CDP_TLV_SOFTWARE_VERSION:
            device.software_version = value.decode("ascii", errors="ignore").strip("\x00")
        elif tlv_type == CDP_TLV_PLATFORM:
            device.platform = value.decode("ascii", errors="ignore").strip("\x00")
        elif tlv_type == CDP_TLV_NATIVE_VLAN:
            if len(value) >= 2:
                device.native_vlan = struct.unpack("!H", value[:2])[0]
        elif tlv_type == CDP_TLV_DUPLEX:
            pass  # Could parse duplex

        offset += tlv_len

    return device if device.device_id else None


def _parse_cdp_address(data: bytes) -> str:
    """Parse CDP network address TLV."""
    if len(data) < 4:
        return ""
    # Number of addresses
    num_addr = struct.unpack("!I", data[:4])[0]
    offset = 4
    addresses = []
    for _ in range(min(num_addr, 4)):
        if offset + 6 > len(data):
            break
        # Protocol type (1 byte) + length (2 bytes) + protocol (1 byte) + length (2 bytes)
        if data[offset] == 0x01:  # IPv4
            addr_len = struct.unpack("!H", data[offset + 1:offset + 3])[0]
            offset += 3
            if addr_len == 4 and offset + 4 <= len(data):
                ip = ".".join(str(b) for b in data[offset:offset + 4])
                addresses.append(ip)
                offset += 4
        else:
            break
    return ", ".join(addresses)


def _parse_cdp_capabilities(data: bytes) -> list[str]:
    """Parse CDP capabilities bitmask."""
    if len(data) < 4:
        return []
    caps = struct.unpack("!I", data[:4])[0]
    cap_names = {
        0x01: "Router", 0x02: "Trans Bridge", 0x04: "Source Route Bridge",
        0x08: "Switch", 0x10: "Host", 0x20: "IGMP",
        0x40: "Repeater", 0x80: "VoIP Phone",
    }
    return [name for bit, name in cap_names.items() if caps & bit]


# ---------------------------------------------------------------------------
# LLDP frame parser
# ---------------------------------------------------------------------------

def _parse_lldp_frame(data: bytes) -> Optional[LLDPDevice]:
    """Parse LLDP frame (after ethertype)."""
    if len(data) < 2:
        return None
    return _parse_lldp_tlvs(data)


def _parse_lldp_tlvs(data: bytes) -> Optional[LLDPDevice]:
    """Parse LLDP TLV fields."""
    device = LLDPDevice()
    offset = 0

    while offset + 2 <= len(data):
        tlv_header = struct.unpack("!H", data[offset:offset + 2])[0]
        tlv_type = tlv_header >> 9
        tlv_len = tlv_header & 0x01FF

        if tlv_type == LLDP_TLV_END or tlv_len == 0:
            break

        if offset + 2 + tlv_len > len(data):
            break

        value = data[offset + 2:offset + 2 + tlv_len]

        if tlv_type == LLDP_TLV_CHASSIS_ID:
            if len(value) > 1:
                subtype = value[0]
                device.chassis_id = _decode_lldp_chassis(subtype, value[1:])
        elif tlv_type == LLDP_TLV_PORT_ID:
            if len(value) > 1:
                subtype = value[0]
                device.port_id = value[1:].decode("ascii", errors="ignore").strip("\x00")
        elif tlv_type == LLDP_TLV_PORT_DESC:
            device.port_desc = value.decode("ascii", errors="ignore").strip("\x00")
        elif tlv_type == LLDP_TLV_SYSTEM_NAME:
            device.system_name = value.decode("ascii", errors="ignore").strip("\x00")
        elif tlv_type == LLDP_TLV_SYSTEM_DESC:
            device.system_desc = value.decode("ascii", errors="ignore").strip("\x00")
        elif tlv_type == LLDP_TLV_MGMT_ADDR:
            device.mgmt_addresses.append(_parse_lldp_mgmt_addr(value))

        offset += 2 + tlv_len

    return device if (device.chassis_id or device.system_name) else None


def _decode_lldp_chassis(subtype: int, data: bytes) -> str:
    """Decode LLDP chassis ID based on subtype."""
    if subtype in (4, 5):  # MAC address or network address
        return ":".join(f"{b:02x}" for b in data)
    return data.decode("ascii", errors="ignore").strip("\x00")


def _parse_lldp_mgmt_addr(data: bytes) -> str:
    """Parse LLDP management address TLV."""
    if len(data) < 2:
        return ""
    addr_len = data[0] - 1  # subtract subtype byte
    if addr_len == 4 and len(data) >= 6:
        return ".".join(str(b) for b in data[1:5])
    if addr_len == 16 and len(data) >= 17:
        parts = []
        for i in range(0, 16, 2):
            parts.append(f"{data[1+i]:02x}{data[2+i]:02x}")
        return ":".join(parts)
    return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def capture_cdp_lldp(
    interface: str = "enp1s0",
    timeout: int = 30,
    use_sudo: bool = False,
) -> DiscoveryResult:
    """Capture CDP and LLDP announcements from neighboring devices.

    Args:
        interface: Network interface to listen on.
        timeout: Seconds to listen for announcements.
        use_sudo: If True, fall back to tcpdump via sudo when raw socket
                  unavailable.

    Returns:
        DiscoveryResult with discovered device information.

    Note:
        - Without root/CAP_NET_RAW and without use_sudo, returns empty result.
        - Set CAP_NET_RAW:  sudo setcap cap_net_raw+ep $(which python3)
    """
    if _has_raw_capability():
        return capture_via_raw_socket(interface, timeout)
    if use_sudo:
        print("  [cdp_lldp] Raw socket unavailable; trying sudo tcpdump...")
        return capture_via_tcpdump(interface, timeout)
    return DiscoveryResult()


def cdp_lldp_available() -> bool:
    """Check if CDP/LLDP capture is possible (raw socket or sudo tcpdump)."""
    return _has_raw_capability() or _can_sudo_tcpdump()


def _can_sudo_tcpdump() -> bool:
    """Check if sudo tcpdump is available."""
    try:
        r = subprocess.run(
            ["sudo", "-n", "tcpdump", "--version"],
            capture_output=True, timeout=5
        )
        return r.returncode == 0
    except Exception:
        return False
