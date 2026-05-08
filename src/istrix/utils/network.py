"""Network utility functions for target validation and CIDR expansion."""

import ipaddress


def validate_target(target: str) -> bool:
    """Return True if target is a valid IP, hostname, or CIDR."""
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    if target and not target.startswith("-") and not target.startswith("/"):
        return True
    return False


def expand_targets(targets: list[str]) -> list[str]:
    """Expand CIDR ranges to individual host IPs. Non-CIDR values pass through."""
    result: list[str] = []
    for t in targets:
        try:
            net = ipaddress.ip_network(t, strict=False)
            if net.prefixlen < 31:
                result.extend(str(ip) for ip in net.hosts())
            else:
                result.append(t)
        except ValueError:
            result.append(t)
    return result


def is_private_ip(ip: str) -> bool:
    """Return True if the IP is in a private/RFC1918 range."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except ValueError:
        return False
