"""Target model for IP addresses, hostnames, and CIDR ranges."""

import ipaddress

from pydantic import BaseModel, Field, model_validator


class Target(BaseModel):
    """A scan target: single IP, hostname, or CIDR network."""

    value: str = Field(..., description="IP address, hostname, or CIDR notation")
    type: str = Field(default="", description="ip, cidr, or hostname")

    @model_validator(mode="after")
    def resolve_type(self) -> "Target":
        value = self.value
        try:
            ipaddress.ip_network(value, strict=False)
            if "/" in value:
                self.type = "cidr"
            else:
                self.type = "ip"
        except ValueError:
            self.type = "hostname"
        return self

    def expand(self) -> list[str]:
        """If this is a CIDR, return all host IPs. Otherwise return [value]."""
        if self.type == "cidr":
            net = ipaddress.ip_network(self.value, strict=False)
            return [str(ip) for ip in net.hosts()]
        return [self.value]


def expand_targets(targets: list[str]) -> list[str]:
    """Expand a list of target strings (IPs, hosts, CIDRs) to individual targets."""
    result: list[str] = []
    for t in targets:
        try:
            result.extend(Target(value=t).expand())
        except Exception:
            result.append(t)
    return result
