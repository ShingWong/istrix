"""Risk assessment profile for threat scoring and reporting."""

from pydantic import BaseModel, Field


class RiskProfile(BaseModel):
    """Comprehensive risk assessment criteria for threat scoring.

    These factors adjust the base technical severity score to produce
    a business-context-aware threat rating. All fields have safe defaults.
    """

    # === Scope & Exposure ===
    public_reachable: bool = Field(
        default=False, description="Target is reachable from the public internet"
    )
    scan_origin: str = Field(
        default="private_lan",
        description="Where the scan originated: private_lan, public_wan, extranet_vpn",
    )

    # === Data Classification ===
    financial_data: str = Field(
        default="N",
        description="Financial data present: N, Y-encrypted, Y-unencrypted",
    )
    privacy_data: str = Field(
        default="N",
        description="PII/privacy data present: N, Y-encrypted, Y-unencrypted",
    )
    government_data: str = Field(
        default="N",
        description="Government/regulated data: N, CUI, ITAR, Classified, FOUO",
    )
    business_sensitive: str = Field(
        default="N",
        description="Sensitive business data: N, Y-encrypted, Y-unencrypted",
    )
    healthcare_data: str = Field(
        default="N",
        description="Healthcare/PHI data: N, Y-encrypted, Y-unencrypted",
    )

    # === Authentication & Hardening ===
    mfa_enforced: bool = Field(
        default=False, description="Multi-factor authentication is enforced"
    )
    patch_age: str = Field(
        default="unknown",
        description="Age of last known patches: recent, stale, critical, unknown",
    )
    exploit_public: bool = Field(
        default=False, description="Public exploit/PoC is known for discovered CVEs"
    )
    mgmt_exposed: bool = Field(
        default=False, description="Management interfaces exposed to scan origin"
    )

    # === Compliance ===
    compliance_framework: str = Field(
        default="none",
        description="Applicable compliance: none, pci_dss, hipaa, soc2, iso27001, nist_800-53",
    )

    def scope_label(self) -> str:
        """Human-readable scope description."""
        if self.public_reachable:
            origin = {"private_lan": "Internal scan of public-facing host",
                      "public_wan": "External scan from public internet",
                      "extranet_vpn": "Vendor/VPN extranet scan"}.get(self.scan_origin, "Public")
            return origin
        return {"private_lan": "Internal LAN scan",
                "public_wan": "External scan (private target)",
                "extranet_vpn": "Vendor/VPN extranet scan"}.get(self.scan_origin, "Internal")

    def risk_multiplier(self) -> float:
        """Calculate a risk multiplier based on all criteria.

        Base = 1.0. Increases for higher-risk factors, capped at 2.5x.
        """
        score = 1.0

        # Exposure
        if self.public_reachable:
            score += 0.4
        if self.scan_origin == "public_wan":
            score += 0.2

        # Data sensitivity (unencrypted = higher risk)
        data_fields = [
            self.financial_data, self.privacy_data, self.business_sensitive,
            self.healthcare_data, self.government_data
        ]
        for d in data_fields:
            if d.startswith("Y-unencrypted"):
                score += 0.20
            elif d.startswith("Y-encrypted"):
                score += 0.08
            elif d == "N":
                pass
            else:
                score += 0.12

        # Auth weaknesses
        if not self.mfa_enforced:
            score += 0.10

        # Patch status
        if self.patch_age == "critical":
            score += 0.30
        elif self.patch_age == "stale":
            score += 0.15

        # Exploit availability
        if self.exploit_public:
            score += 0.25

        # Exposed management
        if self.mgmt_exposed:
            score += 0.15

        return min(score, 2.5)

    def risk_summary_lines(self) -> list[str]:
        """Generate lines for the risk profile section of a report."""
        lines = []

        scope_color = "red" if self.public_reachable else "yellow" if self.scan_origin != "private_lan" else "green"
        lines.append((
            f"Public Reachable: [bold {scope_color}]{'YES' if self.public_reachable else 'No'}[/bold {scope_color}]"
        ))
        lines.append((f"Scan Origin: [bold]{self.scan_origin.replace('_', ' ').title()}[/bold]"))

        data_items = {
            "Financial Data": self.financial_data,
            "Privacy/PII Data": self.privacy_data,
            "Healthcare/PHI Data": self.healthcare_data,
            "Government Data": self.government_data,
            "Business Sensitive Data": self.business_sensitive,
        }
        for label, value in data_items.items():
            if value == "N":
                continue
            color = "red" if "unencrypted" in value else "yellow"
            lines.append((f"{label}: [bold {color}]{value}[/bold {color}]"))

        if self.compliance_framework != "none":
            lines.append((f"Compliance: [bold cyan]{self.compliance_framework.upper()}[/bold cyan]"))

        lines.append((f"MFA Enforced: {'[green]Yes[/green]' if self.mfa_enforced else '[red]No[/red]'}"))
        lines.append((f"Patch Status: [bold]{self.patch_age.title()}[/bold]"))
        if self.exploit_public:
            lines.append(("[red]Public Exploit Available[/red]"))
        if self.mgmt_exposed:
            lines.append(("[red]Management Interfaces Exposed[/red]"))

        return lines
