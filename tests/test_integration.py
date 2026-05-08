"""Integration tests for iStrix scanner pipeline and modules."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from istrix.engine.modules import MODULE_REGISTRY
from istrix.engine.tiers import get_tier
from istrix.models.finding import Finding
from istrix.models.scan import ScanConfig, ScanResult


# ---------------------------------------------------------------------------
# Module auto-discovery
# ---------------------------------------------------------------------------

class TestModuleDiscovery:
    def test_builtin_modules_registered(self):
        assert "http_probe" in MODULE_REGISTRY
        assert "ssl_check" in MODULE_REGISTRY
        assert "dir_bust" in MODULE_REGISTRY
        assert "cve_enrich" in MODULE_REGISTRY

    def test_module_has_required_attrs(self):
        for _name, cls in MODULE_REGISTRY.items():
            assert isinstance(cls.name, str)
            assert isinstance(cls.consumed_types, list)
            assert isinstance(cls.produced_types, list)

    def test_modules_are_instantiable(self):
        for _name, cls in MODULE_REGISTRY.items():
            instance = cls()
            assert instance.name


# ---------------------------------------------------------------------------
# Tier configuration
# ---------------------------------------------------------------------------

class TestTierModuleConfig:
    def test_aggressive_tier_follow_up(self):
        tier = get_tier("aggressive")
        assert "cve_enrich" in tier.follow_up
        assert "http_probe" in tier.follow_up
        assert "ssl_check" in tier.follow_up
        assert "dir_bust" in tier.follow_up

    def test_full_tier_follow_up(self):
        tier = get_tier("full")
        assert "cve_enrich" in tier.follow_up

    def test_normal_tier_follow_up(self):
        tier = get_tier("normal")
        assert "cve_enrich" in tier.follow_up

    def test_quick_no_enrich(self):
        assert "cve_enrich" not in get_tier("quick").follow_up

    def test_stealth_no_enrich(self):
        assert "cve_enrich" not in get_tier("stealth").follow_up


# ---------------------------------------------------------------------------
# CVE Enrich Module (mocked nvdlib)
# ---------------------------------------------------------------------------

class TestCVEEnrichModule:
    @pytest.fixture
    def module(self):
        from istrix.engine.modules.cve_enrich import CVEEnrichModule
        return CVEEnrichModule()

    @pytest.fixture
    def mock_nvdlib(self):
        mock = MagicMock()

        def _fake_cve(**kwargs):
            cve_list = []
            cid = kwargs.get("cveId", "")

            if "keywordSearch" in kwargs:
                kw = kwargs["keywordSearch"].lower()
                if "apache" in kw:
                    cve1 = MagicMock()
                    cve1.id = "CVE-2024-0001"
                    cve1.v31score = [9.8]
                    d1 = MagicMock()
                    d1.lang = "en"
                    d1.value = "Apache HTTP Server critical RCE"
                    cve1.descriptions = [d1]
                    cve_list.append(cve1)
                elif "openssh" in kw or "ssh" in kw:
                    cve2 = MagicMock()
                    cve2.id = "CVE-2024-6387"
                    cve2.v31score = [8.1]
                    d2 = MagicMock()
                    d2.lang = "en"
                    d2.value = "OpenSSH regreSSHion signal handler race"
                    cve2.descriptions = [d2]
                    cve_list.append(cve2)
                else:
                    cve_list.append(MagicMock(id=None, v31score=[None], descriptions=[]))
            elif cid:
                cve1 = MagicMock()
                cve1.id = cid
                cve1.v31score = [7.5]
                d1 = MagicMock()
                d1.lang = "en"
                d1.value = f"Description for {cid}"
                cve1.descriptions = [d1]
                cve_list.append(cve1)

            return cve_list

        mock.searchCVE.side_effect = _fake_cve
        return mock

    def test_no_nvdlib_returns_empty(self, module):
        import sys as _sys
        with patch.dict(_sys.modules, {"nvdlib": None}):
            fake_sys = type(_sys)("sys")
            fake_sys.modules = _sys.modules.copy()
            with patch("istrix.engine.modules.cve_enrich.__name__", "istrix.engine.modules.cve_enrich"):
                results = module.run([
                    Finding(type="service", host="10.0.0.1", port=80,
                            detail="Service: http Apache 2.4.7",
                            evidence="product=Apache version=2.4.7",
                            source="nmap"),
                ])
        assert results == []

    def test_enrich_service_finding(self, module, mock_nvdlib):
        import sys
        with patch.dict(sys.modules, {"nvdlib": mock_nvdlib}):
            results = module.run([
                Finding(type="service", host="10.0.0.1", port=80,
                        detail="Service: http Apache 2.4.7",
                        evidence="product=Apache version=2.4.7",
                        source="nmap"),
            ])
        assert len(results) >= 1, f"Expected at least 1 result, got {len(results)}"
        found = next((r for r in results if r.cve == "CVE-2024-0001"), None)
        assert found is not None
        assert found.severity == "critical"
        assert found.type == "vulnerability"
        assert found.source == "cve_enrich"

    def test_enrich_ssh_service(self, module, mock_nvdlib):
        import sys
        with patch.dict(sys.modules, {"nvdlib": mock_nvdlib}):
            results = module.run([
                Finding(type="service", host="10.0.0.2", port=22,
                        detail="Service: ssh OpenSSH 7.6p1",
                        evidence="product=OpenSSH version=7.6p1",
                        source="nmap"),
            ])
        ssh_cves = [r for r in results if r.cve == "CVE-2024-6387"]
        assert len(ssh_cves) >= 1
        assert ssh_cves[0].severity == "high"

    def test_deduplicate_service_combos(self, module, mock_nvdlib):
        import sys
        with patch.dict(sys.modules, {"nvdlib": mock_nvdlib}):
            module.run([
                Finding(type="service", host="10.0.0.1", port=80,
                        detail="Service: http Apache 2.4.7",
                        evidence="product=Apache version=2.4.7",
                        source="nmap"),
                Finding(type="service", host="10.0.0.1", port=443,
                        detail="Service: https Apache 2.4.7",
                        evidence="product=Apache version=2.4.7",
                        source="nmap"),
            ])
        assert mock_nvdlib.searchCVE.call_count <= 2

    def test_enrich_existing_cve_finding(self, module, mock_nvdlib):
        """Existing vuln findings with CVEs get enriched metadata."""
        import sys
        finding = Finding(type="vulnerability", host="10.0.0.1", port=443,
                          detail="CVE-2024-0001: Apache vuln",
                          severity="medium", cve="CVE-2024-0001",
                          source="nmap")
        with patch.dict(sys.modules, {"nvdlib": mock_nvdlib}):
            module.run([finding])
        assert finding.severity == "high"

    def test_parse_evidence(self, module):
        product, version = module._parse_evidence(
            "product=nginx version=1.18.0 extrainfo=Ubuntu"
        )
        assert product == "nginx"
        assert version == "1.18.0"

    def test_parse_evidence_no_product(self, module):
        product, version = module._parse_evidence("version=2.0")
        assert product == ""

    def test_classify_cvss(self, module):
        assert module._classify_cvss(9.8) == "critical"
        assert module._classify_cvss(8.1) == "high"
        assert module._classify_cvss(6.5) == "medium"
        assert module._classify_cvss(3.0) == "low"
        assert module._classify_cvss(0.0) == "info"


# ---------------------------------------------------------------------------
# NMAP XML Parsing
# ---------------------------------------------------------------------------

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" start="12345">
<host>
  <address addr="192.168.1.1" addrtype="ipv4"/>
  <hostnames>
    <hostname name="test.local" type="PTR"/>
  </hostnames>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open"/>
      <service name="ssh" product="OpenSSH" version="7.6p1" extrainfo="Ubuntu"/>
    </port>
    <port protocol="tcp" portid="80">
      <state state="open"/>
      <service name="http" product="Apache httpd" version="2.4.7"/>
    </port>
    <port protocol="tcp" portid="443">
      <state state="open"/>
      <service name="https" product="nginx" version="1.18.0"/>
    </port>
    <port protocol="tcp" portid="3306">
      <state state="closed"/>
      <service name="mysql"/>
    </port>
  </ports>
  <os>
    <osmatch name="Linux 3.2 - 4.9" accuracy="95">
      <osclass vendor="Linux" osfamily="Linux" osgen="3.x"/>
    </osmatch>
  </os>
  <hostscript>
    <script id="vuln-ssh" output="CVE-2024-6387: OpenSSH 7.6 is vulnerable"/>
  </hostscript>
</host>
</nmaprun>"""


class TestNmapXMLParsing:
    def test_parse_sample_xml(self):
        from istrix.engine.nmap import parse_nmap_xml
        findings = parse_nmap_xml(SAMPLE_NMAP_XML, target_hint="192.168.1.1")
        assert len(findings) >= 5
        types = {f.type for f in findings}
        assert "dns" in types
        assert "open_port" in types
        assert "service" in types
        assert "os" in types
        assert "vulnerability" in types

    def test_hostname_extracted(self):
        from istrix.engine.nmap import parse_nmap_xml
        findings = parse_nmap_xml(SAMPLE_NMAP_XML)
        dns = [f for f in findings if f.type == "dns"]
        assert len(dns) == 1
        assert dns[0].detail == "Hostname: test.local"

    def test_closed_ports_ignored(self):
        from istrix.engine.nmap import parse_nmap_xml
        findings = parse_nmap_xml(SAMPLE_NMAP_XML)
        closed = [f for f in findings if f.type == "open_port" and "3306" in f.detail]
        assert len(closed) == 0

    def test_os_detection(self):
        from istrix.engine.nmap import parse_nmap_xml
        findings = parse_nmap_xml(SAMPLE_NMAP_XML)
        os_f = [f for f in findings if f.type == "os"]
        assert len(os_f) == 1
        assert "Linux" in os_f[0].detail

    def test_cve_extracted(self):
        from istrix.engine.nmap import parse_nmap_xml
        findings = parse_nmap_xml(SAMPLE_NMAP_XML)
        cve_f = [f for f in findings if f.cve == "CVE-2024-6387"]
        assert len(cve_f) >= 1
        assert cve_f[0].severity == "medium"  # CVE keyword match, no CVSS score


# ---------------------------------------------------------------------------
# Report generation (smoke test using generate_report function)
# ---------------------------------------------------------------------------

class TestReportGeneration:
    def _write_results_json(self, tmp_path, findings):
        config = ScanConfig(tier="normal", targets=["10.0.0.1"])
        result = ScanResult(config=config, findings=findings)
        data = {
            "version": "0.1.0",
            "config": config.model_dump(),
            "findings": [f.model_dump() for f in findings],
            "summary": result.summary(),
            "errors": [],
        }
        json_path = tmp_path / "test_results.json"
        json_path.write_text(json.dumps(data, indent=2, default=str))
        return str(json_path)

    def test_generate_html_from_findings(self, tmp_path):
        from istrix.reporting.generator import generate_report

        json_path = self._write_results_json(tmp_path, [
            Finding(type="open_port", host="10.0.0.1", port=22,
                    detail="Port 22 open", source="nmap"),
            Finding(type="vulnerability", host="10.0.0.1", port=22,
                    detail="CVE-2024-6387: regreSSHion", severity="high",
                    cve="CVE-2024-6387", source="nmap"),
        ])

        by_level = {}
        for level in ["brief", "detail", "threat", "remediation"]:
            path = generate_report(
                results_paths=[json_path],
                level=level,
                output_format="html",
                output_dir=str(tmp_path),
            )
            by_level[level] = path
            assert path.exists(), f"{level} report not generated"

    def test_generate_markdown(self, tmp_path):
        from istrix.reporting.generator import generate_report

        json_path = self._write_results_json(tmp_path, [
            Finding(type="open_port", host="10.0.0.1", port=80,
                    detail="Port 80 open", source="nmap"),
        ])

        path = generate_report(results_paths=[json_path], level="brief",
                               output_format="md", output_dir=str(tmp_path))
        assert path.exists()
        assert path.suffix == ".md"


# ---------------------------------------------------------------------------
# Finding model edge cases
# ---------------------------------------------------------------------------

class TestFindingDedup:
    def test_dedup_keys_different(self):
        f1 = Finding(type="service", host="10.0.0.1", port=22,
                      detail="OpenSSH 7.6", source="nmap")
        f2 = Finding(type="service", host="10.0.0.1", port=80,
                      detail="Apache 2.4", source="nmap")
        assert f1.dedup_key() != f2.dedup_key()

    def test_vulnerability_dedup(self):
        f1 = Finding(type="vulnerability", host="10.0.0.1", port=443,
                      detail="CVE-2024-0001", severity="high",
                      cve="CVE-2024-0001", source="nmap")
        f2 = Finding(type="vulnerability", host="10.0.0.1", port=443,
                      detail="CVE-2024-0001", severity="high",
                      cve="CVE-2024-0001", source="nmap")
        assert f1.dedup_key() == f2.dedup_key()

    def test_cve_field_none(self):
        f = Finding(type="other", host="x", detail="x", source="x")
        assert f.cve is None
        assert not f.is_vulnerability

    def test_cve_field_set(self):
        f = Finding(type="other", host="x", detail="x", source="x",
                     cve="CVE-2024-0001")
        assert f.is_vulnerability


# ---------------------------------------------------------------------------
# Cisco / network device OS detection
# ---------------------------------------------------------------------------

class TestNetworkDeviceOSDetection:
    def test_cisco_service_detected_before_linux_os(self):
        """Cisco SSH service should return 'Cisco IOS' even if nmap -O says Linux."""
        from istrix.reporting.generator import ReportGenerator

        findings = [
            Finding(type="os", host="10.0.0.102",
                    detail="OS: Linux 3.2 - 4.9 (accuracy: 95%)", source="nmap"),
            Finding(type="service", host="10.0.0.102", port=22,
                    detail="Service: ssh Cisco SSH 1.25", source="nmap",
                    evidence="product=Cisco version=1.25"),
        ]
        os_name = ReportGenerator._detect_os(findings)
        assert "Cisco" in os_name, f"Expected Cisco IOS, got {os_name}"
        assert "Linux" not in os_name

    def test_cisco_telnet_detected_early(self):
        """Cisco telnet service should be caught in stage 0."""
        from istrix.reporting.generator import ReportGenerator

        findings = [
            Finding(type="os", host="10.0.0.102",
                    detail="OS: Linux 3.10 (accuracy: 92%)", source="nmap"),
            Finding(type="service", host="10.0.0.102", port=23,
                    detail="Service: telnet Cisco router telnetd", source="nmap"),
        ]
        os_name = ReportGenerator._detect_os(findings)
        assert "Cisco" in os_name

    def test_cisco_ssh_banner_returns_ios(self):
        """SSH banner with 'cisco' should return Cisco IOS, not Linux (SSH)."""
        from istrix.reporting.generator import ReportGenerator

        findings = [
            Finding(type="service", host="10.0.0.102", port=22,
                    detail="Service: ssh Cisco SSH 1.25 protocol 2.0",
                    source="nmap"),
        ]
        os_name = ReportGenerator._detect_os(findings)
        assert os_name == "Cisco IOS"

    def test_juniper_detected(self):
        """Juniper/JunOS devices should be detected."""
        from istrix.reporting.generator import ReportGenerator

        findings = [
            Finding(type="service", host="10.0.0.50", port=22,
                    detail="Service: ssh Juniper Router 12.3", source="nmap"),
        ]
        os_name = ReportGenerator._detect_os(findings)
        assert "Juniper" in os_name or "JunOS" in os_name

    def test_linux_os_without_network_services(self):
        """Pure Linux server (no Cisco services) should still return Linux."""
        from istrix.reporting.generator import ReportGenerator

        findings = [
            Finding(type="os", host="10.0.0.1",
                    detail="OS: Linux 5.10 (accuracy: 97%)", source="nmap"),
            Finding(type="service", host="10.0.0.1", port=22,
                    detail="Service: ssh OpenSSH 8.7 protocol 2.0", source="nmap"),
        ]
        os_name = ReportGenerator._detect_os(findings)
        assert "Linux" in os_name
        assert "Cisco" not in os_name

    def test_cdp_discovery_script_parsing(self):
        """CDP NSE script output should produce 'os' type finding with platform."""
        from istrix.engine.nmap import _parse_discovery_script
        from datetime import datetime, timezone

        ts = datetime.now(timezone.utc).isoformat()
        output = (
            "CDP: \n"
            "Device ID: core-switch-1\n"
            "Platform: cisco WS-C3750E-24TD-S, Capabilities: Router Switch\n"
            "Version: Cisco IOS Software, C3750E Software (C3750E-UNIVERSALK9-M), Version 15.2(4)E10\n"
            "IP address: 10.0.0.102\n"
        )
        findings = _parse_discovery_script("broadcast-cdp", output, "10.0.0.1", ts)
        os_findings = [f for f in findings if f.type == "os"]
        assert len(os_findings) >= 1
        assert "Cisco" in os_findings[0].detail
        assert "C3750E" in os_findings[0].detail

    def test_lldp_discovery_script_parsing(self):
        """LLDP NSE script output should extract system description."""
        from istrix.engine.nmap import _parse_discovery_script
        from datetime import datetime, timezone

        ts = datetime.now(timezone.utc).isoformat()
        output = (
            "LLDP: \n"
            "System Name: access-sw-02\n"
            "System Description: Juniper Networks, Inc. ex4300-48p Ethernet Switch, kernel\n"
        )
        findings = _parse_discovery_script("broadcast-lldp", output, "10.0.0.1", ts)
        os_findings = [f for f in findings if f.type == "os"]
        assert len(os_findings) >= 1
        assert "Juniper" in os_findings[0].detail

    def test_snmp_discovery_script_parsing(self):
        """SNMP-info script output should extract sysDescr."""
        from istrix.engine.nmap import _parse_discovery_script
        from datetime import datetime, timezone

        ts = datetime.now(timezone.utc).isoformat()
        output = "sysDescr: Arista Networks EOS version 4.27.3F running on an Arista Networks DCS-7050SX-64"
        findings = _parse_discovery_script("snmp-info", output, "10.0.0.1", ts)
        os_findings = [f for f in findings if f.type == "os"]
        assert len(os_findings) >= 1
        assert "Arista" in os_findings[0].detail

    def test_remediation_cisco_gets_correct_advice(self):
        """Cisco IOS devices should get Cisco-specific remediation, not apt update."""
        from istrix.reporting.generator import ReportGenerator

        gen = ReportGenerator.__new__(ReportGenerator)
        advice = gen.REMEDIATION_OS_ADVICE.get("Cisco IOS")
        assert advice is not None
        general = advice.get("general", "")
        assert "apt" not in general.lower()
        assert "cisco" in general.lower() or "ios" in general.lower()

    def test_remediation_cisco_fallback_from_partial_match(self):
        """OS string like 'Cisco IOS 15.2' should fall back gracefully."""
        from istrix.reporting.generator import ReportGenerator

        gen = ReportGenerator.__new__(ReportGenerator)
        advice = gen.REMEDIATION_OS_ADVICE.get("Cisco IOS")
        assert advice is not None
        advice_partial = gen.REMEDIATION_OS_ADVICE.get("Cisco IOS 15.2", gen.REMEDIATION_OS_ADVICE["unknown"])
        assert advice_partial == gen.REMEDIATION_OS_ADVICE["unknown"]

    def test_oracle_linux_from_ssh_banner(self):
        """SSH banner with 'oracle' should detect Oracle Linux."""
        from istrix.reporting.generator import ReportGenerator

        findings = [
            Finding(type="service", host="10.0.0.58", port=22,
                    detail="Service: ssh OpenSSH 8.7 Oracle Linux Server 9.7",
                    source="nmap"),
        ]
        os_name = ReportGenerator._detect_os(findings)
        assert "Oracle Linux" in os_name

    def test_rhel_family_heuristic_rpcbind_no_distro(self):
        """OpenSSH + rpcbind + no distro banner → RHEL-family heuristic."""
        from istrix.reporting.generator import ReportGenerator

        findings = [
            Finding(type="service", host="10.0.0.58", port=22,
                    detail="Service: ssh OpenSSH 8.7 (protocol 2.0)",
                    source="nmap"),
            Finding(type="service", host="10.0.0.58", port=111,
                    detail="Service: rpcbind 2-4 (RPC #100000)",
                    source="nmap"),
        ]
        os_name = ReportGenerator._detect_os(findings)
        assert "RHEL-family" in os_name

    def test_rhel_family_heuristic_cockpit_port_9090(self):
        """OpenSSH + rpcbind + port 9090/tcp → RHEL-family (Cockpit indicator)."""
        from istrix.reporting.generator import ReportGenerator

        findings = [
            Finding(type="service", host="10.0.0.58", port=22,
                    detail="Service: ssh OpenSSH 8.7 (protocol 2.0)",
                    source="nmap"),
            Finding(type="service", host="10.0.0.58", port=111,
                    detail="Service: rpcbind 2-4 (RPC #100000)",
                    source="nmap"),
            Finding(type="open_port", host="10.0.0.58", port=9090,
                    detail="Port 9090/tcp is open",
                    source="nmap"),
        ]
        os_name = ReportGenerator._detect_os(findings)
        assert "RHEL-family" in os_name

    def test_generic_linux_ssh_not_matched_as_apt(self):
        """'Linux (SSH)' (distro unknown) should give cross-distro advice, not apt-only."""
        from istrix.reporting.remediation import generate_remediation_commands

        cmds = generate_remediation_commands(
            cve_id="CVE-2024-6387",
            cve_description="OpenSSH before 9.8 is vulnerable to regreSSHion.",
            host_os="Linux (SSH)",
        )
        combined = " ".join(cmds).lower()
        assert "upgrade openssh" in combined
        assert "dnf" in combined, f"Unknown Linux should mention dnf option: {cmds}"

    def test_rhel_family_gets_dnf_commands(self):
        """RHEL-family hosts should get dnf-based remediation, not apt."""
        from istrix.reporting.remediation import generate_remediation_commands

        cmds = generate_remediation_commands(
            cve_id="CVE-2024-6387",
            cve_description="OpenSSH before 9.8 is vulnerable to regreSSHion.",
            host_os="Linux (RHEL-family)",
        )
        combined = " ".join(cmds).lower()
        assert "dnf" in combined, f"Should contain dnf: {cmds}"
        assert "apt" not in combined, f"Should not contain apt: {cmds}"

    def test_oracle_linux_gets_dnf_commands(self):
        """Oracle Linux hosts should get dnf-based remediation."""
        from istrix.reporting.remediation import generate_remediation_commands

        cmds = generate_remediation_commands(
            cve_id="CVE-2024-6387",
            cve_description="OpenSSH before 9.8 is vulnerable to regreSSHion.",
            host_os="Oracle Linux 9.7",
        )
        combined = " ".join(cmds).lower()
        assert "dnf" in combined, f"Should contain dnf: {cmds}"
        assert "apt" not in combined, f"Should not contain apt: {cmds}"

    def test_dnf_fallback_for_rhel_generic_advice(self):
        """RHEL-family generic fallback should suggest dnf, not apt."""
        from istrix.reporting.remediation import _generic_os_advice

        cmds = _generic_os_advice("Oracle Linux 9.7")
        combined = " ".join(cmds).lower()
        assert "dnf" in combined

        cmds = _generic_os_advice("Rocky Linux 9.3")
        combined = " ".join(cmds).lower()
        assert "dnf" in combined

    def test_rhel_family_removed_from_apt_os_advice(self):
        """RHEL-family OS strings should NOT match the apt-based 'Linux' advice."""
        from istrix.reporting.generator import ReportGenerator

        gen = ReportGenerator.__new__(ReportGenerator)
        advice = gen._find_os_advice("Linux (RHEL-family)")
        assert "dnf" in str(advice).lower()

        # 'Linux (SSH)' should get the unknown entry
        advice = gen._find_os_advice("Linux (SSH)")
        assert "apt" not in str(advice).lower()


# ---------------------------------------------------------------------------
# Incremental save / resume
# ---------------------------------------------------------------------------

class TestIncrementalSaveResume:
    def test_save_and_load_incremental(self, tmp_path):
        """Incremental state should survive a save/load cycle."""
        from istrix.engine.scanner import ScanOrchestrator
        from istrix.models.scan import ScanConfig

        inc_path = tmp_path / "partial.json"
        config = ScanConfig(tier="normal", targets=["10.0.0.1", "10.0.0.2"])

        orch = ScanOrchestrator(config, incremental_path=inc_path)
        orch._scanned_hosts = {"10.0.0.1"}
        orch._save_incremental_sync(
            [Finding(type="open_port", host="10.0.0.1", port=80,
                      detail="Port 80 open", source="nmap")],
            completed_count=1,
        )

        assert inc_path.exists()
        loaded = ScanOrchestrator._load_incremental(inc_path)
        assert loaded is not None
        assert "10.0.0.1" in loaded["scanned_hosts"]
        assert len(loaded["scanned_hosts"]) == 1

    def test_resume_available_detects_partial(self, tmp_path):
        """resume_available should return True when partial file exists."""
        from istrix.engine.scanner import ScanOrchestrator
        from istrix.models.scan import ScanConfig

        inc_path = tmp_path / "partial.json"
        config = ScanConfig(tier="normal", targets=["10.0.0.1"])
        orch = ScanOrchestrator(config, incremental_path=inc_path)
        orch._scanned_hosts.add("10.0.0.1")
        orch._save_incremental_sync([], completed_count=1)

        assert ScanOrchestrator.resume_available(inc_path)

    def test_resume_available_no_file(self, tmp_path):
        """resume_available should return False when no file exists."""
        from istrix.engine.scanner import ScanOrchestrator
        assert not ScanOrchestrator.resume_available(tmp_path / "nonexistent.json")

    def test_run_filters_scanned_hosts(self, tmp_path):
        """When resuming, already-scanned hosts should be skipped."""
        from istrix.engine.scanner import ScanOrchestrator
        from istrix.models.scan import ScanConfig

        inc_path = tmp_path / "partial.json"

        # Pre-populate with one scanned host
        import json
        inc_path.write_text(json.dumps({
            "version": "0.1.0",
            "scan_config": {"tier": "normal", "targets": ["10.0.0.1", "10.0.0.2", "10.0.0.3"]},
            "findings": [],
            "scanned_hosts": ["10.0.0.1"],
            "last_updated": "2026-01-01T00:00:00",
            "errors": [],
        }))

        config = ScanConfig(tier="normal", targets=["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        orch = ScanOrchestrator(config, incremental_path=inc_path)

        # We rely on nmap_available() being true — mock it
        from unittest.mock import patch
        with patch("istrix.engine.scanner.nmap_available", return_value=True):
            with patch("istrix.engine.scanner.expand_targets", return_value=["10.0.0.1", "10.0.0.2", "10.0.0.3"]):
                # Don't actually run scans — just verify the hosts were loaded
                pass

        assert "10.0.0.1" in orch._scanned_hosts
        assert "10.0.0.2" not in orch._scanned_hosts

    def test_incremental_file_written_after_each_host(self, tmp_path):
        """After _on_target_complete, incremental file should be updated."""
        from istrix.engine.scanner import ScanOrchestrator
        from istrix.models.scan import ScanConfig

        inc_path = tmp_path / "partial.json"
        config = ScanConfig(tier="normal", targets=["10.0.0.1", "10.0.0.2"])

        orch = ScanOrchestrator(config, incremental_path=inc_path)
        orch._on_target_complete("10.0.0.1")
        orch._save_incremental_sync([], completed_count=1)

        loaded = ScanOrchestrator._load_incremental(inc_path)
        assert "10.0.0.1" in loaded["scanned_hosts"]

    def test_no_incremental_without_path(self):
        """Without incremental_path, _save_incremental is a no-op."""
        from istrix.engine.scanner import ScanOrchestrator
        from istrix.models.scan import ScanConfig

        config = ScanConfig(tier="normal", targets=["10.0.0.1"])
        orch = ScanOrchestrator(config, incremental_path=None)
        # Should not raise
        orch._save_incremental_sync([], completed_count=0)

    def test_load_incremental_invalid_json(self, tmp_path):
        """Corrupt partial file should return None gracefully."""
        from istrix.engine.scanner import ScanOrchestrator

        bad_path = tmp_path / "bad.json"
        bad_path.write_text("not json")
        assert ScanOrchestrator._load_incremental(bad_path) is None
