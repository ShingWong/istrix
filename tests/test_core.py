"""Core unit tests for iStrix models and utilities."""

from istrix.models.finding import Finding
from istrix.models.scan import ScanConfig, ScanResult
from istrix.models.target import Target, expand_targets
from istrix.engine.tiers import load_tiers, get_tier, list_tiers
from istrix.utils.network import validate_target, is_private_ip


class TestFinding:
    def test_create_finding(self):
        f = Finding(type="open_port", host="10.0.0.1", port=80, protocol="tcp",
                     detail="Port 80 open", source="nmap")
        assert f.type == "open_port"
        assert f.host == "10.0.0.1"
        assert f.port == 80
        assert f.severity == "info"
        assert not f.is_vulnerability

    def test_vulnerability_finding(self):
        f = Finding(type="vulnerability", host="10.0.0.1", port=443,
                     detail="Outdated TLS", severity="high",
                     cve="CVE-2024-1234", source="nmap")
        assert f.is_vulnerability
        assert f.severity_rank() == 4
        assert f.cve == "CVE-2024-1234"

    def test_dedup_key(self):
        f1 = Finding(type="open_port", host="10.0.0.1", port=80,
                      detail="Port 80 open", source="nmap")
        f2 = Finding(type="open_port", host="10.0.0.1", port=80,
                      detail="Port 80 open", source="nmap")
        assert f1.dedup_key() == f2.dedup_key()

    def test_severity_ranks(self):
        assert Finding(type="other", host="x", detail="x", source="x",
                       severity="critical").severity_rank() == 5
        assert Finding(type="other", host="x", detail="x", source="x",
                       severity="high").severity_rank() == 4
        assert Finding(type="other", host="x", detail="x", source="x",
                       severity="medium").severity_rank() == 3
        assert Finding(type="other", host="x", detail="x", source="x",
                       severity="low").severity_rank() == 2
        assert Finding(type="other", host="x", detail="x", source="x",
                       severity="info").severity_rank() == 1


class TestTarget:
    def test_cidr(self):
        t = Target(value="192.168.1.0/30")
        assert t.type == "cidr"
        assert t.expand() == ["192.168.1.1", "192.168.1.2"]

    def test_single_ip(self):
        t = Target(value="10.0.0.1")
        assert t.type == "ip"
        assert t.expand() == ["10.0.0.1"]

    def test_hostname(self):
        t = Target(value="example.com")
        assert t.type == "hostname"
        assert t.expand() == ["example.com"]

    def test_expand_targets(self):
        result = expand_targets(["192.168.0.0/30", "10.0.0.1", "test.local"])
        assert len(result) == 4


class TestScanResult:
    def test_empty_summary(self):
        config = ScanConfig(tier="normal", targets=["127.0.0.1"])
        result = ScanResult(config=config)
        summary = result.summary()
        assert summary["total_findings"] == 0
        assert summary["hosts_scanned"] == 0

    def test_summary_with_findings(self):
        config = ScanConfig(tier="normal", targets=["127.0.0.1"])
        result = ScanResult(config=config, findings=[
            Finding(type="open_port", host="10.0.0.1", port=80, detail="http", source="nmap"),
            Finding(type="vulnerability", host="10.0.0.1", port=80, severity="high",
                    detail="XSS", source="nmap"),
        ])
        summary = result.summary()
        assert summary["total_findings"] == 2
        assert summary["hosts_scanned"] == 1
        assert summary["ports_open"] == 1
        assert summary["by_severity"] == {"info": 1, "high": 1}


class TestTiers:
    def test_load_tiers(self):
        tiers = load_tiers()
        assert "quick" in tiers
        assert "normal" in tiers
        assert "full" in tiers
        assert "aggressive" in tiers
        assert "stealth" in tiers

    def test_get_tier(self):
        tier = get_tier("normal")
        assert tier.label == "Standard Scan"
        assert "http_probe" in tier.follow_up

    def test_get_unknown_tier(self):
        try:
            get_tier("nonexistent")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_list_tiers(self):
        tiers = list_tiers()
        names = [t.name for t in tiers]
        assert "quick" in names
        assert "aggressive" in names


class TestNetwork:
    def test_validate_target(self):
        assert validate_target("192.168.1.1")
        assert validate_target("example.com")
        assert validate_target("10.0.0.0/24")
        assert not validate_target("")

    def test_private_ip(self):
        assert is_private_ip("192.168.1.1")
        assert is_private_ip("10.0.0.1")
        assert is_private_ip("172.16.0.1")
        assert not is_private_ip("8.8.8.8")
