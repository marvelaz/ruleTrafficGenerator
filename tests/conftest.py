"""
Shared pytest fixtures for phase1 and phase2 test suites.
"""

import json
import sys
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def minimal_config():
    """Minimal config dict covering all keys read by phase1 and phase2."""
    return {
        "fortigate": {
            "host": "172.16.0.4",
            "port": 443,
            "api_token": "test-token",
            "vdom": "root",
            "verify_ssl": False,
            "timeout": 10,
        },
        "network": {
            "inside": {
                "primary_ip": "192.168.1.100",
                "linux_interface": "eth0",
                "aliases": ["192.168.1.101", "192.168.1.102"],
            },
            "outside": {
                "primary_ip": "10.10.0.100",
                "linux_interface": "eth0",
                "aliases": ["10.10.0.101", "10.10.0.102"],
            },
        },
        "traffic": {
            "match_ratio": 0.68,
            "icmp_count": 3,
            "inter_packet_delay": 0,
            "inter_session_delay": 0,
        },
        "lab": {
            "tag": "LAB-TEST-2025",
            "output_dir": "",           # overridden per-test via tmp_path
            "rules_backup_file": "generated_rules.json",
            "observation_window_hours": 24,
        },
        "rules": {
            "ratios": {
                "shadow": 0.20,
                "duplicate": 0.15,
                "subnet_overlap": 0.15,
                "service_overlap": 0.15,
                "clean": 0.35,
            }
        },
    }


@pytest.fixture
def sample_policy():
    """One fully-formed policy dict with correct port2 (inside) → port1 (outside) interfaces."""
    return {
        "name": "CORP-INET-WEB-0001",
        "srcintf": [{"name": "port2"}],
        "dstintf": [{"name": "port1"}],
        "srcaddr": [{"name": "LAB-NET-192-168-1-0_24"}],
        "dstaddr": [{"name": "LAB-NET-10-10-0-0_24"}],
        "service": [{"name": "HTTP"}],
        "action": "accept",
        "schedule": "always",
        "status": "enable",
        "logtraffic": "all",
        "logtraffic-start": "enable",
        "comments": "LAB-TEST-2025",
        "nat": "disable",
        "_seq": 1,
        "_type": "clean",
    }


@pytest.fixture
def rules_json_file(tmp_path, sample_policy):
    """Write 10 sample policies to a temp JSON file; return its path string."""
    policies = []
    for i in range(10):
        p = sample_policy.copy()
        p["name"] = f"CORP-INET-WEB-{i:04d}"
        p["_seq"] = i + 1
        policies.append(p)
    data = {
        "metadata": {"total": 10, "total_pushed": 10},
        "policies": policies,
    }
    path = tmp_path / "generated_rules.json"
    path.write_text(json.dumps(data))
    return str(path)


@pytest.fixture
def address_pool():
    """Real address pool built from phase1 — shared across pool-dependent tests."""
    from phase1_rule_gen import build_address_pool
    return build_address_pool(50)


@pytest.fixture
def default_ratios():
    """Standard overlap-type ratios matching config.yaml.example defaults."""
    return {
        "shadow": 0.20,
        "duplicate": 0.15,
        "subnet_overlap": 0.15,
        "service_overlap": 0.15,
        "clean": 0.35,
    }


@pytest.fixture
def mock_scapy():
    """
    Install a fake scapy / scapy.all into sys.modules so any _send_* function
    that does `from scapy.all import IP, TCP, send` gets MagicMocks instead of
    raw socket objects. Cleaned up after each test.
    """
    fake = MagicMock()
    for attr in ("IP", "TCP", "UDP", "ICMP", "DNS", "DNSQR", "send"):
        obj = MagicMock()
        obj.return_value = MagicMock()
        obj.return_value.__truediv__ = lambda self, other: MagicMock()
        setattr(fake, attr, obj)
    sys.modules["scapy"] = fake
    sys.modules["scapy.all"] = fake
    yield fake
    sys.modules.pop("scapy", None)
    sys.modules.pop("scapy.all", None)
