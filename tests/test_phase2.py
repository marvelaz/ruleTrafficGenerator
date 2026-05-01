"""
Tests for phase2_traffic.py

Coverage:
  - _addr_name_to_cidr        (pure)
  - _pick_ip_for_addr         (pure)
  - TrafficTargetSelector     (file I/O + pure logic)
  - TrafficStats              (pure)
  - dispatch_session          (mocked _send_* functions)
  - SERVICE_PORT_MAP alignment with phase1 SERVICES  (cross-module consistency)
  - setup_ip_aliases          (subprocess mocked)
"""

import subprocess
import time
from subprocess import CalledProcessError
from unittest.mock import MagicMock, call, patch

import pytest

from phase1_rule_gen import SERVICES
from phase2_traffic import (
    SERVICE_PORT_MAP,
    TrafficStats,
    TrafficTargetSelector,
    _addr_name_to_cidr,
    _pick_ip_for_addr,
    dispatch_session,
    setup_ip_aliases,
)


# ---------------------------------------------------------------------------
# _addr_name_to_cidr
# ---------------------------------------------------------------------------

class TestAddrNameToCidr:
    @pytest.mark.parametrize("name,expected", [
        # LAB-NET — /24 subnets
        ("LAB-NET-192-168-1-0_24",    "192.168.1.0/24"),
        ("LAB-NET-10-10-0-0_24",      "10.10.0.0/24"),
        ("LAB-NET-172-16-0-0_24",     "172.16.0.0/24"),
        # LAB-SUB — /28 subnets
        ("LAB-SUB-192-168-1-176_28",  "192.168.1.176/28"),
        ("LAB-SUB-10-20-0-0_28",      "10.20.0.0/28"),
        # LAB-HOST — /32 hosts
        ("LAB-HOST-192-168-1-10",     "192.168.1.10/32"),
        ("LAB-HOST-10-10-0-50",       "10.10.0.50/32"),
        ("LAB-HOST-172-16-1-50",      "172.16.1.50/32"),
        # Unknown / empty → None
        ("UNKNOWN-192-168-1-0",       None),
        ("",                          None),
    ])
    def test_parsing(self, name, expected):
        assert _addr_name_to_cidr(name) == expected


# ---------------------------------------------------------------------------
# _pick_ip_for_addr
# ---------------------------------------------------------------------------

class TestPickIpForAddr:
    def test_returns_ip_in_24_subnet(self):
        result = _pick_ip_for_addr(
            "LAB-NET-192-168-1-0_24",
            ["192.168.1.10", "10.10.0.5"],
        )
        assert result == "192.168.1.10"

    def test_returns_ip_in_28_subnet(self):
        # 192.168.1.176/28 covers .176–.191
        result = _pick_ip_for_addr(
            "LAB-SUB-192-168-1-176_28",
            ["192.168.1.180", "192.168.1.10", "10.0.0.1"],
        )
        assert result == "192.168.1.180"

    def test_host32_returns_exact_ip(self):
        result = _pick_ip_for_addr(
            "LAB-HOST-192-168-1-10",
            ["192.168.1.10", "192.168.2.1"],
        )
        assert result == "192.168.1.10"

    def test_fallback_on_unknown_name(self):
        available = ["1.2.3.4", "5.6.7.8"]
        result = _pick_ip_for_addr("UNKNOWN-ADDR", available)
        assert result in available

    def test_fallback_when_no_ip_in_subnet(self):
        # No available IPs fall in 192.168.1.0/24
        available = ["10.0.0.1", "10.0.0.2"]
        result = _pick_ip_for_addr("LAB-NET-192-168-1-0_24", available)
        assert result in available

    def test_multiple_matching_ips_both_reachable(self):
        # Both IPs are in 192.168.1.0/24 — both must be returnable
        available = ["192.168.1.10", "192.168.1.20"]
        seen = set()
        for _ in range(50):
            seen.add(_pick_ip_for_addr("LAB-NET-192-168-1-0_24", available))
        assert seen == {"192.168.1.10", "192.168.1.20"}

    def test_empty_available_ips_raises(self):
        # Document current behaviour: random.choice([]) raises IndexError
        with pytest.raises(IndexError):
            _pick_ip_for_addr("LAB-NET-192-168-1-0_24", [])


# ---------------------------------------------------------------------------
# TrafficTargetSelector
# ---------------------------------------------------------------------------

class TestTrafficTargetSelector:
    def test_loads_correct_target_count(self, rules_json_file):
        sel = TrafficTargetSelector(rules_json_file, match_ratio=1.0)
        assert len(sel.targets) == 10

    def test_match_ratio_applied(self, rules_json_file):
        sel = TrafficTargetSelector(rules_json_file, match_ratio=0.5)
        assert len(sel.targets) == 5

    def test_targets_plus_skipped_equals_total(self, rules_json_file):
        sel = TrafficTargetSelector(rules_json_file, match_ratio=0.7)
        assert len(sel.targets) + len(sel.skipped) == 10

    def test_missing_file_no_crash(self, tmp_path):
        sel = TrafficTargetSelector(str(tmp_path / "nonexistent.json"), 0.5)
        assert sel.targets == []

    def test_get_next_target_returns_none_when_empty(self, tmp_path):
        sel = TrafficTargetSelector(str(tmp_path / "nonexistent.json"), 0.5)
        assert sel.get_next_target() is None

    def test_get_next_target_returns_dict(self, rules_json_file):
        sel = TrafficTargetSelector(rules_json_file, match_ratio=1.0)
        result = sel.get_next_target()
        assert isinstance(result, dict)
        assert "name" in result

    def test_round_robin_all_targets_in_one_pass(self, rules_json_file):
        sel = TrafficTargetSelector(rules_json_file, match_ratio=1.0)
        seen = set()
        for _ in range(10):
            p = sel.get_next_target()
            seen.add(p["name"])
        # Every target must appear exactly once before any repeats
        assert len(seen) == 10

    def test_round_robin_second_pass_complete(self, rules_json_file):
        sel = TrafficTargetSelector(rules_json_file, match_ratio=1.0)
        # Exhaust first pass
        for _ in range(10):
            sel.get_next_target()
        # Second pass must also cover all 10
        seen = set()
        for _ in range(10):
            p = sel.get_next_target()
            seen.add(p["name"])
        assert len(seen) == 10

    def test_cycle_refills_after_exhaustion(self, rules_json_file):
        sel = TrafficTargetSelector(rules_json_file, match_ratio=1.0)
        # 11th call on a 10-target selector must still return a valid policy
        for _ in range(10):
            sel.get_next_target()
        result = sel.get_next_target()
        assert result is not None
        assert "name" in result


# ---------------------------------------------------------------------------
# TrafficStats
# ---------------------------------------------------------------------------

class TestTrafficStats:
    def test_initial_state(self):
        stats = TrafficStats()
        assert stats.sent == 0
        assert stats.failed == 0
        assert stats.sessions == 0
        assert stats.proto_counts == {}

    def test_record_sent_increments(self):
        stats = TrafficStats()
        stats.record({"sent": True, "proto": "tcp"})
        assert stats.sent == 1
        assert stats.sessions == 1
        assert stats.failed == 0

    def test_record_failed_increments(self):
        stats = TrafficStats()
        stats.record({"sent": False, "proto": "tcp"})
        assert stats.failed == 1
        assert stats.sessions == 1
        assert stats.sent == 0

    def test_proto_counts_tracked(self):
        stats = TrafficStats()
        for _ in range(3):
            stats.record({"sent": True, "proto": "tcp"})
        stats.record({"sent": True, "proto": "icmp"})
        assert stats.proto_counts == {"tcp": 3, "icmp": 1}

    @pytest.mark.parametrize("delta_secs,expected", [
        (65,  "1m 5s"),
        (125, "2m 5s"),
        (60,  "1m 0s"),
        (0,   "0m 0s"),
    ])
    def test_elapsed_format(self, monkeypatch, delta_secs, expected):
        stats = TrafficStats()
        monkeypatch.setattr(time, "time", lambda: stats.start_time + delta_secs)
        assert stats.elapsed() == expected

    def test_render_table_returns_table(self):
        from rich.table import Table
        stats = TrafficStats()
        assert isinstance(stats.render_table(), Table)

    def test_render_table_has_rows(self):
        stats = TrafficStats()
        table = stats.render_table()
        assert table.row_count >= 4  # Sessions, Sent OK, Failed, Elapsed

    def test_render_table_includes_proto_row(self):
        stats = TrafficStats()
        stats.record({"sent": True, "proto": "tcp"})
        table = stats.render_table()
        # Proto rows are added after the fixed 4 rows
        assert table.row_count >= 5


# ---------------------------------------------------------------------------
# dispatch_session  (mocked _send_* functions)
# ---------------------------------------------------------------------------

PATCH_ALL_SENDS = {
    "phase2_traffic._send_tcp_syn": MagicMock(return_value=True),
    "phase2_traffic._send_icmp": MagicMock(return_value=True),
    "phase2_traffic._send_dns_query": MagicMock(return_value=True),
    "phase2_traffic._send_http_request": MagicMock(return_value=True),
}

SRC_IPS = ["192.168.1.10", "192.168.1.20"]
DST_IPS = ["10.10.0.5", "10.10.0.6"]


def _make_test_policy(svc_name):
    return {
        "name": "TEST-POLICY",
        "srcaddr": [{"name": "LAB-NET-192-168-1-0_24"}],
        "dstaddr": [{"name": "LAB-NET-10-10-0-0_24"}],
        "service": [{"name": svc_name}],
    }


class TestDispatchSession:
    def _dispatch(self, svc_name, src_ips=None, dst_ips=None):
        policy = _make_test_policy(svc_name)
        return dispatch_session(
            policy,
            src_ips or SRC_IPS,
            dst_ips or DST_IPS,
            "eth0",
            icmp_count=3,
        )

    def test_http_routes_to_send_http(self):
        with patch("phase2_traffic._send_http_request", return_value=True) as m, \
             patch("phase2_traffic._send_tcp_syn", return_value=True), \
             patch("phase2_traffic._send_icmp", return_value=True), \
             patch("phase2_traffic._send_dns_query", return_value=True):
            self._dispatch("HTTP")
        m.assert_called_once()

    def test_https_routes_to_tcp_syn(self):
        with patch("phase2_traffic._send_tcp_syn", return_value=True) as m, \
             patch("phase2_traffic._send_http_request", return_value=True), \
             patch("phase2_traffic._send_icmp", return_value=True), \
             patch("phase2_traffic._send_dns_query", return_value=True):
            result = self._dispatch("HTTPS")
        m.assert_called_once()
        assert result["port"] == 443

    def test_ssh_routes_to_tcp_syn_port_22(self):
        with patch("phase2_traffic._send_tcp_syn", return_value=True) as m, \
             patch("phase2_traffic._send_http_request", return_value=True), \
             patch("phase2_traffic._send_icmp", return_value=True), \
             patch("phase2_traffic._send_dns_query", return_value=True):
            result = self._dispatch("SSH")
        m.assert_called_once()
        assert result["port"] == 22

    def test_ping_routes_to_send_icmp(self):
        with patch("phase2_traffic._send_icmp", return_value=True) as m, \
             patch("phase2_traffic._send_tcp_syn", return_value=True), \
             patch("phase2_traffic._send_http_request", return_value=True), \
             patch("phase2_traffic._send_dns_query", return_value=True):
            self._dispatch("PING")
        m.assert_called_once()

    def test_dns_routes_to_send_dns_query(self):
        with patch("phase2_traffic._send_dns_query", return_value=True) as m, \
             patch("phase2_traffic._send_tcp_syn", return_value=True), \
             patch("phase2_traffic._send_http_request", return_value=True), \
             patch("phase2_traffic._send_icmp", return_value=True):
            self._dispatch("DNS")
        m.assert_called_once()

    def test_smtp_routes_to_tcp_syn_port_25(self):
        with patch("phase2_traffic._send_tcp_syn", return_value=True) as m, \
             patch("phase2_traffic._send_http_request", return_value=True), \
             patch("phase2_traffic._send_icmp", return_value=True), \
             patch("phase2_traffic._send_dns_query", return_value=True):
            result = self._dispatch("SMTP")
        m.assert_called_once()
        assert result["port"] == 25

    def test_ntp_udp_skip_no_send(self):
        with patch("phase2_traffic._send_tcp_syn", return_value=True) as tcp, \
             patch("phase2_traffic._send_http_request", return_value=True) as http, \
             patch("phase2_traffic._send_icmp", return_value=True) as icmp, \
             patch("phase2_traffic._send_dns_query", return_value=True) as dns:
            result = self._dispatch("NTP")
        tcp.assert_not_called()
        http.assert_not_called()
        icmp.assert_not_called()
        dns.assert_not_called()
        assert result["sent"] is False

    def test_empty_service_list_defaults_no_crash(self):
        policy = {
            "name": "TEST",
            "srcaddr": [{"name": "LAB-NET-192-168-1-0_24"}],
            "dstaddr": [{"name": "LAB-NET-10-10-0-0_24"}],
            "service": [],
        }
        with patch("phase2_traffic._send_http_request", return_value=True), \
             patch("phase2_traffic._send_tcp_syn", return_value=True), \
             patch("phase2_traffic._send_icmp", return_value=True), \
             patch("phase2_traffic._send_dns_query", return_value=True):
            result = dispatch_session(policy, SRC_IPS, DST_IPS, "eth0", 3)
        assert "sent" in result

    def test_returns_required_keys(self):
        with patch("phase2_traffic._send_http_request", return_value=True), \
             patch("phase2_traffic._send_tcp_syn", return_value=True), \
             patch("phase2_traffic._send_icmp", return_value=True), \
             patch("phase2_traffic._send_dns_query", return_value=True):
            result = self._dispatch("HTTP")
        for key in ("src", "dst", "proto", "port", "policy", "sent"):
            assert key in result

    def test_ip_selected_within_policy_subnet(self):
        # src_ips has one IP in 192.168.1.0/24 and one outside — must pick inside
        with patch("phase2_traffic._send_http_request", return_value=True), \
             patch("phase2_traffic._send_tcp_syn", return_value=True), \
             patch("phase2_traffic._send_icmp", return_value=True), \
             patch("phase2_traffic._send_dns_query", return_value=True):
            result = self._dispatch(
                "HTTP",
                src_ips=["192.168.1.10", "10.0.0.1"],
                dst_ips=["10.10.0.5"],
            )
        assert result["src"] == "192.168.1.10"

    def test_sent_true_on_success(self):
        with patch("phase2_traffic._send_http_request", return_value=True), \
             patch("phase2_traffic._send_tcp_syn", return_value=True), \
             patch("phase2_traffic._send_icmp", return_value=True), \
             patch("phase2_traffic._send_dns_query", return_value=True):
            result = self._dispatch("HTTP")
        assert result["sent"] is True

    def test_sent_false_on_failure(self):
        with patch("phase2_traffic._send_http_request", return_value=False), \
             patch("phase2_traffic._send_tcp_syn", return_value=False), \
             patch("phase2_traffic._send_icmp", return_value=False), \
             patch("phase2_traffic._send_dns_query", return_value=False):
            result = self._dispatch("HTTP")
        assert result["sent"] is False


# ---------------------------------------------------------------------------
# SERVICE_PORT_MAP alignment with phase1 SERVICES
# ---------------------------------------------------------------------------

class TestServicePortMapAlignment:
    def test_all_phase1_services_in_port_map(self):
        missing = [svc["name"] for svc in SERVICES if svc["name"] not in SERVICE_PORT_MAP]
        assert missing == [], f"Services missing from SERVICE_PORT_MAP: {missing}"

    def test_ping_key_not_icmp(self):
        # phase1 uses "PING"; "ICMP" would silently fall through to default
        assert "PING" in SERVICE_PORT_MAP
        assert "ICMP" not in SERVICE_PORT_MAP

    def test_mssql_key_has_hyphen(self):
        # phase1 uses "MS-SQL" not "MSSQL"
        assert "MS-SQL" in SERVICE_PORT_MAP
        assert "MSSQL" not in SERVICE_PORT_MAP

    def test_dns_key_not_dns_udp(self):
        # phase1 uses "DNS" not "DNS-UDP"
        assert "DNS" in SERVICE_PORT_MAP
        assert "DNS-UDP" not in SERVICE_PORT_MAP

    def test_all_proto_values_valid(self):
        valid_protos = {"tcp", "icmp", "dns", "udp_skip"}
        for svc_name, (proto, port) in SERVICE_PORT_MAP.items():
            assert proto in valid_protos, f"{svc_name} has invalid proto '{proto}'"


# ---------------------------------------------------------------------------
# setup_ip_aliases  (subprocess mocked)
# ---------------------------------------------------------------------------

class TestSetupIpAliases:
    def test_add_calls_ip_addr_add(self):
        with patch("phase2_traffic.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            setup_ip_aliases("eth0", ["192.168.1.101"], remove=False)
        mock_run.assert_called_once_with(
            ["ip", "addr", "add", "192.168.1.101/24", "dev", "eth0"],
            check=True,
            capture_output=True,
        )

    def test_remove_calls_ip_addr_del(self):
        with patch("phase2_traffic.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            setup_ip_aliases("eth0", ["192.168.1.101"], remove=True)
        mock_run.assert_called_once_with(
            ["ip", "addr", "del", "192.168.1.101/24", "dev", "eth0"],
            check=True,
            capture_output=True,
        )

    def test_multiple_aliases_multiple_calls(self):
        with patch("phase2_traffic.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            setup_ip_aliases("eth0", ["192.168.1.101", "192.168.1.102"])
        assert mock_run.call_count == 2

    def test_subprocess_error_no_crash(self):
        with patch("phase2_traffic.subprocess.run") as mock_run:
            mock_run.side_effect = CalledProcessError(
                1, "ip", stderr=b"RTNETLINK answers: File exists"
            )
            # Must not raise — errors are silently logged
            setup_ip_aliases("eth0", ["192.168.1.101"])
