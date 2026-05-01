"""
Tests for phase1_rule_gen.py

Coverage:
  - _cidr_to_fgt          (pure)
  - _rule_name            (pure)
  - build_address_pool    (pure)
  - _make_policy          (pure)
  - generate_policies     (pure — the exact-count guarantee is the critical test)
  - FortiGateAPI          (mocked network)
  - run(dry_run=True)     (file I/O only)
"""

import ipaddress
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from phase1_rule_gen import (
    FortiGateAPI,
    SERVICES,
    _cidr_to_fgt,
    _make_policy,
    _rule_name,
    build_address_pool,
    generate_policies,
    run,
)


# ---------------------------------------------------------------------------
# _cidr_to_fgt
# ---------------------------------------------------------------------------

class TestCidrToFgt:
    @pytest.mark.parametrize("cidr,expected", [
        ("192.168.1.0/24",    "192.168.1.0 255.255.255.0"),
        ("172.16.0.0/24",     "172.16.0.0 255.255.255.0"),
        ("10.10.0.10/32",     "10.10.0.10 255.255.255.255"),
        ("192.168.1.176/28",  "192.168.1.176 255.255.255.240"),
        ("10.0.0.0/16",       "10.0.0.0 255.255.0.0"),
        # strict=False collapses host bits to network address
        ("192.168.1.5/24",    "192.168.1.0 255.255.255.0"),
    ])
    def test_conversion(self, cidr, expected):
        assert _cidr_to_fgt(cidr) == expected


# ---------------------------------------------------------------------------
# _rule_name
# ---------------------------------------------------------------------------

class TestRuleName:
    def test_corp_inet_web(self):
        name = _rule_name("LAB-NET-192-168-1-0_24", "LAB-NET-10-10-0-0_24", "HTTP", 42)
        assert name == "CORP-INET-WEB-0042"

    def test_mgmt_wan_ssh(self):
        name = _rule_name("LAB-NET-172-16-0-0_24", "LAB-NET-10-20-0-0_24", "SSH", 17)
        assert name == "MGMT-WAN-SSH-0017"

    def test_lan_zone_fallback(self):
        # src address not matching 192-168 or 172-16 → LAN
        name = _rule_name("LAB-HOST-10-10-0-10", "LAB-NET-10-40-0-0_24", "DNS", 1)
        assert name.startswith("LAN-")

    def test_wan_zone_for_10_20(self):
        name = _rule_name("LAB-NET-192-168-1-0_24", "LAB-NET-10-20-0-0_24", "SSH", 1)
        assert "-WAN-" in name

    def test_known_abbrev_kerberos(self):
        name = _rule_name("LAB-NET-192-168-1-0_24", "LAB-NET-10-10-0-0_24", "KERBEROS", 1)
        assert "-AUTH-" in name

    def test_unknown_service_uses_first_four_chars(self):
        name = _rule_name("LAB-NET-192-168-1-0_24", "LAB-NET-10-10-0-0_24", "XYZSERVICE", 1)
        assert "-XYZS-" in name

    def test_counter_zero_padded(self):
        name = _rule_name("LAB-NET-192-168-1-0_24", "LAB-NET-10-10-0-0_24", "HTTP", 1)
        assert name.endswith("-0001")


# ---------------------------------------------------------------------------
# build_address_pool
# ---------------------------------------------------------------------------

class TestBuildAddressPool:
    def test_returns_list(self):
        pool = build_address_pool(10)
        assert isinstance(pool, list)

    def test_has_lab_net_entries(self):
        pool = build_address_pool(10)
        assert any(e["name"].startswith("LAB-NET-") for e in pool)

    def test_has_lab_sub_entries(self):
        pool = build_address_pool(10)
        assert any(e["name"].startswith("LAB-SUB-") for e in pool)

    def test_has_lab_host_entries(self):
        pool = build_address_pool(10)
        assert any(e["name"].startswith("LAB-HOST-") for e in pool)

    def test_entries_have_required_keys(self):
        pool = build_address_pool(10)
        for entry in pool:
            assert "name" in entry
            assert "subnet" in entry
            assert "cidr" in entry

    def test_no_duplicate_names(self):
        pool = build_address_pool(50)
        names = [e["name"] for e in pool]
        assert len(names) == len(set(names))

    def test_cidr_values_are_valid(self):
        pool = build_address_pool(10)
        for entry in pool:
            # Should not raise
            ipaddress.ip_network(entry["cidr"], strict=False)

    def test_inside_addresses_correct_prefix(self):
        pool = build_address_pool(10)
        inside = [e for e in pool if "192-168" in e["name"] or "172-16" in e["name"]]
        assert len(inside) > 0
        for e in inside:
            ip = ipaddress.ip_network(e["cidr"], strict=False)
            first_octet = int(str(ip.network_address).split(".")[0])
            assert first_octet in (192, 172)


# ---------------------------------------------------------------------------
# _make_policy
# ---------------------------------------------------------------------------

class TestMakePolicy:
    REQUIRED_KEYS = {
        "name", "srcintf", "dstintf", "srcaddr", "dstaddr",
        "service", "action", "schedule", "status", "logtraffic",
        "logtraffic-start", "comments", "nat", "_seq", "_type",
    }

    def test_returns_dict(self):
        p = _make_policy(1, "TEST", "SRC", "DST", "HTTP", "port2", "port1")
        assert isinstance(p, dict)

    def test_required_keys_present(self):
        p = _make_policy(1, "TEST", "SRC", "DST", "HTTP", "port2", "port1")
        assert self.REQUIRED_KEYS.issubset(p.keys())

    def test_comments_contains_only_tag(self):
        p = _make_policy(1, "TEST", "SRC", "DST", "HTTP", "port2", "port1",
                         policy_type="shadow-broad")
        assert p["comments"] == "LAB-TEST-2025"
        assert "shadow" not in p["comments"]
        assert "type=" not in p["comments"]

    def test_interfaces_passed_through(self):
        p = _make_policy(1, "TEST", "SRC", "DST", "HTTP", "port5", "port6")
        assert p["srcintf"] == [{"name": "port5"}]
        assert p["dstintf"] == [{"name": "port6"}]

    def test_policy_type_stored_in_type_field(self):
        p = _make_policy(1, "TEST", "SRC", "DST", "HTTP", "port2", "port1",
                         policy_type="duplicate")
        assert p["_type"] == "duplicate"

    def test_seq_stored(self):
        p = _make_policy(42, "TEST", "SRC", "DST", "HTTP", "port2", "port1")
        assert p["_seq"] == 42

    def test_default_action_is_accept(self):
        p = _make_policy(1, "TEST", "SRC", "DST", "HTTP", "port2", "port1")
        assert p["action"] == "accept"


# ---------------------------------------------------------------------------
# generate_policies  — THE CRITICAL CLASS
# ---------------------------------------------------------------------------

class TestGeneratePolicies:
    VALID_TYPES = {
        "shadow-broad", "shadow-specific", "duplicate",
        "subnet-overlap-broad", "subnet-overlap-specific",
        "svc-overlap", "clean",
    }

    @pytest.mark.parametrize("n", [1, 7, 10, 50, 100, 200])
    def test_exact_count(self, address_pool, default_ratios, n):
        policies, meta = generate_policies(n, address_pool, default_ratios, "port2", "port1")
        assert len(policies) == n
        assert meta["total_pushed"] == n

    def test_metadata_keys_present(self, address_pool, default_ratios):
        _, meta = generate_policies(20, address_pool, default_ratios, "port2", "port1")
        for key in ("total", "clean", "shadow", "duplicate",
                    "subnet_overlap", "service_overlap", "total_pushed"):
            assert key in meta

    def test_all_policies_tagged(self, address_pool, default_ratios):
        policies, _ = generate_policies(20, address_pool, default_ratios, "port2", "port1")
        for p in policies:
            assert p["comments"] == "LAB-TEST-2025"

    def test_no_type_leaked_to_comments(self, address_pool, default_ratios):
        policies, _ = generate_policies(20, address_pool, default_ratios, "port2", "port1")
        for p in policies:
            assert "type=" not in p["comments"]

    def test_all_types_are_valid(self, address_pool, default_ratios):
        policies, _ = generate_policies(50, address_pool, default_ratios, "port2", "port1")
        for p in policies:
            assert p["_type"] in self.VALID_TYPES

    def test_all_policies_have_required_keys(self, address_pool, default_ratios):
        required = {"name", "srcintf", "dstintf", "srcaddr", "dstaddr",
                    "service", "action", "comments", "_seq", "_type"}
        policies, _ = generate_policies(20, address_pool, default_ratios, "port2", "port1")
        for p in policies:
            assert required.issubset(p.keys())

    def test_seq_values_unique(self, address_pool, default_ratios):
        policies, _ = generate_policies(30, address_pool, default_ratios, "port2", "port1")
        seqs = [p["_seq"] for p in policies]
        assert len(seqs) == len(set(seqs))

    def test_ratio_normalization(self, address_pool):
        # Ratios summing to 2.0 should still produce exactly n policies
        ratios = {"shadow": 0.40, "duplicate": 0.30, "subnet_overlap": 0.30,
                  "service_overlap": 0.30, "clean": 0.70}
        policies, meta = generate_policies(50, address_pool, ratios, "port2", "port1")
        assert len(policies) == 50
        assert meta["total_pushed"] == 50

    def test_pure_clean_ratios(self, address_pool):
        ratios = {"shadow": 0, "duplicate": 0, "subnet_overlap": 0,
                  "service_overlap": 0, "clean": 1}
        policies, _ = generate_policies(10, address_pool, ratios, "port2", "port1")
        assert all(p["_type"] == "clean" for p in policies)
        assert len(policies) == 10

    def test_high_service_overlap_no_overshoot(self, address_pool):
        # High svc_overlap ratio with small n — service_overlap capping must not overshoot
        ratios = {"shadow": 0, "duplicate": 0, "subnet_overlap": 0,
                  "service_overlap": 1, "clean": 0}
        for n in (3, 5, 7):
            policies, meta = generate_policies(n, address_pool, ratios, "port2", "port1")
            assert len(policies) == n, f"Overshoot at n={n}: got {len(policies)}"

    def test_interfaces_are_assigned(self, address_pool, default_ratios):
        policies, _ = generate_policies(20, address_pool, default_ratios, "port2", "port1")
        for p in policies:
            assert p["srcintf"] == [{"name": "port2"}]
            assert p["dstintf"] == [{"name": "port1"}]


# ---------------------------------------------------------------------------
# FortiGateAPI  (mocked network)
# ---------------------------------------------------------------------------

class TestFortiGateAPI:
    @pytest.fixture
    def api_and_session(self, minimal_config):
        with patch("phase1_rule_gen.requests.Session") as MockSession:
            mock_sess = MagicMock()
            MockSession.return_value = mock_sess
            api = FortiGateAPI(minimal_config["fortigate"])
            api.session = mock_sess
            yield api, mock_sess

    def test_auth_header_set(self, minimal_config):
        with patch("phase1_rule_gen.requests.Session") as MockSession:
            mock_sess = MagicMock()
            MockSession.return_value = mock_sess
            FortiGateAPI(minimal_config["fortigate"])
            call_args = mock_sess.headers.update.call_args[0][0]
            assert "Authorization" in call_args
            assert "test-token" in call_args["Authorization"]

    def test_url_contains_vdom(self, minimal_config):
        with patch("phase1_rule_gen.requests.Session"):
            api = FortiGateAPI(minimal_config["fortigate"])
            url = api._url("/cmdb/firewall/policy")
            assert "vdom=root" in url

    def test_get_returns_json(self, api_and_session):
        api, mock_sess = api_and_session
        mock_sess.get.return_value.json.return_value = {"results": []}
        mock_sess.get.return_value.raise_for_status = MagicMock()
        result = api.get("/cmdb/firewall/policy")
        assert result == {"results": []}

    def test_post_raises_on_error_status(self, api_and_session):
        import requests
        api, mock_sess = api_and_session
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = "Not Found"
        mock_resp.raise_for_status.side_effect = requests.HTTPError("404")
        mock_sess.post.return_value = mock_resp
        with pytest.raises(requests.HTTPError):
            api.post("/cmdb/firewall/policy", {})

    def test_get_existing_addresses_returns_set(self, api_and_session):
        api, mock_sess = api_and_session
        mock_sess.get.return_value.json.return_value = {
            "results": [{"name": "ADDR-A"}, {"name": "ADDR-B"}]
        }
        mock_sess.get.return_value.raise_for_status = MagicMock()
        result = api.get_existing_addresses()
        assert result == {"ADDR-A", "ADDR-B"}

    def test_get_existing_addresses_empty_on_error(self, api_and_session):
        api, mock_sess = api_and_session
        mock_sess.get.side_effect = Exception("connection refused")
        result = api.get_existing_addresses()
        assert result == set()

    def test_create_address_returns_true_on_success(self, api_and_session):
        api, mock_sess = api_and_session
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {}
        mock_sess.post.return_value = mock_resp
        assert api.create_address("TEST-ADDR", "192.168.1.0 255.255.255.0") is True

    def test_create_address_returns_false_on_error(self, api_and_session):
        api, mock_sess = api_and_session
        mock_sess.post.side_effect = Exception("failed")
        assert api.create_address("TEST-ADDR", "192.168.1.0 255.255.255.0") is False

    def test_get_all_lab_policies_filters_by_tag(self, api_and_session):
        api, mock_sess = api_and_session
        mock_sess.get.return_value.json.return_value = {
            "results": [
                {"policyid": 1, "name": "LAB-1", "comments": "LAB-TEST-2025"},
                {"policyid": 2, "name": "PROD-1", "comments": "production rule"},
                {"policyid": 3, "name": "LAB-2", "comments": "LAB-TEST-2025 seq=3"},
            ]
        }
        mock_sess.get.return_value.raise_for_status = MagicMock()
        result = api.get_all_lab_policies()
        assert len(result) == 2
        assert all("LAB-TEST-2025" in p["comments"] for p in result)

    def test_get_all_lab_policies_empty_on_error(self, api_and_session):
        api, mock_sess = api_and_session
        mock_sess.get.side_effect = Exception("timeout")
        result = api.get_all_lab_policies()
        assert result == []


# ---------------------------------------------------------------------------
# run(dry_run=True)  — file I/O, no network
# ---------------------------------------------------------------------------

class TestRunDryRun:
    def _write_config(self, tmp_path, minimal_config):
        cfg = {**minimal_config, "lab": {**minimal_config["lab"],
                                         "output_dir": str(tmp_path)}}
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump(cfg))
        return str(config_file)

    def test_dry_run_writes_json(self, tmp_path, minimal_config):
        config_path = self._write_config(tmp_path, minimal_config)
        run(config_path, n_rules=10, dry_run=True)
        assert (tmp_path / "generated_rules.json").exists()

    def test_dry_run_json_is_valid(self, tmp_path, minimal_config):
        config_path = self._write_config(tmp_path, minimal_config)
        run(config_path, n_rules=10, dry_run=True)
        data = json.loads((tmp_path / "generated_rules.json").read_text())
        assert "policies" in data
        assert "metadata" in data

    def test_dry_run_policy_count(self, tmp_path, minimal_config):
        config_path = self._write_config(tmp_path, minimal_config)
        run(config_path, n_rules=10, dry_run=True)
        data = json.loads((tmp_path / "generated_rules.json").read_text())
        assert len(data["policies"]) == 10

    def test_dry_run_returns_metadata(self, tmp_path, minimal_config):
        config_path = self._write_config(tmp_path, minimal_config)
        meta = run(config_path, n_rules=10, dry_run=True)
        assert isinstance(meta, dict)
        assert "total" in meta
