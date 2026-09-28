"""resolve_guest — an omitted guest kind / node is answered by /cluster/resources, not guessed.

Before: `kind` defaulted to "lxc" and `node` to the configured node, so a QEMU guest, or any guest
on another node, reached PVE on the wrong path and came back 500 / 403, which reads like a
permissions problem. Fully mocked, no live Proxmox.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import proximo.server as server
from proximo.audit import AuditLedger
from proximo.backends import ProximoError
from proximo.cluster_ops import resolve_guest
from proximo.config import ProximoConfig
from proximo.firewall import _fw_base

_RESOURCES = [
    {"vmid": 300, "type": "qemu", "node": "pve2", "name": "web1"},
    {"vmid": 200, "type": "lxc", "node": "pve3", "name": "ct1"},
    {"id": "storage/pve1/local", "type": "storage", "node": "pve1"},
]


class _Api:
    def __init__(self, resources=None, raise_on_list=False):
        self.config = SimpleNamespace(node="pve1")
        self._resources = _RESOURCES if resources is None else resources
        self._raise = raise_on_list
        self.gets: list[str] = []
        self.posts: list[tuple[str, dict | None]] = []

    def _get(self, path):
        self.gets.append(path)
        if path == "/cluster/resources?type=vm":
            if self._raise:
                raise RuntimeError("403 Permission check failed")
            return self._resources
        if path.endswith("/config"):
            return {"cores": 2}
        if path == "/storage":
            return []
        return {}

    def _post(self, path, data=None):
        self.posts.append((path, data))
        return "UPID:pve2:00001:0:0:0:task:300:root@pam:"

    def guest_status(self, vmid, kind="lxc", node=None):
        self.gets.append(f"/nodes/{node or self.config.node}/{kind}/{vmid}/status/current")
        return {"status": "running", "name": "web1"}


# ---------------------------------------------------------------------------
# resolve_guest
# ---------------------------------------------------------------------------

def test_both_omitted_come_from_one_listing():
    api = _Api()
    assert resolve_guest(api, "300") == ("qemu", "pve2")
    assert resolve_guest(api, "200") == ("lxc", "pve3")
    assert api.gets == ["/cluster/resources?type=vm"] * 2


def test_explicit_values_mean_no_request():
    api = _Api()
    assert resolve_guest(api, "300", "qemu", "pve2") == ("qemu", "pve2")
    assert resolve_guest(api, "300", "qemu", need_node=False) == ("qemu", None)
    assert api.gets == []


def test_only_the_missing_value_is_filled():
    api = _Api()
    assert resolve_guest(api, "300", kind="qemu") == ("qemu", "pve2")
    assert resolve_guest(api, "300", node="pve2") == ("qemu", "pve2")


def test_explicit_kind_the_cluster_contradicts_is_refused_with_the_real_one():
    with pytest.raises(ProximoError, match="VMID 300 is a qemu guest, not lxc"):
        resolve_guest(_Api(), "300", kind="lxc")


def test_explicit_node_the_cluster_contradicts_is_refused_with_the_real_one():
    with pytest.raises(ProximoError, match="VMID 300 is on node 'pve2', not 'pve1'"):
        resolve_guest(_Api(), "300", node="pve1")


def test_absent_vmid_falls_back_to_the_old_defaults():
    """The caller's own read then meets PVE's 404 and its PLAN says so, as before."""
    assert resolve_guest(_Api(), "999") == ("lxc", None)
    assert resolve_guest(_Api(), "999", kind="qemu") == ("qemu", None)


@pytest.mark.parametrize("api", [_Api(raise_on_list=True), _Api(resources={})])
def test_unreadable_listing_falls_back_to_the_old_defaults(api):
    assert resolve_guest(api, "300") == ("lxc", None)


def test_string_vmid_rows_match_too():
    api = _Api(resources=[{"vmid": "300", "type": "qemu", "node": "pve2"}])
    assert resolve_guest(api, "300") == ("qemu", "pve2")


def test_vmid_is_validated_before_the_wire():
    api = _Api()
    with pytest.raises(ProximoError):
        resolve_guest(api, "300&type=storage")
    assert api.gets == []


# ---------------------------------------------------------------------------
# the firewall guest scope (one path builder for every guest firewall tool)
# ---------------------------------------------------------------------------

def test_firewall_guest_scope_resolves_kind_and_node():
    assert _fw_base(_Api(), "guest", vmid="300") == "/nodes/pve2/qemu/300/firewall"


def test_firewall_node_scope_does_no_lookup():
    api = _Api()
    assert _fw_base(api, "node") == "/nodes/pve1/firewall"
    assert api.gets == []


# ---------------------------------------------------------------------------
# the tool layer
# ---------------------------------------------------------------------------

def _wire(tmp_path, monkeypatch, api):
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(api_base_url="https://x:8006/api2/json", node="pve1", token_path="/run/x",
                        ct_allowlist=frozenset({"*"}), audit_log_path=log)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, api, SimpleNamespace(), AuditLedger(log)))
    return log


def test_guest_status_without_kind_or_node_reads_the_right_path(tmp_path, monkeypatch):
    api = _Api()
    log = _wire(tmp_path, monkeypatch, api)

    server.pve_guest_status(vmid="300")

    assert api.gets[-1] == "/nodes/pve2/qemu/300/status/current"
    with open(log, encoding="utf-8") as f:
        assert json.loads(f.readline())["target"] == "qemu/300"


def test_guest_migrate_without_kind_or_node_posts_from_the_real_source(tmp_path, monkeypatch):
    api = _Api()
    _wire(tmp_path, monkeypatch, api)

    out = server.pve_guest_migrate(vmid="300", target="pve3", online=True, confirm=True)

    assert out["status"] == "submitted"
    assert api.posts == [("/nodes/pve2/qemu/300/migrate", {"target": "pve3", "online": 1})]


def test_ha_resource_add_without_kind_builds_the_right_sid(tmp_path, monkeypatch):
    api = _Api()
    _wire(tmp_path, monkeypatch, api)

    server.pve_ha_resource_add(vmid="300", confirm=True)

    assert api.posts[-1][1]["sid"] == "vm:300"


def test_contradicting_kind_is_refused_before_any_post(tmp_path, monkeypatch):
    api = _Api()
    _wire(tmp_path, monkeypatch, api)

    with pytest.raises(ProximoError, match="is a qemu guest"):
        server.pve_guest_power(vmid="300", action="stop", kind="lxc", confirm=True)
    assert api.posts == []


def test_a_refused_resolution_is_on_the_ledger(tmp_path, monkeypatch):
    api = _Api()
    log = _wire(tmp_path, monkeypatch, api)

    with pytest.raises(ProximoError):
        server.pve_guest_config_get(vmid="300", node="pve1")

    with open(log, encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    assert [(e["action"], e["target"], e["outcome"], e["mutation"], e["detail"]["phase"]) for e in entries] == [
        ("pve_guest_config_get", "guest/300", "error", False, "resolve"),
    ]


def test_firewall_guest_rule_add_without_kind_or_node_posts_to_the_real_guest(tmp_path, monkeypatch):
    api = _Api()
    _wire(tmp_path, monkeypatch, api)

    out = server.pve_firewall_rule_add(action="ACCEPT", scope="guest", vmid="300", proto="tcp",
                                       dport="22", confirm=True)

    assert out["status"] == "ok"
    assert api.posts[-1][0] == "/nodes/pve2/qemu/300/firewall/rules"


def test_ct_diagnose_without_node_reads_the_container_where_it_is(tmp_path, monkeypatch):
    api = _Api()
    _wire(tmp_path, monkeypatch, api)

    server.ct_diagnose(ctid="200")

    assert "/nodes/pve3/lxc/200/status/current" in api.gets
