"""pve_guest_migrate_preflight — PVE's own migration precondition (GET .../migrate).

Fully mocked, no live Proxmox. The op builds the right path (node default, optional ?target=),
validates before the wire, and returns PVE's data unchanged; the tool is audited as a read
and never reaches a mutating verb.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import proximo.server as server
from proximo.audit import AuditLedger
from proximo.backends import ProximoError
from proximo.cluster_ops import guest_migrate_preflight
from proximo.config import ProximoConfig

_VERDICT = {
    "running": 1,
    "allowed_nodes": ["pve2"],
    "not_allowed_nodes": {"pve3": {"unavailable_storages": ["local-lvm"]}},
    "local_disks": [{"volid": "local-lvm:vm-300-disk-0", "size": 34359738368, "drivename": "scsi0"}],
    "local_resources": [],
}


class _Api:
    def __init__(self, data=None):
        self.config = SimpleNamespace(node="pve1")
        self.gets: list[str] = []
        self.writes: list[str] = []
        self._data = _VERDICT if data is None else data

    def _get(self, path):
        self.gets.append(path)
        return self._data

    def _post(self, path, data=None):
        self.writes.append(path)

    def _put(self, path, data=None):
        self.writes.append(path)

    def _delete(self, path, params=None):
        self.writes.append(path)


def test_preflight_defaults_to_the_configured_node():
    api = _Api()
    assert guest_migrate_preflight(api, "300", kind="qemu") == _VERDICT
    assert api.gets == ["/nodes/pve1/qemu/300/migrate"]


def test_preflight_passes_target_and_node():
    api = _Api()
    guest_migrate_preflight(api, "200", kind="lxc", node="pve2", target="pve3")
    assert api.gets == ["/nodes/pve2/lxc/200/migrate?target=pve3"]


def test_preflight_none_body_is_an_empty_dict():
    api = _Api(data={})
    assert guest_migrate_preflight(api, "300", kind="qemu") == {}


@pytest.mark.parametrize("kwargs", [
    {"vmid": "abc"},
    {"vmid": "300", "kind": "docker"},
    {"vmid": "300", "node": "bad/node"},
    {"vmid": "300", "target": "pve2&force=1"},
    {"vmid": "300", "target": ""},
])
def test_preflight_validates_before_the_wire(kwargs):
    api = _Api()
    with pytest.raises(ProximoError):
        guest_migrate_preflight(api, **{"kind": "qemu", **kwargs})
    assert api.gets == []


def test_preflight_tool_is_an_audited_read(tmp_path, monkeypatch):
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(api_base_url="https://x:8006/api2/json", node="pve1", token_path="/run/x",
                        ct_allowlist=frozenset({"*"}), audit_log_path=log)
    api = _Api()
    monkeypatch.setattr(server, "_svc", lambda: (cfg, api, SimpleNamespace(), AuditLedger(log)))

    out = server.pve_guest_migrate_preflight(vmid="300", kind="qemu", target="pve2")

    assert out == _VERDICT
    assert api.gets == ["/nodes/pve1/qemu/300/migrate?target=pve2"]
    assert api.writes == []
    with open(log, encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]
    assert [(e["action"], e["target"], e["mutation"]) for e in entries] == [
        ("pve_guest_migrate_preflight", "qemu/300", False)
    ]
