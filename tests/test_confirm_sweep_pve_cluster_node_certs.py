"""Confirm=True sweep — pve_cluster + pve_node + pve_certs wrapper welds.

Closes the coverage-audit gap (`.scratch/2026-07-14-tool-coverage-audit-findings.json`,
modules `src/proximo/tools/pve_cluster.py` (3 high), `src/proximo/tools/pve_node.py`
(1 high + 3 med), `src/proximo/tools/pve_certs.py` (2 high)): every tool below has its
confirm=False PLAN branch tested elsewhere (test_cluster_ops.py, test_tasks_pools.py,
test_storage_admin.py, test_node_lifecycle.py, test_certs.py) but its confirm=True EXECUTE
branch — the wrapper's own `_audited(...)` call — was never invoked through the actual
`server.pve_*` wrapper, only through the underlying op/plan functions, bypassing the
wrapper's own argument-forwarding and _audited() wiring.

Mirrors the `_wire()` idiom in tests/test_server_plan.py:110-131 (already re-used and
review-approved in tests/test_confirm_sweep_pve_firewall_network.py and
tests/test_confirm_sweep_pve_guest.py): `proximo.server._svc` is monkeypatched to a fake
api + a REAL AuditLedger in tmp_path, so a confirm=True call proves three welds at once:
  1. return shape — status is the EXECUTED shape ("ok"/"submitted"), never "plan";
  2. the fake api captured the underlying call — reusing the fake idioms already
     established in test_cluster_ops.py (`_StatusApi.guest_status` + path-aware `_get`
     for the migrate disk-residency blast) and test_node_lifecycle.py (`_FakeNodeApi`'s
     typed node_hosts_get/set, node_dns_set, node_startall, node_storage_backend_create
     methods — pve_node.py calls these directly, not through generic _get/_post/_put/_delete);
  3. the ledger recorded a confirmed mutation — structural asserts only (action, mutation,
     outcome, detail.confirmed), never exact prose.

Two tools carry a unique weld beyond the generic three, called out explicitly by the
audit-fixes plan (Task 3):
  - pve_guest_migrate forwards `online` differently by guest kind (pve_cluster.py:139-144 /
    cluster_ops.py:240-248): QEMU online=True sends 'online=1' (live migration); LXC
    online=True sends 'restart=1' (stop→move→start — real downtime, NOT live). The test
    asserts the correct key lands for each kind, and that the other key is absent.
  - pve_node_storage_backend_create (pve_node.py:165-178) builds TWO different views of the
    same **kw from the caller: the raw API call receives every kwarg verbatim (including an
    explicit None), but the ledger `detail` only gets the non-None subset (`extra = {k: v for
    k, v in kw.items() if v is not None}`, pve_node.py:171). The test asserts a None-valued
    kwarg reaches the api call unfiltered but is absent from the ledger detail — the
    "kwarg filtering + ledger detail" weld named in the audit-fixes plan.

The fake api's `_get` is path-aware, reusing the idioms already established in the sibling
test modules: cluster/resource reads return [] (storage-delete's dependent-guest blast finds
nothing, keeping the plan clean), guest-config reads return a disk-free config (so the
migrate blast finds no disks to flag), storage.cfg reads return [], ACL/pool reads return an
empty/harmless pool, and ACME account/plugin reads return a small fixture dict. This lets
every tool's _plan() build (which runs even on confirm=True — no plan, no mutation) resolve
without raising, while the mutation calls land in per-verb (or per-typed-method) capture
lists.

Three more dedicated tests (Task 11), the same honesty fix already landed for
pve_backup_delete (tests/test_confirm_sweep_pve_backup.py): backends.py's node_startall/
node_stopall/node_migrateall are all typed `-> str | None` and documented "Returns a task
UPID or None", but the pve_node.py wrappers hardcoded outcome="submitted" regardless of what
the backend actually returned. When PVE answers with no task (synchronous, already-finished),
a fixed "submitted" would falsely claim an in-flight task in BOTH the envelope status and the
ledger's own record — each tool gets a sync case (backend returns None -> "ok") alongside its
existing/added async case (backend returns a UPID -> "submitted").
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

import proximo.server as server
from proximo.audit import AuditLedger
from proximo.config import ProximoConfig


class _Api:
    """Path-aware fake Proxmox api: records every generic _post/_put/_delete call AND the
    typed methods pve_node.py / cluster_ops.py call directly on the api object (guest_status,
    node_hosts_get/set, node_dns_set, node_startall, node_storage_backend_create) — mirrors
    test_cluster_ops.py's `_StatusApi` and test_node_lifecycle.py's `_FakeNodeApi`. Answers
    _get reads just enough for the PLAN builders (which always run first, even on
    confirm=True) to resolve without raising.
    """

    def __init__(self, node: str = "pve"):
        self.config = SimpleNamespace(node=node)
        self.gets: list[str] = []
        self.posts: list[tuple[str, dict | None]] = []
        self.puts: list[tuple[str, dict | None]] = []
        self.deletes: list[tuple[str, dict | None]] = []
        # typed-method capture lists — these tools call api.<method>(...) directly, not the
        # generic verbs above.
        self.node_hosts_sets: list[tuple] = []
        self.node_dns_sets: list[tuple] = []
        self.node_startalls: list[tuple] = []
        self.node_stopalls: list[tuple] = []
        self.node_migratealls: list[tuple] = []
        self.node_storage_backend_creates: list[tuple] = []

    def _get(self, path):
        self.gets.append(path)
        if path == "/cluster/resources":
            return []  # storage_delete/update's dependent-guest blast: no guests to flag
        if path.endswith("/config"):
            # guest config for pve_guest_migrate's disk-residency blast — no disk keys, so
            # the blast finds nothing to migrate and the plan stays clean.
            return {"cores": 2, "memory": 512}
        if path == "/storage":
            return []
        if path == "/access/acl":
            return []
        if path.startswith("/pools/"):
            return {"poolid": "team-a", "members": []}
        if path.startswith("/cluster/acme/account/"):
            return {"name": "letsencrypt", "contact": "admin@example.test"}
        if path.startswith("/cluster/acme/plugins/"):
            return {"id": "cf-dns", "type": "dns", "api": "cf"}
        if path.endswith("/dns"):
            return {"search": "example.test", "dns1": "9.9.9.9"}
        return {}

    def _post(self, path, data=None):
        self.posts.append((path, data))
        return "UPID:pve:00001:0:0:0:task:100:root@pam:"

    def _put(self, path, data=None):
        self.puts.append((path, data))
        return None

    def _delete(self, path, params=None):
        self.deletes.append((path, params))
        return None

    # --- typed methods called directly (not through _get/_post/_put/_delete) ---

    def guest_status(self, vmid, kind="lxc", node=None):
        return {"status": "running", "name": "web1", "uptime": 500}

    def node_hosts_get(self, node=None):
        return {"data": "127.0.0.1 localhost\n", "digest": "hosts-digest-1"}

    def node_hosts_set(self, data, node=None, digest=None):
        self.node_hosts_sets.append((data, node, digest))

    def node_dns_set(self, node=None, search=None, dns1=None, dns2=None, dns3=None):
        self.node_dns_sets.append((node, search, dns1, dns2, dns3))

    def node_startall(self, node=None, vms=None):
        self.node_startalls.append((node, vms))
        return "UPID:pve:00002:0:0:0:vzstart:0:root@pam:"

    def node_stopall(self, node=None, vms=None):
        self.node_stopalls.append((node, vms))
        return "UPID:pve:00004:0:0:0:vzstop:0:root@pam:"

    def node_migrateall(self, target, node=None, vms=None, maxworkers=None):
        self.node_migratealls.append((target, node, vms, maxworkers))
        return "UPID:pve:00005:0:0:0:migrateall:0:root@pam:"

    def node_storage_backend_create(self, backend, name, node=None, **kw):
        self.node_storage_backend_creates.append((backend, name, node, kw))
        return "UPID:pve:00003:0:0:0:diskcreate:0:root@pam:"


def _wire(tmp_path, monkeypatch):
    """The `_wire()` idiom from tests/test_server_plan.py:110-131."""
    log = str(tmp_path / "audit.log")
    cfg = ProximoConfig(
        api_base_url="https://x:8006/api2/json", node="pve", token_path="/run/x",
        ct_allowlist=frozenset({"*"}), audit_log_path=log,
    )
    api = _Api()
    exec_ = SimpleNamespace()  # unused by these wrappers
    ledger = AuditLedger(log)
    monkeypatch.setattr(server, "_svc", lambda: (cfg, api, exec_, ledger))
    return cfg, api, ledger, log


def _entries(log: str) -> list[dict]:
    with open(log, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _confirmed_entry(log: str, action: str, outcome: str) -> dict:
    entries = [e for e in _entries(log) if e["action"] == action and e["outcome"] == outcome]
    assert len(entries) == 1, f"expected exactly one {action!r}/{outcome!r} ledger entry, got {entries}"
    return entries[0]


# ---------------------------------------------------------------------------
# Homogeneous sweep — table-driven over the tools with no unique weld beyond
# "confirm=True reaches the right verb/path/data and records a confirmed mutation".
# Covers pve_cluster.py's HA/task/pool/storage-CRUD group (pve_guest_migrate is pulled out
# below for its kind-dependent online/restart weld) and all 6 pve_certs.py ACME
# account/plugin CRUD tools.
# ---------------------------------------------------------------------------

_SWEEP_CASES = [
    pytest.param(
        "pve_ha_resource_add",
        dict(vmid="150", kind="lxc", state="started"),
        "ok", "posts", "/cluster/ha/resources",
        # ha_resource_add(): group/max_restart/max_relocate all None here -> omitted.
        {"sid": "ct:150", "state": "started"},
        id="ha_resource_add",
    ),
    pytest.param(
        "pve_ha_resource_remove",
        dict(vmid="150", kind="lxc"),
        "ok", "deletes", "/cluster/ha/resources/ct:150",
        # ha_resource_remove() calls api._delete(path) with NO params arg -> captured params=None.
        None,
        id="ha_resource_remove",
    ),
    pytest.param(
        "pve_task_stop",
        dict(upid="UPID:pve:0000A1B2:0000C3D4:00000000:00000001:vzdump:105:root@pam:"),
        "ok", "deletes",
        "/nodes/pve/tasks/UPID:pve:0000A1B2:0000C3D4:00000000:00000001:vzdump:105:root@pam:",
        # task_stop() calls api._delete(path) with NO params arg -> captured params=None.
        None,
        id="task_stop",
    ),
    pytest.param(
        "pve_pool_update",
        dict(poolid="team-a", vms="100,200"),
        "ok", "puts", "/pools/team-a",
        # pool_update(): storage=None, delete=False -> only vms lands in the body.
        {"vms": "100,200"},
        id="pool_update",
    ),
    pytest.param(
        "pve_pool_delete",
        dict(poolid="team-a"),
        "ok", "deletes", "/pools/team-a",
        # pool_delete() calls api._delete(path) with NO params arg -> captured params=None.
        None,
        id="pool_delete",
    ),
    pytest.param(
        "pve_storage_create",
        dict(storage="nfs1", storage_type="nfs", server="nfs.example.test", export="/data"),
        "ok", "posts", "/storage",
        # storage_create(): content/path/nodes all None, disable/shared both False -> omitted.
        {"storage": "nfs1", "type": "nfs", "server": "nfs.example.test", "export": "/data"},
        id="storage_create",
    ),
    pytest.param(
        "pve_storage_update",
        dict(storage="nfs1", content="images,iso"),
        "ok", "puts", "/storage/nfs1",
        # storage_update(): nodes/disable/shared/delete all None -> omitted.
        {"content": "images,iso"},
        id="storage_update",
    ),
    pytest.param(
        "pve_storage_delete",
        dict(storage="nfs1"),
        "ok", "deletes", "/storage/nfs1",
        # storage_delete() calls api._delete(path) with NO params arg -> captured params=None.
        None,
        id="storage_delete",
    ),
    pytest.param(
        "pve_acme_account_create",
        dict(name="letsencrypt", contact="admin@example.test"),
        "ok", "posts", "/cluster/acme/account",
        # acme_account_create(): tos_url/directory both None -> filtered by the op's own
        # "{k: v for k, v in data.items() if v is not None}" before the POST.
        {"name": "letsencrypt", "contact": "admin@example.test"},
        id="acme_account_create",
    ),
    pytest.param(
        "pve_acme_account_update",
        dict(name="letsencrypt", contact="ops@example.test"),
        "ok", "puts", "/cluster/acme/account/letsencrypt",
        # acme_account_update(): only contact is ever passed through **kw by the wrapper.
        {"contact": "ops@example.test"},
        id="acme_account_update",
    ),
    pytest.param(
        "pve_acme_account_delete",
        dict(name="letsencrypt"),
        "ok", "deletes", "/cluster/acme/account/letsencrypt",
        # acme_account_delete() calls api._delete(path) with NO params arg -> captured params=None.
        None,
        id="acme_account_delete",
    ),
    pytest.param(
        "pve_acme_plugin_create",
        dict(plugin_id="cf-dns", plugin_type="dns", dns_api="cf"),
        "ok", "posts", "/cluster/acme/plugins",
        # acme_plugin_create(): dns_api maps to 'api'; data/disable both None -> omitted.
        {"id": "cf-dns", "type": "dns", "api": "cf"},
        id="acme_plugin_create",
    ),
    pytest.param(
        "pve_acme_plugin_update",
        dict(plugin_id="cf-dns", dns_api="route53"),
        "ok", "puts", "/cluster/acme/plugins/cf-dns",
        # acme_plugin_update(): dns_api maps to 'api'; data/disable/digest all None -> omitted.
        {"api": "route53"},
        id="acme_plugin_update",
    ),
    pytest.param(
        "pve_acme_plugin_delete",
        dict(plugin_id="cf-dns"),
        "ok", "deletes", "/cluster/acme/plugins/cf-dns",
        # acme_plugin_delete() calls api._delete(path) with NO params arg -> captured params=None.
        None,
        id="acme_plugin_delete",
    ),
]


@pytest.mark.parametrize(
    "tool_name,kwargs,expected_status,capture,path,data_exact", _SWEEP_CASES,
)
def test_confirm_true_executes_forwards_and_records(
    tmp_path, monkeypatch, tool_name, kwargs, expected_status, capture, path, data_exact,
):
    """confirm=True executes (never 'plan'), the fake captured the forwarded call, and the
    ledger recorded a confirmed mutation — the three welds the audit found untested."""
    _, api, _, log = _wire(tmp_path, monkeypatch)
    fn = getattr(server, tool_name)

    out = fn(confirm=True, **kwargs)

    # weld 1: return shape is the EXECUTED shape, never "plan"
    assert out["status"] == expected_status
    assert out["status"] != "plan"

    # weld 2: the fake captured the underlying call at the expected verb + path, with the
    # EXACT forwarded payload (full dict equality — an accidental extra field now fails).
    calls = getattr(api, capture)
    assert calls, f"{tool_name} confirm=True never reached api.{capture}"
    call_path, call_data = calls[-1]
    assert call_path == path
    assert call_data == data_exact

    # weld 3: ledger structural asserts — never exact prose
    entry = _confirmed_entry(log, tool_name, expected_status)
    assert entry["mutation"] is True
    assert entry["detail"]["confirmed"] is True


# ---------------------------------------------------------------------------
# pve_guest_migrate — unique weld: `online` forwards to a DIFFERENT body key depending on
# guest kind (QEMU 'online'=live migration; LXC 'restart'=stop→move→start, real downtime).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind,online,data_exact",
    [
        # guest_migrate(): online=False skips the online/restart block entirely for either kind.
        pytest.param("lxc", False, {"target": "node2"}, id="migrate_lxc_offline_no_online_or_restart"),
        # LXC has no live-migration path -> online=True sends 'restart' (real downtime).
        pytest.param("lxc", True, {"target": "node2", "restart": 1}, id="migrate_lxc_online_sends_restart"),
        # QEMU online=True sends 'online' (live migration).
        pytest.param("qemu", True, {"target": "node2", "online": 1}, id="migrate_qemu_online_sends_online"),
    ],
)
def test_guest_migrate_confirm_forwards_online_param_by_kind_and_records(
    tmp_path, monkeypatch, kind, online, data_exact,
):
    """confirm=True on pve_guest_migrate reaches api._post with the target always present, and
    with the online/restart flag forwarded to the RIGHT key for the guest kind — LXC has no
    live-migration path (online=True means a restart migration, real downtime), QEMU does."""
    _, api, _, log = _wire(tmp_path, monkeypatch)

    out = server.pve_guest_migrate(vmid="500", target="node2", kind=kind, online=online, confirm=True)

    assert out["status"] == "submitted"
    assert out["status"] != "plan"

    assert api.posts, "pve_guest_migrate confirm=True never reached api._post"
    call_path, call_data = api.posts[-1]
    assert call_path == f"/nodes/pve/{kind}/500/migrate"
    # exact: only 'target' plus (kind-dependent) at most one of online/restart — never both.
    assert call_data == data_exact

    entry = _confirmed_entry(log, "pve_guest_migrate", "submitted")
    assert entry["mutation"] is True
    assert entry["detail"]["confirmed"] is True


def test_guest_migrate_confirm_forwards_local_disk_options_in_wire_form(tmp_path, monkeypatch):
    """The local-disk knobs reach api._post under PVE's own (hyphenated) names, next to online."""
    _, api, _, log = _wire(tmp_path, monkeypatch)

    out = server.pve_guest_migrate(vmid="500", target="node2", kind="qemu", online=True,
                                   with_local_disks=True, targetstorage="local-lvm:fast",
                                   bwlimit=204800, migration_type="insecure", confirm=True)

    assert out["status"] == "submitted"
    assert api.posts[-1] == ("/nodes/pve/qemu/500/migrate", {
        "target": "node2", "online": 1, "with-local-disks": 1, "targetstorage": "local-lvm:fast",
        "bwlimit": 204800, "migration_type": "insecure",
    })
    assert _confirmed_entry(log, "pve_guest_migrate", "submitted")["detail"]["confirmed"] is True


def test_guest_migrate_plan_with_local_disks_posts_nothing(tmp_path, monkeypatch):
    _, api, _, _ = _wire(tmp_path, monkeypatch)

    out = server.pve_guest_migrate(vmid="500", target="node2", kind="qemu", online=True,
                                   with_local_disks=True)

    assert out["status"] == "plan"
    assert "with-local-disks=1" in out["change"]
    assert api.posts == []


# ---------------------------------------------------------------------------
# pve_node_hosts_set / pve_node_dns_set / pve_node_startall — typed-method captures (pve_node.py
# calls api.node_hosts_set/node_dns_set/node_startall directly, not through the generic verbs).
# ---------------------------------------------------------------------------


def test_node_hosts_set_confirm_executes_forwards_and_records(tmp_path, monkeypatch):
    _, api, _, log = _wire(tmp_path, monkeypatch)

    out = server.pve_node_hosts_set(
        data="127.0.0.1 localhost\n", digest="hosts-digest-1", confirm=True,
    )

    assert out["status"] == "ok"
    assert out["status"] != "plan"

    assert api.node_hosts_sets, "pve_node_hosts_set confirm=True never reached api.node_hosts_set"
    # exact: the wrapper calls api.node_hosts_set(data, node, digest) positionally — full tuple.
    assert api.node_hosts_sets[-1] == ("127.0.0.1 localhost\n", None, "hosts-digest-1")

    entry = _confirmed_entry(log, "pve_node_hosts_set", "ok")
    assert entry["mutation"] is True
    assert entry["detail"]["confirmed"] is True


def test_node_dns_set_confirm_executes_forwards_and_records(tmp_path, monkeypatch):
    _, api, _, log = _wire(tmp_path, monkeypatch)

    out = server.pve_node_dns_set(search="example.test", dns1="9.9.9.9", confirm=True)

    assert out["status"] == "ok"
    assert out["status"] != "plan"

    assert api.node_dns_sets, "pve_node_dns_set confirm=True never reached api.node_dns_set"
    # exact: the wrapper calls api.node_dns_set(node, search, dns1, dns2, dns3) positionally —
    # node/dns2/dns3 all default None here.
    assert api.node_dns_sets[-1] == (None, "example.test", "9.9.9.9", None, None)

    entry = _confirmed_entry(log, "pve_node_dns_set", "ok")
    assert entry["mutation"] is True
    assert entry["detail"]["confirmed"] is True


def test_node_startall_confirm_executes_forwards_vms_and_records(tmp_path, monkeypatch):
    _, api, _, log = _wire(tmp_path, monkeypatch)

    out = server.pve_node_startall(vms="100,101", confirm=True)

    assert out["status"] == "submitted"
    assert out["status"] != "plan"

    assert api.node_startalls, "pve_node_startall confirm=True never reached api.node_startall"
    # exact: the wrapper calls api.node_startall(node, vms) positionally — node defaults None.
    assert api.node_startalls[-1] == (None, "100,101")

    entry = _confirmed_entry(log, "pve_node_startall", "submitted")
    assert entry["mutation"] is True
    assert entry["detail"]["confirmed"] is True
    assert entry["detail"]["vms"] == "100,101"


def test_node_startall_confirm_sync_reports_ok_not_submitted(tmp_path, monkeypatch):
    """node_startall() may return None (backends.py's own documented contract: "Returns a task
    UPID or None") rather than a task UPID for a synchronous, already-finished start -- a fixed
    outcome="submitted" would then falsely claim an in-flight task in BOTH the envelope status
    and the ledger's own record."""
    _, api, _, log = _wire(tmp_path, monkeypatch)
    monkeypatch.setattr(api, "node_startall", lambda node=None, vms=None: None)

    out = server.pve_node_startall(confirm=True)

    assert out["status"] == "ok"
    assert out["status"] != "submitted"
    assert out["result"] is None

    entry = _confirmed_entry(log, "pve_node_startall", "ok")
    assert entry["mutation"] is True
    assert entry["detail"]["confirmed"] is True


def test_node_stopall_confirm_executes_forwards_vms_and_records(tmp_path, monkeypatch):
    _, api, _, log = _wire(tmp_path, monkeypatch)

    out = server.pve_node_stopall(vms="100,101", confirm=True)

    assert out["status"] == "submitted"
    assert out["status"] != "plan"

    assert api.node_stopalls, "pve_node_stopall confirm=True never reached api.node_stopall"
    # exact: the wrapper calls api.node_stopall(node, vms) positionally — node defaults None.
    assert api.node_stopalls[-1] == (None, "100,101")

    entry = _confirmed_entry(log, "pve_node_stopall", "submitted")
    assert entry["mutation"] is True
    assert entry["detail"]["confirmed"] is True
    assert entry["detail"]["vms"] == "100,101"


def test_node_stopall_confirm_sync_reports_ok_not_submitted(tmp_path, monkeypatch):
    """Same honesty fix as node_startall above -- node_stopall() may also return None."""
    _, api, _, log = _wire(tmp_path, monkeypatch)
    monkeypatch.setattr(api, "node_stopall", lambda node=None, vms=None: None)

    out = server.pve_node_stopall(confirm=True)

    assert out["status"] == "ok"
    assert out["status"] != "submitted"
    assert out["result"] is None

    entry = _confirmed_entry(log, "pve_node_stopall", "ok")
    assert entry["mutation"] is True
    assert entry["detail"]["confirmed"] is True


def test_node_migrateall_confirm_executes_forwards_target_and_records(tmp_path, monkeypatch):
    _, api, _, log = _wire(tmp_path, monkeypatch)

    out = server.pve_node_migrateall(target="pve2", vms="100,101", confirm=True)

    assert out["status"] == "submitted"
    assert out["status"] != "plan"

    assert api.node_migratealls, (
        "pve_node_migrateall confirm=True never reached api.node_migrateall"
    )
    # exact: api.node_migrateall(target, node, vms, maxworkers) positionally — node/maxworkers
    # both default None here.
    assert api.node_migratealls[-1] == ("pve2", None, "100,101", None)

    entry = _confirmed_entry(log, "pve_node_migrateall", "submitted")
    assert entry["mutation"] is True
    assert entry["detail"]["confirmed"] is True
    assert entry["detail"]["target"] == "pve2"


def test_node_migrateall_confirm_sync_reports_ok_not_submitted(tmp_path, monkeypatch):
    """Same honesty fix as node_startall/node_stopall above -- node_migrateall() may also
    return None."""
    _, api, _, log = _wire(tmp_path, monkeypatch)
    monkeypatch.setattr(
        api, "node_migrateall",
        lambda target, node=None, vms=None, maxworkers=None: None,
    )

    out = server.pve_node_migrateall(target="pve2", confirm=True)

    assert out["status"] == "ok"
    assert out["status"] != "submitted"
    assert out["result"] is None

    entry = _confirmed_entry(log, "pve_node_migrateall", "ok")
    assert entry["mutation"] is True
    assert entry["detail"]["confirmed"] is True


# ---------------------------------------------------------------------------
# pve_node_storage_backend_create — unique weld: kwarg filtering + ledger detail. The raw API
# call receives every kwarg verbatim (including an explicit None); the ledger detail's `extra`
# only carries the non-None subset (pve_node.py:171).
# ---------------------------------------------------------------------------


def test_node_storage_backend_create_confirm_filters_kwargs_into_ledger_detail(tmp_path, monkeypatch):
    """confirm=True reaches api.node_storage_backend_create with devices/raidlevel forwarded
    AND the caller's explicit ashift=None passed through unfiltered — but the ledger `detail`
    (built from `extra = {k: v for k, v in kw.items() if v is not None}`) must NOT carry the
    None-valued ashift, only the non-None backend/name/devices/raidlevel."""
    _, api, _, log = _wire(tmp_path, monkeypatch)

    out = server.pve_node_storage_backend_create(
        backend="zfs", name="tank", devices="/dev/sdb,/dev/sdc",
        raidlevel="raidz", ashift=None, confirm=True,
    )

    assert out["status"] == "submitted"
    assert out["status"] != "plan"

    assert api.node_storage_backend_creates, (
        "pve_node_storage_backend_create confirm=True never reached "
        "api.node_storage_backend_create"
    )
    call_backend, call_name, call_node, call_kw = api.node_storage_backend_creates[-1]
    assert call_backend == "zfs"
    assert call_name == "tank"
    # exact: the raw API call receives the kwargs UNFILTERED — including the explicit None —
    # via **({"devices": devices} if devices else {}), **kw; nothing else is added.
    assert call_kw == {"devices": "/dev/sdb,/dev/sdc", "raidlevel": "raidz", "ashift": None}

    entry = _confirmed_entry(log, "pve_node_storage_backend_create", "submitted")
    assert entry["mutation"] is True
    assert entry["detail"]["confirmed"] is True
    # ledger detail: kwarg filtering — only the non-None extras land here.
    assert entry["detail"]["backend"] == "zfs"
    assert entry["detail"]["name"] == "tank"
    assert entry["detail"]["devices"] == "/dev/sdb,/dev/sdc"
    assert entry["detail"]["raidlevel"] == "raidz"
    assert "ashift" not in entry["detail"]
