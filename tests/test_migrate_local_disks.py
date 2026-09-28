"""pve_guest_migrate with local disks — with-local-disks / targetstorage / bwlimit / migration_type.

Fully mocked, no live Proxmox. Three layers:
- migrate_options: wire names per kind, and refusals for what a kind does not take;
- guest_migrate / plan_migrate: the knobs reach the POST body, and the PLAN refuses the same input;
- compute_migrate_blast: a local disk is a FAIL without with_local_disks and a named, sized COPY
  (MEDIUM) with it; the copy's landing storage must itself exist on the target.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from proximo.backends import ProximoError
from proximo.blast import _disk_size_bytes, compute_migrate_blast
from proximo.cluster_ops import guest_migrate, migrate_options, parse_storage_map, plan_migrate
from proximo.planning import RISK_HIGH, RISK_MEDIUM


def _meta(shared=True, nodes=None):
    return {"shared": shared, "nodes": nodes}


class _LocalDiskApi:
    """A running QEMU guest whose disks sit on local LVM; records the POST."""

    def __init__(self, config=None, storage=None):
        self.config = SimpleNamespace(node="pve1")
        self._cfg = config if config is not None else {
            "scsi0": "local-lvm:vm-300-disk-0,iothread=1,size=32G",
            "scsi1": "local-lvm:vm-300-disk-1,size=512M",
        }
        self._storage = storage if storage is not None else [
            {"storage": "local-lvm", "type": "lvm", "shared": 0},
            {"storage": "fast", "type": "lvmthin", "shared": 0, "nodes": "pve1"},
        ]
        self.posts: list[tuple[str, dict]] = []

    def guest_status(self, vmid, kind="lxc", node=None):
        return {"status": "running", "name": "web1", "uptime": 500}

    def _get(self, path):
        if path.endswith("/config"):
            return self._cfg
        if path == "/storage":
            return self._storage
        return {}

    def _post(self, path, data=None):
        self.posts.append((path, data or {}))
        return "UPID:pve1:00001:0:0:0:qmigrate:300:root@pam:"


# ---------------------------------------------------------------------------
# migrate_options — wire form and refusals
# ---------------------------------------------------------------------------

def test_options_default_to_nothing():
    assert migrate_options("qemu") == {}
    assert migrate_options("lxc") == {}


def test_options_qemu_wire_names():
    assert migrate_options("qemu", True, "1", 1024, "secure") == {
        "with-local-disks": 1, "targetstorage": "1", "bwlimit": 1024, "migration_type": "secure",
    }


def test_options_lxc_targetstorage_is_hyphenated():
    assert migrate_options("lxc", targetstorage="local-lvm", bwlimit=0) == {
        "target-storage": "local-lvm", "bwlimit": 0,
    }


def test_options_refuse_with_local_disks_for_lxc():
    with pytest.raises(ProximoError, match="QEMU"):
        migrate_options("lxc", with_local_disks=True)


def test_options_refuse_migration_type_for_lxc():
    with pytest.raises(ProximoError, match="QEMU"):
        migrate_options("lxc", migration_type="insecure")


@pytest.mark.parametrize("value", ["plaintext", "", "SECURE"])
def test_options_refuse_unknown_migration_type(value):
    with pytest.raises(ProximoError, match="migration_type"):
        migrate_options("qemu", migration_type=value)


@pytest.mark.parametrize("value", [-1, True, "fast", []])
def test_options_refuse_bad_bwlimit(value):
    with pytest.raises(ProximoError, match="bwlimit"):
        migrate_options("qemu", bwlimit=value)


@pytest.mark.parametrize("value", ["1", "local-lvm", "a:b", "a:b,c:d", "a:b,fallback", "ceph.pool_1:x-y"])
def test_options_accept_targetstorage_shapes(value):
    assert migrate_options("qemu", targetstorage=value)["targetstorage"] == value


@pytest.mark.parametrize("value", ["", "a:b:c", "a,b", "1a", "a:", ":b", "a b", "a;rm", "a:b,,c:d"])
def test_options_refuse_bad_targetstorage(value):
    with pytest.raises(ProximoError, match="targetstorage"):
        migrate_options("qemu", targetstorage=value)


def test_parse_storage_map():
    assert parse_storage_map(None) == (None, {})
    assert parse_storage_map("1") == (None, {})
    assert parse_storage_map("fast") == ("fast", {})
    assert parse_storage_map("a:b,fallback,c:d") == ("fallback", {"a": "b", "c": "d"})


# ---------------------------------------------------------------------------
# guest_migrate / plan_migrate
# ---------------------------------------------------------------------------

def test_guest_migrate_posts_local_disk_options():
    api = _LocalDiskApi()
    guest_migrate(api, "300", "pve2", kind="qemu", online=True, with_local_disks=True, bwlimit=102400)
    assert api.posts == [("/nodes/pve1/qemu/300/migrate", {
        "target": "pve2", "with-local-disks": 1, "bwlimit": 102400, "online": 1,
    })]


def test_guest_migrate_refuses_before_posting():
    api = _LocalDiskApi()
    with pytest.raises(ProximoError):
        guest_migrate(api, "300", "pve2", kind="lxc", with_local_disks=True)
    assert api.posts == []


def test_plan_refuses_what_execute_refuses():
    with pytest.raises(ProximoError, match="targetstorage"):
        plan_migrate(_LocalDiskApi(), "300", "pve2", kind="qemu", targetstorage="a:b:c")


def test_plan_live_local_disk_without_flag_is_high_and_names_the_flag():
    p = plan_migrate(_LocalDiskApi(), "300", "pve2", kind="qemu", online=True)
    assert p.risk == RISK_HIGH
    assert any("with_local_disks=True" in line for line in p.blast_radius)


def test_plan_live_local_disk_with_flag_is_medium_and_sizes_the_copy():
    p = plan_migrate(_LocalDiskApi(), "300", "pve2", kind="qemu", online=True, with_local_disks=True)
    assert p.risk == RISK_MEDIUM
    copies = [a for a in p.affected if a["state"] == "copy"]
    assert {a["slot"] for a in copies} == {"scsi0", "scsi1"}
    assert {a["target_storage"] for a in copies} == {"local-lvm"}
    text = "\n".join(p.blast_radius)
    assert "32.0 GiB" in text and "512.0 MiB" in text and "totalling 32.5 GiB" in text
    assert "with-local-disks=1" in p.change


def test_plan_targetstorage_unavailable_on_target_fails():
    p = plan_migrate(_LocalDiskApi(), "300", "pve2", kind="qemu", online=True,
                     with_local_disks=True, targetstorage="fast")
    assert p.risk == RISK_HIGH
    assert all(a["state"] == "unavailable" for a in p.affected)
    assert any("'fast'" in line and "FAILS" in line for line in p.blast_radius)


def test_plan_targetstorage_unknown_storage_is_incomplete():
    p = plan_migrate(_LocalDiskApi(), "300", "pve2", kind="qemu", online=True,
                     with_local_disks=True, targetstorage="nowhere")
    assert p.complete is False
    assert p.risk == RISK_HIGH


def test_plan_bwlimit_and_insecure_are_disclosed():
    p = plan_migrate(_LocalDiskApi(), "300", "pve2", kind="qemu", online=True,
                     with_local_disks=True, bwlimit=204800, migration_type="insecure")
    text = "\n".join(p.blast_radius)
    assert "204800 KiB/s (~200 MiB/s)" in text
    assert "UNENCRYPTED" in text
    assert any("insecure" in r for r in p.risk_reasons)


def test_plan_live_blast_no_longer_claims_shared_storage_is_required():
    api = _LocalDiskApi(config={"scsi0": "ceph:vm-300-disk-0,size=8G"},
                        storage=[{"storage": "ceph", "shared": 1}])
    p = plan_migrate(api, "300", "pve2", kind="qemu", online=True)
    assert p.risk == RISK_MEDIUM
    assert not any("requires shared storage" in line for line in p.blast_radius + p.risk_reasons)


# ---------------------------------------------------------------------------
# compute_migrate_blast — the pure classifier
# ---------------------------------------------------------------------------

def test_blast_copy_is_medium_not_high():
    r = compute_migrate_blast("pveB", {"scsi0": "local-lvm"}, {"local-lvm": _meta(shared=False)},
                              config_complete=True, online=True, kind="qemu", with_local_disks=True)
    assert r.max_severity == "medium"
    assert r.affected[0]["state"] == "copy"


def test_blast_copy_does_not_hide_a_raw_disk():
    r = compute_migrate_blast("pveB", {"scsi0": "local-lvm"}, {"local-lvm": _meta(shared=False)},
                              config_complete=True, online=True, kind="qemu", raw_slots=["scsi1"],
                              with_local_disks=True)
    assert r.max_severity == "high"


def test_blast_shared_disk_is_not_copied_even_with_the_flag():
    r = compute_migrate_blast("pveB", {"scsi0": "ceph"}, {"ceph": _meta(shared=True)},
                              config_complete=True, online=True, kind="qemu", with_local_disks=True,
                              storage_map=("fast", {}))
    assert r.affected == []
    assert r.max_severity == "none"


def test_blast_storage_map_pair_wins_over_default():
    r = compute_migrate_blast("pveB", {"scsi0": "a", "scsi1": "b"},
                              {"a": _meta(False), "b": _meta(False), "x": _meta(False), "y": _meta(False)},
                              config_complete=True, online=False, kind="qemu", with_local_disks=True,
                              storage_map=("y", {"a": "x"}))
    assert {a["slot"]: a["target_storage"] for a in r.affected} == {"scsi0": "x", "scsi1": "y"}


def test_blast_total_is_withheld_when_a_size_is_missing():
    r = compute_migrate_blast("pveB", {"scsi0": "a", "scsi1": "a"}, {"a": _meta(False)},
                              config_complete=True, online=False, kind="qemu", with_local_disks=True,
                              disk_sizes={"scsi0": 1024 ** 3})
    text = "\n".join(r.summary_lines)
    assert "totalling" not in text
    assert "size not in config" in text


@pytest.mark.parametrize("value,expected", [
    ("vg:vm-1-disk-0,size=32G", 32 * 1024 ** 3),
    ("vg:vm-1-disk-0,size=512M,iothread=1", 512 * 1024 ** 2),
    ("vg:vm-1-disk-0,iothread=1", None),
    ("vg:vm-1-disk-0,backup_size=8G", None),
])
def test_disk_size_bytes(value, expected):
    assert _disk_size_bytes(value) == expected



def test_blast_lxc_local_volume_is_a_copy_without_a_flag():
    """pct migrate moves local volumes itself: an LXC local disk is a COPY, not a FAIL."""
    r = compute_migrate_blast("pveB", {"rootfs": "local-lvm"}, {"local-lvm": _meta(shared=False)},
                              config_complete=True, online=True, kind="lxc",
                              disk_sizes={"rootfs": 8 * 1024 ** 3})
    assert r.max_severity == "medium"
    assert r.affected[0]["state"] == "copy"
    assert "LXC storage migration" in r.affected[0]["effect"]
    assert not any("FAILS" in line for line in r.summary_lines)


def test_blast_lxc_target_storage_must_exist_on_target():
    r = compute_migrate_blast("pveB", {"rootfs": "local-lvm"},
                              {"local-lvm": _meta(shared=False), "fast": _meta(False, nodes={"pveA"})},
                              config_complete=True, online=False, kind="lxc", storage_map=("fast", {}))
    assert r.max_severity == "high"
    assert r.affected[0]["state"] == "unavailable"


def test_plan_lxc_restart_migration_with_local_rootfs_names_the_copy():
    api = _LocalDiskApi(config={"rootfs": "local-lvm:vm-200-disk-0,size=8G"})
    p = plan_migrate(api, "200", "pve2", kind="lxc", online=True, targetstorage="local-lvm")
    assert p.risk == RISK_HIGH  # restart migration = real downtime, whatever the disks do
    assert [a["state"] for a in p.affected] == ["copy"]
    assert "target-storage=local-lvm" in p.change
