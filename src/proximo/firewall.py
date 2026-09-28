"""FIREWALL pillar — cluster / node / guest firewall management.

Covers the three PVE firewall scopes:
  cluster  → /cluster/firewall
  node     → /nodes/{node}/firewall
  guest    → /nodes/{node}/{kind}/{vmid}/firewall

Every mutating function is PLAN-gated at the server layer (no plan → no mutation).
Plans are HONEST: they surface the rule, its position, and its scope before any edit.

Hard rules mirrored from the codebase:
- Firewall edits are SILENT-MISTAKE-PRONE: a misplaced ACCEPT/DROP rule or toggling
  the firewall off can instantly lock you out of the host (SSH/8006). Plans always
  surface scope + position + the full rule so the caller sees exactly what changes.
- No UNDO: PVE firewall config lives in cluster config files, not in guest disk
  snapshots. _auto_undo / snapshot rollback does NOT revert firewall changes.
  Never claim UNDO; the only revert is the inverse op (re-add / re-enable / etc.).
- Firewall writes are assumed SYNCHRONOUS (return null data, not a task UPID).
  The "submitted" outcome pattern does NOT apply here. Flag as shape risk.
- RISK_HIGH for firewall_set_enabled regardless of direction: enabling may instantly
  drop traffic if rules are absent/wrong (default-DROP without ACCEPT for 8006/22);
  disabling strips all firewall protection.
- rule add/remove/update are RISK_MEDIUM floor with a prominent connectivity/lockout
  note. Absence of HIGH is NOT a safety signal (rules are curated heuristics).
- No self-gating: the server layer adds confirm-gating + audit; these functions are
  pure ops.

Endpoint shape / backend dependency notes (flag for live smoke):
- All PUT endpoints (rule_update, set_enabled) call api._put() on ApiBackend.
- Firewall writes assumed synchronous (no UPID). If live PVE returns a UPID, change
  outcome="ok" → outcome="submitted" in the server layer and adjust return shape.
- firewall_rule_remove and firewall_rule_update re-read rules at op time and pass the
  PVE digest in the DELETE params / PUT body for optimistic-locking. Shape risk: it is
  uncertain whether GET …/firewall/rules actually surfaces a top-level 'digest' field on
  all PVE versions. If the live endpoint does not return a digest, these ops will raise
  ProximoError rather than silently proceeding without a lock. Confirm at live smoke.
"""

from __future__ import annotations

import ipaddress
import re

from . import blast as blast_engine
from .backends import ProximoError, _check_kind, _check_node, _check_vmid
from .cluster_ops import resolve_guest
from .planning import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Plan, _max_risk

# Firewall comment/freetext fields are stored in PVE's line-based config files (cluster.fw, guest .fw).
# A newline or other control character can corrupt that config — the SAME threat class the access
# modules guard with their own _check_freetext (deliberate per-module duplication of the tiny helper,
# matching that pattern). 2026-07-10 audit L9: the guard was present in access_* but absent here.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _check_freetext(value: str, field: str) -> str:
    """Reject control characters/newlines in a firewall freetext field (raw value, no strip)."""
    s = str(value)
    if _CONTROL_RE.search(s):
        raise ProximoError(
            f"invalid {field}: {value!r} — control characters and newlines are not allowed"
        )
    return s

# ---------------------------------------------------------------------------
# Module-level validators
# ---------------------------------------------------------------------------

_VALID_SCOPES = frozenset({"cluster", "node", "guest"})
_VALID_ACTIONS = frozenset({"ACCEPT", "DROP", "REJECT"})
_VALID_DIRECTIONS = frozenset({"in", "out"})


def _check_scope(scope: str) -> str:
    if scope not in _VALID_SCOPES:
        raise ProximoError(
            f"invalid scope: {scope!r} (expected one of {sorted(_VALID_SCOPES)})"
        )
    return scope


def _check_alias_ipset_scope(scope: str) -> str:
    """Aliases and IP sets exist only at cluster and guest scope.

    Schema-verified 2026-07-06 (pve-docs api-viewer): node firewall exposes only
    options/rules/log — there are NO /nodes/{node}/firewall/aliases or .../ipset
    endpoints, so node scope must fail-fast here instead of 501ing against PVE.
    """
    _check_scope(scope)
    if scope == "node":
        raise ProximoError(
            "firewall aliases/ipsets do not exist at node scope in the PVE API "
            "(node firewall has only options/rules/log) — use scope='cluster' "
            "or scope='guest'"
        )
    return scope


def _check_pos(pos) -> int:
    """Firewall rule position — must be a non-negative integer (it goes into the URL path)."""
    try:
        n = int(pos)
    except (TypeError, ValueError) as exc:
        raise ProximoError(f"invalid rule position: {pos!r} (must be a non-negative integer)") from exc
    if n < 0:
        raise ProximoError(f"invalid rule position: {pos!r} (must be >= 0)")
    return n


def _check_action(action: str) -> str:
    a = str(action).upper()
    if a not in _VALID_ACTIONS:
        raise ProximoError(
            f"invalid firewall action: {action!r} (expected one of {sorted(_VALID_ACTIONS)})"
        )
    return a


def _check_direction(direction: str) -> str:
    d = str(direction).lower()
    if d not in _VALID_DIRECTIONS:
        raise ProximoError(
            f"invalid rule direction: {direction!r} (expected 'in' or 'out')"
        )
    return d


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def _fw_base(
    api,
    scope: str,
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
) -> str:
    """Build the base firewall URL for the given scope.

    cluster → /cluster/firewall
    node    → /nodes/{node}/firewall
    guest   → /nodes/{node}/{kind}/{vmid}/firewall
    """
    _check_scope(scope)
    if scope == "cluster":
        return "/cluster/firewall"
    _check_node(node)
    if scope == "node":
        return f"/nodes/{node or api.config.node}/firewall"
    # guest scope
    if vmid is None:
        raise ProximoError("vmid is required for guest scope")
    vmid = _check_vmid(vmid)
    kind, node = resolve_guest(api, vmid, kind, node)
    kind = _check_kind(kind)
    return f"/nodes/{node or api.config.node}/{kind}/{vmid}/firewall"


# ---------------------------------------------------------------------------
# READ operations (no confirm-gate; audited at server layer)
# ---------------------------------------------------------------------------

def firewall_rules_list(
    api,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
) -> list[dict]:
    """List all firewall rules for the given scope.

    GET /cluster/firewall/rules
    GET /nodes/{node}/firewall/rules
    GET /nodes/{node}/{kind}/{vmid}/firewall/rules

    Returns a list of rule dicts: {pos, action, type, enable, comment, …}.
    Reads are audited at the server layer (no confirm-gate needed).
    """
    base = _fw_base(api, scope, node, vmid, kind)
    return api._get(f"{base}/rules") or []


def firewall_options_get(
    api,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
) -> dict:
    """Get firewall options (enable flag, policy, log rate, …) for the given scope.

    GET /cluster/firewall/options
    GET /nodes/{node}/firewall/options
    GET /nodes/{node}/{kind}/{vmid}/firewall/options

    Returns a dict from PVE; fields vary by scope (e.g. 'enable', 'policy_in', 'policy_out').
    Reads are audited at the server layer (no confirm-gate needed).
    """
    base = _fw_base(api, scope, node, vmid, kind)
    return api._get(f"{base}/options") or {}


def security_groups_list(api) -> list[dict]:
    """List cluster-wide security groups.

    GET /cluster/firewall/groups

    Returns a list of group dicts: {group, comment, digest}.
    Cluster-scope only — node/guest scopes do not expose this endpoint.
    Reads are audited at the server layer (no confirm-gate needed).

    Shape risk: only cluster scope is assumed to expose this endpoint; node/guest
    may return 404. Confirm at live smoke.
    """
    return api._get("/cluster/firewall/groups") or []


def ipset_list(
    api,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
) -> list[dict]:
    """List IP sets for the given scope (cluster or guest — node scope has no ipset).

    GET /cluster/firewall/ipset
    GET /nodes/{node}/{kind}/{vmid}/firewall/ipset

    Returns a list of IPSet dicts.

    Schema-verified 2026-07-06 (pve-docs api-viewer): cluster + guest scopes only;
    node firewall exposes only options/rules/log.
    """
    _check_alias_ipset_scope(scope)
    base = _fw_base(api, scope, node, vmid, kind)
    return api._get(f"{base}/ipset") or []


# ---------------------------------------------------------------------------
# MUTATION operations — PLAN-gated + audited at the server layer
# ---------------------------------------------------------------------------

def firewall_rule_add(
    api,
    action: str,
    direction: str = "in",
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
    source: str | None = None,
    dest: str | None = None,
    proto: str | None = None,
    dport: str | None = None,
    sport: str | None = None,
    comment: str | None = None,
    enable: bool = True,
) -> None:
    """Add a new firewall rule. PVE inserts it at the TOP (position 0) and shifts existing rules
    down — `pos` is ignored on create — so the new rule takes PRECEDENCE (matching is first-match,
    top-down). A new DROP can therefore shadow a lower ACCEPT (e.g. for SSH/8006) and cause a lockout.

    POST /cluster/firewall/rules
    POST /nodes/{node}/firewall/rules
    POST /nodes/{node}/{kind}/{vmid}/firewall/rules

    Returns None (synchronous; PVE returns null data on success).

    MUTATION — confirm-gated + audited at the server layer.
    No UNDO: firewall config is not in guest disk snapshots; revert manually.

    Shape risk: PVE uses 'type' internally but callers pass action (ACCEPT/DROP/REJECT).
    The 'type' field (in/out/group) is the direction/type parameter. Confirm param
    names match live API at smoke time.
    """
    action = _check_action(action)
    direction = _check_direction(direction)
    base = _fw_base(api, scope, node, vmid, kind)
    data: dict = {
        "action": action,
        "type": direction,
        "enable": 1 if enable else 0,
    }
    if source is not None:
        data["source"] = source
    if dest is not None:
        data["dest"] = dest
    if proto is not None:
        data["proto"] = proto
    if dport is not None:
        data["dport"] = dport
    if sport is not None:
        data["sport"] = sport
    if comment is not None:
        data["comment"] = _check_freetext(comment, "comment")
    # MUTATION — confirm-gated + audited at the server layer.
    return api._post(f"{base}/rules", data)


def _fetch_rules_digest(api, base: str, op_name: str) -> str:
    """Re-read rules at op time to obtain the PVE digest for optimistic-locking.
    Shape risk: whether GET …/firewall/rules surfaces a 'digest' field is uncertain until
    live smoke. If no digest is available, abort with ProximoError rather than silently
    proceeding without a lock (fail-closed). Shared by firewall_rule_remove/update."""
    rules = api._get(f"{base}/rules") or []
    digest = next((r.get("digest") for r in rules if r.get("digest")), None)
    if digest is None:
        raise ProximoError(
            f"{op_name}: could not obtain a digest from {base}/rules — "
            "aborting to prevent undetected concurrent modification (shape risk: confirm "
            "at live smoke whether this PVE version returns a digest on the rules list)"
        )
    return digest


def firewall_rule_remove(
    api,
    pos: int,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
    digest: str | None = None,
) -> None:
    """Delete a firewall rule by position.

    DELETE /cluster/firewall/rules/{pos}
    DELETE /nodes/{node}/firewall/rules/{pos}
    DELETE /nodes/{node}/{kind}/{vmid}/firewall/rules/{pos}

    Returns None (synchronous; PVE returns null on success).

    MUTATION — confirm-gated + audited at the server layer.
    No UNDO: firewall config is not in guest disk snapshots; revert by re-adding.

    WARNING: positions shift after inserts/deletes. Always verify the current rule
    list before removing by position to avoid removing the wrong rule.

    digest: caller-pinned PVE optimistic-lock digest (read from the dry-run PLAN). When given it is
    used verbatim so PVE rejects the delete if the rule list changed since the preview — closing the
    plan->confirm window. When None, falls back to an op-time re-read (which cannot detect that
    window; 2026-07-10 audit M1).
    """
    pos = _check_pos(pos)
    base = _fw_base(api, scope, node, vmid, kind)
    effective_digest = digest if digest is not None else _fetch_rules_digest(api, base, "firewall_rule_remove")
    # MUTATION — confirm-gated + audited at the server layer.
    return api._delete(f"{base}/rules/{pos}", {"digest": effective_digest})


def firewall_rule_update(
    api,
    pos: int,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
    action: str | None = None,
    direction: str | None = None,
    source: str | None = None,
    dest: str | None = None,
    proto: str | None = None,
    dport: str | None = None,
    sport: str | None = None,
    comment: str | None = None,
    enable: bool | None = None,
    digest: str | None = None,
) -> None:
    """Update an existing firewall rule at position `pos`.

    PUT /cluster/firewall/rules/{pos}
    PUT /nodes/{node}/firewall/rules/{pos}
    PUT /nodes/{node}/{kind}/{vmid}/firewall/rules/{pos}

    Returns None (synchronous; PVE returns null on success).

    MUTATION — confirm-gated + audited at the server layer.
    No UNDO: firewall config is not in guest disk snapshots.

    WARNING: positions shift after inserts/deletes. Verify the current rule list
    before updating by position to avoid updating the wrong rule.

    Backend dependency: calls api._put() — this method MUST be added to ApiBackend
    before live use (backends.py only has _get/_post/_delete). Add one line mirroring
    _delete to unblock. Tests fake _put on the mock.
    """
    pos = _check_pos(pos)
    base = _fw_base(api, scope, node, vmid, kind)
    data: dict = {}
    if action is not None:
        data["action"] = _check_action(action)
    if direction is not None:
        data["type"] = _check_direction(direction)
    if source is not None:
        data["source"] = source
    if dest is not None:
        data["dest"] = dest
    if proto is not None:
        data["proto"] = proto
    if dport is not None:
        data["dport"] = dport
    if sport is not None:
        data["sport"] = sport
    if comment is not None:
        data["comment"] = _check_freetext(comment, "comment")
    if enable is not None:
        data["enable"] = 1 if enable else 0
    if not data:
        raise ProximoError("firewall_rule_update requires at least one field to update")
    # The empty-data guard runs BEFORE we fetch the digest so that guard stays reliable.
    # A caller-pinned digest (from the dry-run PLAN) is used verbatim so PVE rejects a plan->confirm
    # concurrent change; None falls back to an op-time re-read (2026-07-10 audit M1).
    data["digest"] = digest if digest is not None else _fetch_rules_digest(api, base, "firewall_rule_update")
    # MUTATION — confirm-gated + audited at the server layer.
    return api._put(f"{base}/rules/{pos}", data)


def firewall_set_enabled(
    api,
    enabled: bool,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
) -> None:
    """Toggle the firewall on or off for the given scope.

    PUT /cluster/firewall/options    body: {enable: 0|1}
    PUT /nodes/{node}/firewall/options
    PUT /nodes/{node}/{kind}/{vmid}/firewall/options

    Returns None (synchronous; PVE returns null on success).

    MUTATION — confirm-gated + audited at the server layer.
    No UNDO: firewall config is not in guest disk snapshots.

    HIGH-RISK operation (both directions):
    - ENABLING: if no ACCEPT rules exist for SSH (22) or the PVE web UI (8006),
      the default-DROP policy can instantly lock you out of the host.
    - DISABLING: immediately strips all firewall protection from the scope.
    - Cluster scope is the master kill-switch for ALL nodes and guests.

    Backend dependency: calls api._put() — must be added to ApiBackend before live use.
    """
    base = _fw_base(api, scope, node, vmid, kind)
    data = {"enable": 1 if enabled else 0}
    # HIGH-RISK MUTATION — confirm-gated + audited at the server layer.
    return api._put(f"{base}/options", data)


# ---------------------------------------------------------------------------
# PLAN factories — pure functions (no I/O except where noted)
# ---------------------------------------------------------------------------

def _scope_label(scope: str, node: str | None, vmid: str | None, kind: str | None) -> str:
    """Human-readable scope string for blast_radius / change messages."""
    if scope == "cluster":
        return "cluster (all nodes and guests)"
    if scope == "node":
        return f"node/{node or 'default'}"
    return f"{kind or 'guest'}/{vmid}"


def _enable_flag(raw) -> bool:
    """Normalize a PVE rule 'enable' field (1/0, '1'/'0', True/False, or absent->1) to bool.
    Default ON: a rule with no explicit enable is active in PVE. An unparseable value is treated
    as ENABLED (active) — over-flag, never read a present-but-odd value as the inert 'staged' path."""
    if raw is None:
        return True
    if isinstance(raw, bool):
        return raw
    s = str(raw).strip()
    return s != "0"


def _removal_reach_lines(found: dict, reach) -> list[str]:
    """Frame a rule's REACH as the effect of REMOVING it: removing an ACCEPT CLOSES the access it
    permitted; removing a DROP/REJECT RE-PERMITS the traffic it blocked. A disabled (staged) rule
    has no live effect, so removing it changes nothing live."""
    action = str(found.get("action", "")).upper()
    enabled = _enable_flag(found.get("enable", 1))
    service = blast_engine._port_label(found.get("dport"), found.get("proto"))
    _, from_label = blast_engine._source_breadth(found.get("source"))
    if not enabled:
        return [
            f"this rule is currently DISABLED (staged) — removing it changes nothing live "
            f"(it was not permitting/blocking {service} from {from_label})",
        ]
    if action == "ACCEPT":
        return [
            f"removing this ACCEPT CLOSES inbound {service} from {from_label} — that access will "
            "no longer be permitted by this rule",
        ]
    # DROP / REJECT
    return [
        f"removing this {action} RE-PERMITS {service} from {from_label} — traffic this rule was "
        "blocking is no longer blocked by it (other rules / the default policy still apply)",
    ]


def _merged_post_update(found: dict, new_fields: dict) -> dict:
    """Resolve the POST-UPDATE rule fields for reach classification: new_fields layered over the
    stored rule. The stored DIRECTION lives under 'type'; new_fields carries it as 'direction' —
    so 'direction' wins when present, otherwise the stored 'type'. Other fields (action/source/
    dport/proto) use new-when-the-key-is-present, else the stored value. 'enable' is normalized."""
    return {
        "action": new_fields.get("action") or found.get("action", ""),
        "direction": new_fields.get("direction") or found.get("type", "in"),
        "source": new_fields["source"] if "source" in new_fields else found.get("source"),
        "dport": new_fields["dport"] if "dport" in new_fields else found.get("dport"),
        "proto": new_fields["proto"] if "proto" in new_fields else found.get("proto"),
        "enable": (_enable_flag(new_fields["enable"]) if "enable" in new_fields
                   else _enable_flag(found.get("enable", 1))),
    }


_RULE_SNAPSHOT_KEYS = (
    "pos", "action", "type", "source", "dest", "dport", "sport", "proto", "enable", "comment",
)


def _find_rule_at_pos(
    api, pos: int, scope: str, node: str | None, vmid: str | None, kind: str | None,
) -> tuple[dict | None, dict, str | None, str | None]:
    """One safe read of the rule list for plan_firewall_rule_remove/update: return
    (found_rule_or_None, current_snapshot_dict, check_error, digest). check_error is the raising
    exception's class name, or None if the read succeeded. digest is the PVE optimistic-lock digest
    from this read (or None), surfaced so the caller can PIN it on confirm — an op-time re-read always
    matches current config and cannot detect a plan->confirm concurrent change (2026-07-10 audit M1)."""
    try:
        rules = firewall_rules_list(api, scope, node, vmid, kind) or []
        found = next((r for r in rules if r.get("pos") == pos), None)
        current = {k: found[k] for k in _RULE_SNAPSHOT_KEYS if k in found} if found else {}
        digest = next((r.get("digest") for r in rules if r.get("digest")), None)
        return found, current, None, digest
    except Exception as e:
        return None, {}, type(e).__name__, None


def plan_firewall_rule_add(
    action: str,
    direction: str = "in",
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
    source: str | None = None,
    dest: str | None = None,
    dport: str | None = None,
    proto: str | None = None,
) -> Plan:
    """Preview adding a firewall rule. PURE — no API call needed.

    RISK_MEDIUM floor: a misplaced ACCEPT/DROP rule can affect connectivity without
    warning. The plan surfaces scope, direction, action, and key address/port fields
    so the caller can verify the rule before confirming.

    Note: the absence of HIGH is NOT a safety signal — rule classification is heuristic.
    A DROP on port 22 or 8006 can cause a lockout.
    """
    action = _check_action(action)
    direction = _check_direction(direction)
    _check_scope(scope)

    scope_label = _scope_label(scope, node, vmid, kind)
    rule_summary = f"action={action}, type={direction}"
    if source:
        rule_summary += f", source={source}"
    if dest:
        rule_summary += f", dest={dest}"
    if dport:
        rule_summary += f", dport={dport}"

    # Per-rule REACH — what this rule permits/blocks if it is the deciding match in an enforced,
    # default-DROP firewall. NOT "the cluster is exposed". rule_add has no enable param, so
    # enable=True (a staged add is over-flagged as active — the conservative direction, and the
    # loaded-gun warning still fires). `proto` is reflected in the service label (a udp rule is not
    # narrated as /tcp). The factory stays PURE — the reach engine reads no API.
    reach = blast_engine.compute_firewall_reach(action, direction, source, dport, proto, scope_label)

    return Plan(
        action="pve_firewall_rule_add",
        target=f"firewall/{scope}",
        change=f"add firewall rule on {scope_label}: {rule_summary}",
        current={},
        blast_radius=reach.summary_lines + [
            f"adds a firewall rule to {scope_label}: {rule_summary}",
            "PVE inserts this rule at the TOP (position 0) and shifts existing rules down — it takes "
            "PRECEDENCE over them (first-match, top-down); a new DROP can shadow a lower ACCEPT "
            "(e.g. for SSH/8006) and cause a lockout",
            "a misplaced DROP/REJECT can interrupt connectivity; a misplaced ACCEPT can open access",
            "no UNDO: firewall config is not in guest snapshots; revert by removing this rule",
        ],
        affected=reach.affected,
        risk=_max_risk(RISK_MEDIUM, reach.risk),
        risk_reasons=reach.risk_reasons + [
            "firewall rule changes affect network connectivity — silent-mistake-prone",
            "absence of HIGH is NOT a safety signal (heuristic only)",
        ],
        complete=reach.complete,
    )


def plan_firewall_rule_remove(
    api,
    pos: int,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
) -> Plan:
    """Preview removing a firewall rule at position `pos`.

    Reads firewall_rules_list (a safe read) to surface what rule is at the given
    position, so the caller sees exactly what will be removed.

    RISK_MEDIUM floor. Removing the wrong rule (e.g. the ACCEPT for SSH/8006) is
    a lockout. Plan discloses the rule at the given position.

    Note: positions SHIFT after every insert or delete. Always re-list rules and
    confirm the position before removing.
    """
    pos = _check_pos(pos)
    _check_scope(scope)

    scope_label = _scope_label(scope, node, vmid, kind)
    rule_desc = f"rule at position {pos}"

    found, current, check_error, digest = _find_rule_at_pos(api, pos, scope, node, vmid, kind)
    if found:
        rule_desc = (
            f"rule at pos={pos}: action={found.get('action', '?')}, "
            f"type={found.get('type', '?')}"
        )
        if found.get("source"):
            rule_desc += f", source={found['source']}"
        if found.get("dest"):
            rule_desc += f", dest={found['dest']}"
        if found.get("dport"):
            rule_desc += f", dport={found['dport']}"

    affected: list[dict] = []
    complete = True
    risk = RISK_MEDIUM

    if check_error is not None:
        # A failed read => we can't compute the removed rule's reach. Incomplete, not benign.
        complete = False
        blast = [
            f"rule lookup failed ({check_error}) — could not confirm what rule is at position {pos}; "
            "removal may affect the wrong rule or fail",
            "could not compute the removed rule's reach — absence of a reach warning is NOT a safety signal",
            "positions SHIFT after inserts/deletes — re-list rules before confirming",
            "no UNDO: firewall config is not in guest snapshots",
        ]
        reasons = [
            f"rule lookup for position {pos} failed — cannot confirm what is removed",
            "absence of HIGH is NOT a safety signal",
        ]
    else:
        # Compute the REACH of the rule being removed, then frame the REMOVAL effect:
        # removing an ACCEPT CLOSES that access; removing a DROP/REJECT RE-PERMITS it.
        reach_lines: list[str] = []
        if found:
            reach = blast_engine.compute_firewall_reach(
                found.get("action", ""), found.get("type", "in"), found.get("source"),
                found.get("dport"), found.get("proto"), scope_label,
                enable=_enable_flag(found.get("enable", 1)),
            )
            affected = reach.affected
            complete = reach.complete
            risk = _max_risk(risk, reach.risk)
            reach_lines = _removal_reach_lines(found, reach)
        blast = [
            *reach_lines,
            f"removes {rule_desc} from {scope_label}",
            "positions SHIFT after this removal — re-list rules if doing further edits",
            "removing an ACCEPT rule for SSH (22) or PVE UI (8006) can cause a lockout",
            "no UNDO: firewall config is not in guest snapshots; revert by re-adding",
        ]
        reasons = [
            "firewall rule removal affects connectivity — verify the rule before confirming",
            "absence of HIGH is NOT a safety signal (heuristic only)",
        ]

    if digest:
        current = {**current, "digest": digest}
        blast = [
            *blast,
            f"optimistic-lock digest: {digest} — pass digest={digest!r} to pve_firewall_rule_remove "
            "on confirm so PVE rejects the removal if the rule list moved since this preview (positions "
            "shift and the WRONG rule can be removed otherwise)",
        ]
    return Plan(
        action="pve_firewall_rule_remove",
        target=f"firewall/{scope}/rules/{pos}",
        change=f"remove {rule_desc} from {scope_label}",
        current=current,
        blast_radius=blast,
        affected=affected,
        risk=risk,
        risk_reasons=reasons,
        complete=complete,
    )


def plan_firewall_rule_update(
    api,
    pos: int,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
    **new_fields,
) -> Plan:
    """Preview updating a firewall rule at position `pos`.

    Reads firewall_rules_list (a safe read) to surface the rule's current state
    so the caller can compare before/after. RISK_MEDIUM floor (same connectivity risk as add/remove).

    Note: positions SHIFT after inserts/deletes; re-list before updating.
    Backend dependency: calls api._put() at execute time.
    """
    pos = _check_pos(pos)
    _check_scope(scope)
    # Validate action/direction in new_fields before the safe-read, mirroring the op-layer checks.
    if "action" in new_fields:
        new_fields["action"] = _check_action(new_fields["action"])
    if "direction" in new_fields:
        new_fields["direction"] = _check_direction(new_fields["direction"])

    scope_label = _scope_label(scope, node, vmid, kind)
    rule_desc = f"rule at position {pos}"

    found, current, check_error, digest = _find_rule_at_pos(api, pos, scope, node, vmid, kind)
    if found:
        rule_desc = (
            f"rule at pos={pos}: action={found.get('action', '?')}, "
            f"type={found.get('type', '?')}"
        )

    changed_fields = ", ".join(f"{k}={v!r}" for k, v in new_fields.items()) if new_fields else "(no fields)"

    affected: list[dict] = []
    complete = True
    risk = RISK_MEDIUM

    if check_error is not None:
        complete = False
        blast = [
            f"rule lookup failed ({check_error}) — could not read current state of {rule_desc}; "
            "update may affect the wrong rule or fail",
            "could not compute the post-update reach — absence of a reach warning is NOT a safety signal",
            "positions SHIFT after inserts/deletes — re-list rules before confirming",
            "no UNDO: firewall config is not in guest snapshots",
        ]
        reasons = [
            f"rule lookup for position {pos} failed — cannot compare before/after state",
            "absence of HIGH is NOT a safety signal",
        ]
    else:
        # Compute the REACH of the POST-UPDATE rule (new_fields merged over the current rule).
        # KEY-MISMATCH TRAP: the stored direction lives under 'type'; new_fields carries it as
        # 'direction'. Layer the new value over the stored one for each reachable field.
        reach_lines: list[str] = []
        base = found or {}
        merged = _merged_post_update(base, new_fields)
        reach = blast_engine.compute_firewall_reach(
            merged["action"], merged["direction"], merged["source"],
            merged["dport"], merged["proto"], scope_label, enable=merged["enable"],
        )
        affected = reach.affected
        complete = reach.complete
        risk = _max_risk(risk, reach.risk)
        reach_lines = [f"after this update, {line}" if line.lower().startswith("this rule")
                       else line for line in reach.summary_lines]
        blast = [
            *reach_lines,
            f"updates {rule_desc} on {scope_label}: changes → {changed_fields}",
            "positions SHIFT after inserts/deletes; verify position before updating",
            "a changed DROP/REJECT can affect connectivity; a changed ACCEPT can open access",
            "no UNDO: firewall config is not in guest snapshots; revert by re-updating",
        ]
        reasons = [
            "firewall rule update affects connectivity — silent-mistake-prone",
            "absence of HIGH is NOT a safety signal (heuristic only)",
        ]

    if digest:
        current = {**current, "digest": digest}
        blast = [
            *blast,
            f"optimistic-lock digest: {digest} — pass digest={digest!r} to pve_firewall_rule_update "
            "on confirm so PVE rejects the update if the rule list moved since this preview (positions "
            "shift and the WRONG rule can be updated otherwise)",
        ]
    return Plan(
        action="pve_firewall_rule_update",
        target=f"firewall/{scope}/rules/{pos}",
        change=f"update {rule_desc} on {scope_label}: {changed_fields}",
        current=current,
        blast_radius=blast,
        affected=affected,
        risk=risk,
        risk_reasons=reasons,
        complete=complete,
    )


def plan_firewall_set_enabled(
    api,
    enabled: bool,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
) -> Plan:
    """Preview toggling the firewall on or off.

    Reads firewall_options_get (a safe read) to surface the current enable state.
    RISK_HIGH both directions:
    - ENABLING: default-DROP can lock you out (SSH/8006) if ACCEPT rules are absent.
    - DISABLING: immediately strips all firewall protection from the scope.
    - Cluster scope = master kill-switch for every node and guest.
    """
    _check_scope(scope)

    scope_label = _scope_label(scope, node, vmid, kind)
    current: dict = {}
    check_error: str | None = None

    try:
        opts = firewall_options_get(api, scope, node, vmid, kind) or {}
        if "enable" in opts:
            current = {"enable": opts["enable"]}
    except Exception as e:
        check_error = type(e).__name__

    action_str = "ENABLE" if enabled else "DISABLE"

    if check_error is not None:
        blast = [
            f"could NOT read current firewall state for {scope_label} ({check_error}); "
            f"proceeding would {action_str} the firewall — connectivity impact unknown",
        ]
        reasons = [
            f"current state unknown — cannot confirm whether {action_str} changes anything",
            "RISK_HIGH maintained: uncertainty is not a safety signal",
        ]
    elif enabled:
        blast = [
            f"ENABLES the firewall on {scope_label}",
            "if ACCEPT rules for SSH (22) or PVE web UI (8006) are absent, "
            "the default-DROP policy will IMMEDIATELY block access — potential LOCKOUT",
        ]
        if scope == "cluster":
            blast.append(
                "cluster scope is the master kill-switch — affects ALL nodes and guests"
            )
        reasons = [
            "enabling the firewall can instantly lock you out if ACCEPT rules are incomplete",
            "verify SSH (22) and PVE UI (8006) ACCEPT rules exist before confirming",
        ]
    else:
        blast = [
            f"DISABLES the firewall on {scope_label} — immediately strips ALL firewall protection",
        ]
        if scope == "cluster":
            blast.append(
                "cluster scope is the master kill-switch — disables firewall protection "
                "for ALL nodes and guests simultaneously"
            )
        blast.append(
            "no UNDO: firewall config is not in guest snapshots; re-enable manually"
        )
        reasons = [
            "disabling the firewall removes all protection from the scope — all traffic passes through",
        ]

    # Lockout blast: ENABLING under default-DROP can cut management on any node lacking an inbound
    # SSH/8006 ACCEPT. Cluster/node scope only (a guest firewall is self-scoped). Names the at-risk
    # nodes on top of the unconditional HIGH; never lowers risk. DISABLE is a different (exposure) graph.
    affected: list[dict] = []
    complete = True
    if enabled and scope in ("cluster", "node"):
        lock = blast_engine.firewall_lockout_blast(api, scope, node)
        blast.extend(lock.summary_lines)
        affected = lock.affected
        complete = lock.complete

    return Plan(
        action="pve_firewall_set_enabled",
        target=f"firewall/{scope}/options",
        change=f"{action_str} firewall on {scope_label}",
        current=current,
        blast_radius=blast,
        risk=RISK_HIGH,
        risk_reasons=reasons,
        affected=affected,
        complete=complete,
    )


# ===========================================================================
# ALIASES — named IP/Network definitions (cluster / node / guest scope)
# ---------------------------------------------------------------------------
# Grounded against live PVE 9.2 schema (2026-06-14):
#   GET    {base}/aliases               list
#   POST   {base}/aliases               {name, cidr, comment?}   (NO digest on create)
#   GET    {base}/aliases/{name}         read one
#   PUT    {base}/aliases/{name}         {cidr?, comment?, rename?, digest?}
#   DELETE {base}/aliases/{name}         {digest?}
# An alias is a PASSIVE named CIDR: it changes traffic only when a firewall rule
# references it (source/dest = the alias name). PVE refuses to delete an alias that
# is still referenced. No UNDO — alias state lives in firewall config files.
# ===========================================================================

# NB: anchored with \Z (not $) — '$' also matches just before a trailing newline,
# which would let "web\n" pass and flow into a URL path. \Z matches only the very end.
_FW_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9\-_]+\Z")


def _check_fw_name(value: str, label: str) -> str:
    """Validate a firewall object name (alias / ipset / security-group).

    PVE constrains these to ``[A-Za-z][A-Za-z0-9\\-\\_]+`` (letter first, len >= 2).
    The name goes into the URL path, so reject anything outside that class.
    """
    v = str(value)
    if not _FW_NAME_RE.match(v):
        raise ProximoError(
            f"invalid {label}: {value!r} (must match [A-Za-z][A-Za-z0-9-_]+ — "
            "letter first, then letters/digits/-/_, length >= 2)"
        )
    return v


def _check_cidr(value: str, label: str = "cidr") -> str:
    """Validate an IP or CIDR network. Rejects path-traversal / injection — the value
    can flow into a URL path segment (ipset entry remove). Accepts single IPs (v4/v6)
    and CIDR networks; ipaddress() rejects '..', spaces, and anything non-numeric/host."""
    v = str(value).strip()
    try:
        ipaddress.ip_network(v, strict=False)
    except ValueError as exc:
        raise ProximoError(
            f"invalid {label}: {value!r} (expected an IP address or CIDR network)"
        ) from exc
    return v


def alias_list(
    api,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
) -> list[dict]:
    """List firewall aliases for the given scope (cluster or guest — node scope has
    no aliases; read; audited at server layer)."""
    _check_alias_ipset_scope(scope)
    base = _fw_base(api, scope, node, vmid, kind)
    return api._get(f"{base}/aliases") or []


def alias_create(
    api,
    name: str,
    cidr: str,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
    comment: str | None = None,
) -> None:
    """Create a firewall alias (named CIDR). MUTATION — confirm-gated + audited at server layer.

    POST {base}/aliases  {name, cidr, comment?}
    No UNDO: revert by deleting the alias. Passive until a rule references it.
    """
    name = _check_fw_name(name, "alias name")
    cidr = _check_cidr(cidr)
    _check_alias_ipset_scope(scope)
    base = _fw_base(api, scope, node, vmid, kind)
    data: dict = {"name": name, "cidr": cidr}
    if comment is not None:
        data["comment"] = _check_freetext(comment, "comment")
    return api._post(f"{base}/aliases", data)


def alias_update(
    api,
    name: str,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
    cidr: str | None = None,
    comment: str | None = None,
    rename: str | None = None,
    digest: str | None = None,
) -> None:
    """Update a firewall alias. MUTATION — confirm-gated + audited at server layer.

    PUT {base}/aliases/{name}  {cidr?, comment?, rename?, digest?}
    Requires at least one of cidr / comment / rename. Changing the CIDR silently
    alters what every rule referencing this alias matches. No UNDO.
    """
    name = _check_fw_name(name, "alias name")
    _check_alias_ipset_scope(scope)
    base = _fw_base(api, scope, node, vmid, kind)
    data: dict = {}
    if cidr is not None:
        data["cidr"] = _check_cidr(cidr)
    if comment is not None:
        data["comment"] = _check_freetext(comment, "comment")
    if rename is not None:
        data["rename"] = _check_fw_name(rename, "alias rename")
    if not data:
        raise ProximoError("alias_update requires at least one of: cidr, comment, rename")
    if digest is not None:
        data["digest"] = digest
    return api._put(f"{base}/aliases/{name}", data)


def alias_delete(
    api,
    name: str,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
    digest: str | None = None,
) -> None:
    """Delete a firewall alias. MUTATION — confirm-gated + audited at server layer.

    DELETE {base}/aliases/{name}  {digest?}
    PVE refuses if the alias is still referenced by a rule. No UNDO: re-create to revert.
    """
    name = _check_fw_name(name, "alias name")
    _check_alias_ipset_scope(scope)
    base = _fw_base(api, scope, node, vmid, kind)
    params: dict = {}
    if digest is not None:
        params["digest"] = digest
    return api._delete(f"{base}/aliases/{name}", params)


def _find_alias(api, name: str, scope, node, vmid, kind) -> tuple[dict, bool]:
    """One safe read: return (current alias dict or {}, read_failed). 2026-07-10 audit L17: a failed
    read must be distinguishable from 'alias absent' — both used to return {} and read complete."""
    try:
        aliases = alias_list(api, scope, node, vmid, kind) or []
    except Exception:
        return {}, True
    found = next((a for a in aliases if a.get("name") == name), None)
    if not found:
        return {}, False
    return {k: found[k] for k in ("name", "cidr", "comment", "ipversion") if k in found}, False


def plan_alias_create(
    name: str,
    cidr: str,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
    comment: str | None = None,
) -> Plan:
    """Preview creating an alias. PURE. RISK_LOW — passive definition until referenced."""
    name = _check_fw_name(name, "alias name")
    _check_alias_ipset_scope(scope)
    scope_label = _scope_label(scope, node, vmid, kind)
    return Plan(
        action="pve_firewall_alias_create",
        target=f"firewall/{scope}/aliases/{name}",
        change=f"create alias '{name}' = {cidr} on {scope_label}",
        current={},
        blast_radius=[
            f"defines a named alias '{name}' -> {cidr} on {scope_label}",
            "passive: affects traffic only once a firewall rule references this alias",
            "no UNDO: alias lives in firewall config (not a guest snapshot); revert by deleting it",
        ],
        risk=RISK_LOW,
        risk_reasons=["an alias is a passive definition — no effect until a rule references it"],
    )


def plan_alias_update(
    api,
    name: str,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
    cidr: str | None = None,
    comment: str | None = None,
    rename: str | None = None,
) -> Plan:
    """Preview updating an alias. Reads the current alias (one safe read). RISK_MEDIUM:
    changing the CIDR silently changes what every referencing rule matches."""
    name = _check_fw_name(name, "alias name")
    _check_alias_ipset_scope(scope)
    scope_label = _scope_label(scope, node, vmid, kind)
    current, read_failed = _find_alias(api, name, scope, node, vmid, kind)
    changes = []
    if cidr is not None:
        changes.append(f"cidr -> {cidr}")
    if comment is not None:
        changes.append("comment")
    if rename is not None:
        changes.append(f"rename -> {rename}")
    change_summary = ", ".join(changes) if changes else "(no fields)"
    blast = [
        f"updates alias '{name}' on {scope_label}: {change_summary}",
        "any firewall rule referencing this alias changes what it matches — silently",
        "no UNDO: revert by updating the alias back to its previous value",
    ]
    if read_failed:
        blast.append("could not read the current alias — prior value UNKNOWN; no guided revert baseline")
    return Plan(
        action="pve_firewall_alias_update",
        target=f"firewall/{scope}/aliases/{name}",
        change=f"update alias '{name}' on {scope_label}: {change_summary}",
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=[
            "changing an alias alters every referencing rule's match set — connectivity risk",
        ],
        complete=not read_failed,
    )


def plan_alias_delete(
    api,
    name: str,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
) -> Plan:
    """Preview deleting an alias. Reads the current alias (one safe read). RISK_MEDIUM:
    PVE refuses if the alias is still referenced; if forced out elsewhere, rules break."""
    name = _check_fw_name(name, "alias name")
    _check_alias_ipset_scope(scope)
    scope_label = _scope_label(scope, node, vmid, kind)
    current, read_failed = _find_alias(api, name, scope, node, vmid, kind)
    blast = [
        f"removes alias '{name}' from {scope_label}",
        "PVE refuses the delete while any rule still references this alias",
        "no UNDO: re-create the alias to revert",
    ]
    if read_failed:
        blast.append("could not read the current alias — prior value UNKNOWN; no guided revert baseline")
    return Plan(
        action="pve_firewall_alias_delete",
        target=f"firewall/{scope}/aliases/{name}",
        change=f"delete alias '{name}' from {scope_label}",
        current=current,
        blast_radius=blast,
        risk=RISK_MEDIUM,
        risk_reasons=[
            "a referencing rule would break if the alias is removed — verify nothing uses it",
        ],
        complete=not read_failed,
    )


# ===========================================================================
# IP-SETS — named sets of IP/Network entries (cluster / node / guest scope)
# ---------------------------------------------------------------------------
# Grounded against live PVE 9.2 schema (2026-06-14):
#   POST   {base}/ipset                  {name, comment?}            create empty set
#   DELETE {base}/ipset/{name}            {force?}                    delete set (force wipes members)
#   POST   {base}/ipset/{name}            {cidr, comment?, nomatch?}  add entry
#   DELETE {base}/ipset/{name}/{cidr}     {digest?}                   remove entry
# A rule references a set as '+name'. Empty set = passive (LOW); entry changes
# alter every referencing rule's match set (MEDIUM). 'force' wipes ALL members.
# No UNDO — ipset state lives in firewall config files.
#
# Shape risk (confirm at live smoke): the entry path embeds the CIDR verbatim
# (e.g. .../ipset/blocklist/10.0.0.0/24) — the slash is part of the {cidr} path
# segment. Confirm the live API accepts the unencoded slash.
# ===========================================================================


def ipset_create(
    api,
    name: str,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
    comment: str | None = None,
) -> None:
    """Create an empty IP set. MUTATION — confirm-gated + audited at server layer.

    POST {base}/ipset  {name, comment?}
    Passive until a rule references it as '+name'. No UNDO: delete to revert.
    """
    name = _check_fw_name(name, "ipset name")
    _check_alias_ipset_scope(scope)
    base = _fw_base(api, scope, node, vmid, kind)
    data: dict = {"name": name}
    if comment is not None:
        data["comment"] = _check_freetext(comment, "comment")
    return api._post(f"{base}/ipset", data)


def ipset_delete(
    api,
    name: str,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
    force: bool = False,
) -> None:
    """Delete an IP set. MUTATION — confirm-gated + audited at server layer.

    DELETE {base}/ipset/{name}  {force?}
    Without force, PVE refuses a non-empty set. force=True WIPES all members first.
    PVE also refuses while a rule still references the set. No UNDO.
    """
    name = _check_fw_name(name, "ipset name")
    _check_alias_ipset_scope(scope)
    base = _fw_base(api, scope, node, vmid, kind)
    params: dict = {}
    if force:
        params["force"] = 1
    return api._delete(f"{base}/ipset/{name}", params)


def ipset_entry_add(
    api,
    name: str,
    cidr: str,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
    comment: str | None = None,
    nomatch: bool = False,
) -> None:
    """Add an IP/Network entry to an IP set. MUTATION — confirm-gated + audited at server layer.

    POST {base}/ipset/{name}  {cidr, comment?, nomatch?}
    Changes what every rule referencing this set matches. nomatch=True marks the entry
    as an exclusion (a hole in the set). No UNDO: remove the entry to revert.
    """
    name = _check_fw_name(name, "ipset name")
    cidr = _check_cidr(cidr)
    _check_alias_ipset_scope(scope)
    base = _fw_base(api, scope, node, vmid, kind)
    data: dict = {"cidr": cidr}
    if comment is not None:
        data["comment"] = _check_freetext(comment, "comment")
    if nomatch:
        data["nomatch"] = 1
    return api._post(f"{base}/ipset/{name}", data)


def ipset_entry_remove(
    api,
    name: str,
    cidr: str,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
    digest: str | None = None,
) -> None:
    """Remove an IP/Network entry from an IP set. MUTATION — confirm-gated + audited at server layer.

    DELETE {base}/ipset/{name}/{cidr}  {digest?}
    Changes what every rule referencing this set matches. No UNDO: re-add to revert.
    """
    name = _check_fw_name(name, "ipset name")
    cidr = _check_cidr(cidr)
    _check_alias_ipset_scope(scope)
    base = _fw_base(api, scope, node, vmid, kind)
    params: dict = {}
    if digest is not None:
        params["digest"] = digest
    return api._delete(f"{base}/ipset/{name}/{cidr}", params)


def _ipset_entries(api, name: str, scope, node, vmid, kind) -> tuple[list[dict], bool]:
    """One safe read of an IP set's members. Returns (entries, read_failed).

    read_failed distinguishes a genuinely-empty set from an unreadable one, so a
    destructive plan never presents a failed read as a confirmed zero-member wipe.
    """
    try:
        base = _fw_base(api, scope, node, vmid, kind)
        return (api._get(f"{base}/ipset/{name}") or []), False
    except Exception:
        return [], True


def plan_ipset_create(
    name: str,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
    comment: str | None = None,
) -> Plan:
    """Preview creating an IP set. PURE. RISK_LOW — empty set, passive until referenced."""
    name = _check_fw_name(name, "ipset name")
    _check_alias_ipset_scope(scope)
    scope_label = _scope_label(scope, node, vmid, kind)
    return Plan(
        action="pve_firewall_ipset_create",
        target=f"firewall/{scope}/ipset/{name}",
        change=f"create empty IP set '{name}' on {scope_label}",
        current={},
        blast_radius=[
            f"defines an empty IP set '{name}' on {scope_label}",
            f"passive: affects traffic only once a rule references it as '+{name}' and entries are added",
            "no UNDO: ipset lives in firewall config (not a guest snapshot); revert by deleting it",
        ],
        risk=RISK_LOW,
        risk_reasons=["an empty IP set is a passive container — no effect until referenced and filled"],
    )


def plan_ipset_delete(
    api,
    name: str,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
    force: bool = False,
) -> Plan:
    """Preview deleting an IP set. Reads current members (one safe read). RISK_MEDIUM:
    force WIPES all members; PVE refuses while a rule still references the set."""
    name = _check_fw_name(name, "ipset name")
    _check_alias_ipset_scope(scope)
    scope_label = _scope_label(scope, node, vmid, kind)
    entries, read_failed = _ipset_entries(api, name, scope, node, vmid, kind)
    if read_failed:
        members: object = "unknown"
        if force:
            force_line = (
                f"force=True: WIPES ALL members of '{name}' — member count UNKNOWN (read failed), "
                "so the destructive scope cannot be confirmed"
            )
        else:
            force_line = (
                f"force=False: PVE refuses if '{name}' is non-empty — member count UNKNOWN (read failed)"
            )
    else:
        n = len(entries)
        members = n
        if force:
            force_line = f"force=True: WIPES all {n} member(s) of '{name}', then removes the set"
        else:
            force_line = f"force=False: PVE refuses if '{name}' is non-empty (it has {n} member(s))"
    return Plan(
        action="pve_firewall_ipset_delete",
        target=f"firewall/{scope}/ipset/{name}",
        change=f"delete IP set '{name}' from {scope_label}",
        current={"members": members, "force": force},
        blast_radius=[
            f"removes IP set '{name}' from {scope_label}",
            force_line,
            "PVE refuses the delete while any rule still references this set",
            "no UNDO: re-create the set and re-add members to revert",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "removing a referenced IP set breaks rules; force wipes members irreversibly",
        ],
    )


def plan_ipset_entry_add(
    name: str,
    cidr: str,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
    comment: str | None = None,
    nomatch: bool = False,
) -> Plan:
    """Preview adding an entry to an IP set. PURE. RISK_MEDIUM — changes referencing rules' match set."""
    name = _check_fw_name(name, "ipset name")
    cidr = _check_cidr(cidr)
    _check_alias_ipset_scope(scope)
    scope_label = _scope_label(scope, node, vmid, kind)
    kindword = "exclusion (nomatch)" if nomatch else "entry"
    return Plan(
        action="pve_firewall_ipset_entry_add",
        target=f"firewall/{scope}/ipset/{name}",
        change=f"add {kindword} {cidr} to IP set '{name}' on {scope_label}",
        current={},
        blast_radius=[
            f"adds {cidr} as a {kindword} to IP set '{name}' on {scope_label}",
            f"every rule referencing '+{name}' changes what it matches (more or fewer packets)",
            "no UNDO: remove this entry to revert",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["changing an IP set's members alters every referencing rule's match set"],
    )


def plan_ipset_entry_remove(
    name: str,
    cidr: str,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
) -> Plan:
    """Preview removing an entry from an IP set. PURE. RISK_MEDIUM — changes referencing rules' match set."""
    name = _check_fw_name(name, "ipset name")
    cidr = _check_cidr(cidr)
    _check_alias_ipset_scope(scope)
    scope_label = _scope_label(scope, node, vmid, kind)
    return Plan(
        action="pve_firewall_ipset_entry_remove",
        target=f"firewall/{scope}/ipset/{name}",
        change=f"remove entry {cidr} from IP set '{name}' on {scope_label}",
        current={},
        blast_radius=[
            f"removes {cidr} from IP set '{name}' on {scope_label}",
            f"every rule referencing '+{name}' changes what it matches — may open or close access",
            "no UNDO: re-add this entry to revert",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=["changing an IP set's members alters every referencing rule's match set"],
    )


# ===========================================================================
# SECURITY GROUPS — named, reusable rule bundles (cluster-only)
# ---------------------------------------------------------------------------
# Grounded against live PVE 9.2 schema (2026-06-14):
#   POST   /cluster/firewall/groups          {group, comment?}   create empty group
#   DELETE /cluster/firewall/groups/{group}                       delete (NO params; must be empty)
# A rule references a group via type=group, action=<group-name>. An empty group is
# passive (LOW). PVE refuses to delete a group that still has rules or is referenced
# (MEDIUM). No UNDO — group state lives in cluster firewall config.
# Security groups are CLUSTER-SCOPE ONLY (node/guest do not expose this endpoint).
# ===========================================================================


def security_group_create(api, group: str, comment: str | None = None) -> None:
    """Create an empty security group. MUTATION — confirm-gated + audited at server layer.

    POST /cluster/firewall/groups  {group, comment?}
    Passive until a rule references it (type=group). No UNDO: delete to revert.
    """
    group = _check_fw_name(group, "security group name")
    data: dict = {"group": group}
    if comment is not None:
        data["comment"] = _check_freetext(comment, "comment")
    return api._post("/cluster/firewall/groups", data)


def security_group_delete(api, group: str) -> None:
    """Delete a security group. MUTATION — confirm-gated + audited at server layer.

    DELETE /cluster/firewall/groups/{group}   (no params)
    PVE refuses while the group still holds rules OR is referenced by a rule. No UNDO.
    """
    group = _check_fw_name(group, "security group name")
    return api._delete(f"/cluster/firewall/groups/{group}", {})


def _security_group_rules(api, group: str) -> tuple[list[dict], bool]:
    """One safe read of a group's rules. Returns (rules, read_failed).

    read_failed distinguishes a genuinely-empty group from an unreadable one, so the
    delete plan never presents a failed read as a confirmed zero-rule group.
    """
    try:
        return (api._get(f"/cluster/firewall/groups/{group}") or []), False
    except Exception:
        return [], True


def plan_security_group_create(group: str, comment: str | None = None) -> Plan:
    """Preview creating a security group. PURE. RISK_LOW — empty group, passive until referenced."""
    group = _check_fw_name(group, "security group name")
    return Plan(
        action="pve_firewall_security_group_create",
        target=f"firewall/cluster/groups/{group}",
        change=f"create empty security group '{group}' (cluster)",
        current={},
        blast_radius=[
            f"defines an empty security group '{group}' on the cluster",
            "passive: affects traffic only once rules are added AND a rule references the group",
            "no UNDO: group lives in cluster firewall config (not a guest snapshot); revert by deleting it",
        ],
        risk=RISK_LOW,
        risk_reasons=["an empty security group is a passive bundle — no effect until filled and referenced"],
    )


def plan_security_group_delete(api, group: str) -> Plan:
    """Preview deleting a security group. Reads the group's rules (one safe read). RISK_MEDIUM:
    PVE refuses while the group is non-empty or still referenced by a rule."""
    group = _check_fw_name(group, "security group name")
    rules, read_failed = _security_group_rules(api, group)
    if read_failed:
        rule_count: object = "unknown"
        holds_line = (
            f"removes security group '{group}' from the cluster — rule count UNKNOWN (read failed)"
        )
    else:
        n = len(rules)
        rule_count = n
        holds_line = f"removes security group '{group}' (currently holds {n} rule(s)) from the cluster"
    return Plan(
        action="pve_firewall_security_group_delete",
        target=f"firewall/cluster/groups/{group}",
        change=f"delete security group '{group}' (cluster)",
        current={"rules": rule_count},
        blast_radius=[
            holds_line,
            "PVE refuses the delete while the group is non-empty or still referenced by a rule",
            "empty the group's rules and remove any referencing rule first",
            "no UNDO: re-create the group and its rules to revert",
        ],
        risk=RISK_MEDIUM,
        risk_reasons=[
            "deleting a referenced/non-empty security group is refused or breaks referencing rules",
        ],
    )


# ===========================================================================
# OPTIONS SET — firewall options for a scope (cluster / node / guest)
# ---------------------------------------------------------------------------
# Grounded against live PVE 9.2 schema (2026-06-14):
#   PUT {base}/options  {<option>: <value>, ..., delete?: <csv keys>, digest?}
# Options are a flat bag whose valid keys vary by scope:
#   cluster: enable, policy_in, policy_out, policy_forward, ebtables, log_ratelimit
#   node:    enable, log_level_in/out, nf_conntrack_*, tcp_flags_log_level, nosmurfs, ...
#   guest:   enable, dhcp, ipfilter, macfilter, ndp, radv, policy_in/out, log_level_in/out
# We pass the bag through verbatim and let PVE validate scope-specific keys.
# RISK_HIGH when 'enable' or any 'policy*' key changes (lockout / default-policy flip);
# else RISK_MEDIUM. No UNDO — config-file state; revert by setting the prior values.
#
# Note: firewall_set_enabled is the focused tool for just the enable flag; this tool
# is the general options editor (policies, log levels, ebtables, log_ratelimit, ...).
# ===========================================================================


_RESERVED_OPTION_KEYS = frozenset({"delete", "digest"})


def _check_option_keys(options: dict) -> None:
    """'delete' and 'digest' are reserved PVE request params, not firewall options. Reject them
    inside the options bag — otherwise options={'delete': 'enable,policy_in'} would smuggle a
    HIGH-risk reset past the risk classifier (which only inspects option keys)."""
    bad = _RESERVED_OPTION_KEYS & set(options)
    if bad:
        raise ProximoError(
            f"reserved key(s) {sorted(bad)} cannot be passed inside options — "
            "use the dedicated delete=[...] / digest=... parameters instead"
        )


def _parse_delete_keys(delete) -> list[str]:
    """Normalize the `delete` param (list OR comma-separated string) to a list of keys."""
    if isinstance(delete, list):
        return [str(k).strip() for k in delete if str(k).strip()]
    if isinstance(delete, str):
        return [k.strip() for k in delete.split(",") if k.strip()]
    return []


def _options_set_is_high(option_keys, delete_keys) -> bool:
    """A firewall-options change is HIGH-risk if it flips the enable flag or any policy —
    whether the key is being SET or UNSET (a deleted policy reverts to the default, also risky)."""
    return any(
        k == "enable" or k.startswith("policy")
        for k in list(option_keys) + list(delete_keys)
    )


def _is_lockout_trigger(options: dict, delete_keys: list) -> bool:
    """True if this options change moves toward default-DROP and can lock out management:
    enabling the firewall, setting policy_in=DROP, or UNSETTING policy_in (reverts to PVE's
    default DROP). policy_in=ACCEPT is a WIDENING — not a trigger."""
    enable = options.get("enable")
    if str(enable).strip().lower() in ("1", "true"):
        return True
    if str(options.get("policy_in", "")).strip().upper() == "DROP":
        return True
    return "policy_in" in delete_keys


def firewall_options_set(
    api,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
    options: dict | None = None,
    delete: list | str | None = None,
    digest: str | None = None,
) -> None:
    """Set firewall options for a scope. MUTATION — confirm-gated + audited at server layer.

    PUT {base}/options  {<option>: <value>, ..., delete?: csv, digest?}
    Requires at least one option to set or delete (a digest alone is not a change).
    Changing policy_in/out to DROP or enabling the firewall can lock you out. No UNDO.
    """
    if not options and not delete:
        raise ProximoError(
            "firewall_options_set requires at least one option to set (options=...) "
            "or unset (delete=[...]) — a digest alone is not a change"
        )
    _check_option_keys(options or {})
    base = _fw_base(api, scope, node, vmid, kind)
    data: dict = dict(options or {})
    delete_keys = _parse_delete_keys(delete)
    if delete_keys:
        data["delete"] = ",".join(delete_keys)
    if digest is not None:
        data["digest"] = digest
    return api._put(f"{base}/options", data)


def plan_firewall_options_set(
    api,
    scope: str = "cluster",
    node: str | None = None,
    vmid: str | None = None,
    kind: str | None = None,
    options: dict | None = None,
    delete: list | str | None = None,
) -> Plan:
    """Preview a firewall-options change. Reads current options (one safe read). RISK_HIGH when
    'enable' or any 'policy*' key changes (lockout / default-policy flip); else RISK_MEDIUM."""
    _check_scope(scope)
    options = options or {}
    _check_option_keys(options)
    delete_keys = _parse_delete_keys(delete)
    scope_label = _scope_label(scope, node, vmid, kind)

    current: dict = {}
    read_failed = False
    try:
        current = firewall_options_get(api, scope, node, vmid, kind) or {}
        # keep only the keys this change touches, so the preview stays focused
        touched = set(options) | set(delete_keys)
        current = {k: v for k, v in current.items() if k in touched}
    except Exception:
        current = {}
        read_failed = True  # 2026-07-10 audit M7: a swallowed read is disclosed, not silent

    high = _options_set_is_high(options.keys(), delete_keys)
    set_summary = ", ".join(f"{k}={options[k]}" for k in options) or "(none)"
    del_summary = ", ".join(delete_keys) or "(none)"

    blast = [
        f"sets firewall options on {scope_label}: set [{set_summary}], unset [{del_summary}]",
        "no UNDO: firewall options live in config (not a guest snapshot); revert by setting prior values",
    ]
    reasons = ["firewall option changes can affect connectivity for the whole scope"]
    if high:
        blast.insert(1,
            "enabling the firewall or setting policy_in/out=DROP can instantly lock you out "
            "(no ACCEPT for SSH/22 or PVE UI/8006) — verify rules before confirming")
        if scope == "cluster":
            blast.insert(2, "cluster scope changes the default policy for ALL nodes and guests")
        reasons.append("changes the enable flag or default policy — lockout / cluster-wide impact")

    # Lockout blast: if this change moves toward default-DROP (enable / policy_in=DROP / unset
    # policy_in) at cluster/node scope, name the nodes that would lose management access.
    affected: list[dict] = []
    complete = not read_failed
    if read_failed:
        blast.append(
            "could not read the current firewall options — prior values are UNKNOWN, so there is "
            "no guided revert baseline; verify before confirming"
        )
    if scope in ("cluster", "node") and _is_lockout_trigger(options, delete_keys):
        lock = blast_engine.firewall_lockout_blast(api, scope, node)
        blast.extend(lock.summary_lines)
        affected = lock.affected
        complete = complete and lock.complete

    return Plan(
        action="pve_firewall_options_set",
        target=f"firewall/{scope}/options",
        change=f"change firewall options on {scope_label}: set=[{set_summary}], unset=[{del_summary}]",
        current=current,
        blast_radius=blast,
        risk=RISK_HIGH if high else RISK_MEDIUM,
        risk_reasons=reasons,
        affected=affected,
        complete=complete,
    )
