"""Safe-runbook MCP prompts — user-invoked front doors that encode the correct,
safe multi-step sequence for common Proxmox operations (plan-first, verify-after,
receipts). These add real capability, not score-filler: each prompt must name the
actual tools and steer toward the guarded path the trust spine enforces.

Same pin-the-surface discipline as test_tool_count: EXPECTED_PROMPT_COUNT is bumped
intentionally when a prompt is added/removed, never allowed to drift silently.
"""

from __future__ import annotations

import asyncio

import proximo.server as server

EXPECTED_PROMPT_COUNT = 5

EXPECTED_PROMPTS = {
    "safe_migration",
    "diagnose_cluster",
    "provision_container",
    "safe_backup",
    "review_receipts",
}


def _list_prompts():
    return asyncio.run(server.mcp.list_prompts())


def _prompt(name: str) -> object:
    for p in _list_prompts():
        if p.name == name:
            return p
    raise AssertionError(f"prompt {name!r} not registered")


def _text(name: str, arguments: dict[str, str] | None = None) -> str:
    result = asyncio.run(server.mcp.get_prompt(name, arguments or {}))
    return "\n".join(
        m.content.text for m in result.messages if hasattr(m.content, "text")
    )


def test_expected_prompts_registered_and_count_pinned():
    names = {p.name for p in _list_prompts()}
    assert EXPECTED_PROMPTS <= names, f"missing prompts: {EXPECTED_PROMPTS - names}"
    assert len(names) == EXPECTED_PROMPT_COUNT, (
        f"prompt surface changed: registry exposes {len(names)}, expected "
        f"{EXPECTED_PROMPT_COUNT}. If intentional, bump EXPECTED_PROMPT_COUNT."
    )


def test_every_prompt_has_a_description():
    for p in _list_prompts():
        assert p.description and p.description.strip(), f"{p.name} has no description"


def test_safe_migration_plans_before_moving_and_verifies():
    text = _text("safe_migration", {"guest": "101", "target_node": "pve-b"})
    assert "101" in text and "pve-b" in text
    assert "pve_guest_migrate" in text
    # capacity check on the destination before committing
    assert "pve_cluster_resources" in text
    # plan-first discipline, then verify
    low = text.lower()
    assert "plan" in low and "before" in low
    assert "pve_guest_status" in text
    # PVE's own precondition verdict comes before the Proximo plan
    assert text.index("pve_guest_migrate_preflight") < text.index("call `pve_guest_migrate` for")


def test_diagnose_cluster_is_read_only():
    text = _text("diagnose_cluster", {})
    assert "pve_cluster_status" in text
    assert "pve_doctor" in text
    assert "pve_tasks_list" in text
    # must declare itself read-only and steer away from mutation
    assert "read-only" in text.lower()


def test_diagnose_cluster_scopes_to_a_node_when_given():
    text = _text("diagnose_cluster", {"node": "pve-a"})
    assert "pve-a" in text


def test_provision_container_plans_before_create():
    text = _text("provision_container", {"node": "pve-a", "hostname": "web01"})
    assert "web01" in text and "pve-a" in text
    assert "pve_create_container" in text
    low = text.lower()
    assert "plan" in low and "before" in low


def test_safe_backup_runs_then_verifies():
    text = _text("safe_backup", {"guest": "202"})
    assert "202" in text
    assert "pve_backup" in text
    # verification step after the backup
    assert "pve_backup_list" in text


def test_review_receipts_verifies_the_chain():
    text = _text("review_receipts", {})
    # the PROVE front door: confirm the tamper-evident chain first
    assert "audit_verify" in text


def test_review_receipts_is_honest_about_off_box_entries():
    # No tool returns the ledger's records — audit_verify yields integrity + a count.
    # The prompt must not promise to summarize entries it can't fetch: it says so, points
    # at the off-box read, and takes no decorative arguments.
    text = _text("review_receipts", {}).lower()
    assert "off-box" in text or "off box" in text
    assert (_prompt("review_receipts").arguments or []) == [], (
        "review_receipts should take no arguments — a 'limit' nothing consumes is an overclaim"
    )
