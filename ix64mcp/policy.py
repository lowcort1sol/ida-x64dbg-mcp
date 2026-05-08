from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


SAFE_ACTIONS = {
    "ida.goto",
    "ida.rename",
    "ida.comment",
    "ida.get_function",
    "ida.get_xrefs",
    "ida.list_strings",
    "ida.get_string_xrefs",
    "ida.function_summary",
    "ida.callgraph",
    "ida.cfg",
    "ida.callers",
    "ida.callees",
    "ida.string_to_functions",
    "ida.import_to_callers",
    "ida.branch_context",
    "ida.stack_var_usage",
    "ida.pseudocode",
    "ida.refresh_decompiler",
    "ida.set_decompiler_comment",
    "x64dbg.goto",
    "x64dbg.set_breakpoint",
    "x64dbg.remove_breakpoint",
    "x64dbg.run",
    "x64dbg.pause",
    "x64dbg.step_into",
    "x64dbg.step_over",
    "x64dbg.read_memory",
    "x64dbg.read_registers",
    "x64dbg.runtime_snapshot",
    "x64dbg.list_modules",
    "x64dbg.memory_map",
    "x64dbg.call_stack",
    "x64dbg.threads",
    "x64dbg.exceptions",
    "x64dbg.set_hardware_breakpoint",
    "x64dbg.remove_hardware_breakpoint",
    "x64dbg.set_memory_breakpoint",
    "x64dbg.remove_memory_breakpoint",
    "x64dbg.set_conditional_breakpoint",
    "x64dbg.set_temporary_breakpoint",
    "x64dbg.breakpoint_group_add",
    "x64dbg.remove_breakpoint_group",
    "x64dbg.breakpoint_snapshot",
    "x64dbg.dump_metadata",
    "x64dbg.run_until_breakpoint",
    "trace.recipe_enable",
    "trace.recipe_disable",
    "trace.recipe_status",
    "analysis.sync_address",
    "analysis.add_note",
    "analysis.link_dynamic_static",
    "analysis.follow_debugger",
    "analysis.break_on_entry",
    "analysis.wait_for_event",
    "analysis.policy_status",
    "analysis.policy_approve",
    "analysis.policy_clear",
    "analysis.suggest_name",
    "analysis.suggest_comment",
    "analysis.suggest_type",
    "analysis.list_suggestions",
    "analysis.apply_suggestion",
    "analysis.reject_suggestion",
    "analysis.timeline_summary",
    "analysis.context_budget",
    "analysis.semantic_cache",
    "analysis.session_resume",
    "analysis.session_list",
    "analysis.runtime_history",
    "analysis.correlate_runtime_static",
    "analysis.detect_anti_debug",
    "workflow.follow_debugger",
    "workflow.explain_current_function",
    "workflow.find_password_check",
    "workflow.break_on_first_strcmp_like",
    "workflow.rename_functions_from_trace",
    "workflow.make_patch_plan",
    "workflow.generate_analysis_report",
    "workflow.analyze_function_runtime",
    "pe.summary",
    "pe.imports",
    "pe.exports",
    "pe.resources",
    "pe.relocations",
    "patch.plan",
    "patch.diff",
    "patch.rollback",
    "malware.workspace_create",
    "malware.triage",
    "malware.behavior_report",
    "malware.add_ioc",
    "malware.add_config",
    "malware.workspace_update",
    "malware.add_artifact",
    "malware.add_lineage",
    "malware.export_report",
    "malware.sandbox_check",
}

RISKY_ACTIONS = {
    "x64dbg.patch_memory": "patching debuggee memory changes runtime behavior",
    "x64dbg.write_memory": "writing debuggee memory changes runtime behavior",
    "x64dbg.dump_memory": "dumping process memory may expose sensitive or malicious payloads",
    "x64dbg.run_until_return": "scripted execution can accidentally run more code than intended",
    "analysis.automation_loop": "automation loops can drive an unknown sample too aggressively",
    "patch.apply_file": "patching files changes executable behavior and must be explicitly approved",
    "patch.apply_memory": "patching debuggee memory changes runtime behavior",
}


@dataclass(slots=True)
class PolicyDecision:
    allowed: bool
    action: str
    level: str
    reason: str

    def as_json(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "action": self.action,
            "level": self.level,
            "reason": self.reason,
        }


@dataclass(slots=True)
class PolicyEngine:
    mode: str = "analysis-safe"
    approved_actions: set[str] = field(default_factory=set)

    @classmethod
    def from_env(cls) -> "PolicyEngine":
        mode = os.environ.get("IX64MCP_POLICY", "analysis-safe").strip().lower() or "analysis-safe"
        if os.environ.get("IX64MCP_ALLOW_RISKY", "").strip().lower() in {"1", "true", "yes", "on"}:
            mode = "permissive"
        return cls(mode=mode)

    def decide(self, action: str) -> PolicyDecision:
        if action in SAFE_ACTIONS:
            return PolicyDecision(True, action, "safe", "allowed in analysis-safe mode")
        if self.mode == "permissive":
            return PolicyDecision(True, action, "risky", "allowed by permissive policy")
        if action in self.approved_actions:
            return PolicyDecision(True, action, "risky", "allowed by explicit temporary approval")
        reason = RISKY_ACTIONS.get(action, "action is not registered as analysis-safe")
        return PolicyDecision(False, action, "risky", reason)

    def require(self, action: str) -> PolicyDecision:
        decision = self.decide(action)
        if not decision.allowed:
            raise PermissionError(f"policy blocked {action}: {decision.reason}")
        return decision

    def approve(self, action: str, reason: str = "") -> dict[str, Any]:
        self.approved_actions.add(action)
        return {
            "action": action,
            "approved": True,
            "reason": reason,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    def clear(self, action: str | None = None) -> dict[str, Any]:
        if action:
            self.approved_actions.discard(action)
        else:
            self.approved_actions.clear()
        return {"cleared": action or "all"}

    def status(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "safe_actions": sorted(SAFE_ACTIONS),
            "risky_actions": sorted(RISKY_ACTIONS),
            "approved_actions": sorted(self.approved_actions),
        }
