"""hackle — a trust-tier-gated executor agent."""
from hackle.action_tier import ActionClassifier, ActionTier
from hackle.audit import AuditLogger, get_audit_logger
from hackle.escalation import EscalationHold
from hackle.fingerprint import action_fingerprint
from hackle.llm import LLMClient
from hackle.loop import ExecutorLoop, OllamaLoopModel, RunReport, StepRecord
from hackle.tools import ToolRunner, ToolResult

__version__ = "0.1.0"
__all__ = [
    "ActionClassifier",
    "ActionTier",
    "AuditLogger",
    "get_audit_logger",
    "EscalationHold",
    "action_fingerprint",
    "LLMClient",
    "ExecutorLoop",
    "OllamaLoopModel",
    "RunReport",
    "StepRecord",
    "ToolRunner",
    "ToolResult",
]
