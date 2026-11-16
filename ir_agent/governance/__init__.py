"""Governance Layer.

Responsible for human approval gates, audit logging, prompt injection guarding,
and sensitive data protection.
"""

from ir_agent.governance.approval import ApprovalGate
from ir_agent.governance.audit import AuditLogger, AuditWriteError
from ir_agent.governance.injection_guard import PromptInjectionGuard

__all__ = ["ApprovalGate", "AuditLogger", "AuditWriteError", "PromptInjectionGuard"]
