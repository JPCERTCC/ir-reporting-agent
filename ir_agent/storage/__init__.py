"""Storage Layer.

Provides append-only JSONL stores for evidence ledger, audit logs,
normalized events, and other persistent data.
"""

from ir_agent.storage.store import AppendOnlyStore

__all__ = ["AppendOnlyStore"]
