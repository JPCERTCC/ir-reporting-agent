"""Ingestion Layer.

Responsible for scanning, classifying, hashing, and chunking raw artifact files.
"""

from ir_agent.ingestion.chunker import Chunk, chunk_file
from ir_agent.ingestion.scanner import FileRecord, FileRecordModel, IngestionService

__all__ = ["Chunk", "FileRecord", "FileRecordModel", "IngestionService", "chunk_file"]
