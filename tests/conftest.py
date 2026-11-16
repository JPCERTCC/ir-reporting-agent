"""Shared test setup.

``ir-agent init`` writes a template manifest that ``ingest`` and
``build-coverage`` refuse to run on (a human must fill in the case scope).
Tests that drive the CLI from ``init`` get a filled-in template instead; tests
of the template gate import ``MANIFEST_TEMPLATE`` at module import time, which
keeps the real template.
"""

from __future__ import annotations

import pytest

import ir_agent.cli.main as cli_main

FILLED_TEMPLATE = (
    cli_main.MANIFEST_TEMPLATE
    .replace('case_name: "Untitled Case"', 'case_name: "Test Case"')
    .replace('scope: "Define investigation scope here"', 'scope: "Test investigation scope"')
    .replace('  - "host01"', '  - "WEB01"')
    .replace("2024-01-01T00:00:00Z", "2024-01-01T00:00:01Z")
)


@pytest.fixture(autouse=True)
def _filled_manifest_template(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli_main, "MANIFEST_TEMPLATE", FILLED_TEMPLATE)
