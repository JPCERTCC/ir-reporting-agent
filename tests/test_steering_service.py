"""Unit tests for ir_agent.steering.service.CaseSteeringService."""

from pathlib import Path

import pytest
import yaml

from ir_agent.steering.manifest import (
    ExpressionPolicy,
)
from ir_agent.steering.service import (
    CaseSteeringService,
    ManifestLoadError,
    ManifestNotLoadedError,
    ManifestValidationError,
)

VALID_MANIFEST_DATA = {
    "case_id": "CASE-2024-001",
    "case_name": "Test Incident Investigation",
    "scope": "Full investigation of lateral movement via compromised VPN",
    "hosts": ["host01", "host02", "dc01"],
    "time_range": {
        "start": "2024-01-15T00:00:00Z",
        "end": "2024-01-20T23:59:59Z",
    },
    "report_language": "ja",
    "review_language": "ja",
    "report_timezone": "Asia/Tokyo",
}


@pytest.fixture
def case_dir(tmp_path: Path) -> Path:
    """Create a case directory with a valid manifest.yaml."""
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(yaml.dump(VALID_MANIFEST_DATA), encoding="utf-8")
    return tmp_path


@pytest.fixture
def service() -> CaseSteeringService:
    """Create a fresh CaseSteeringService instance."""
    return CaseSteeringService()


class TestLoadManifest:
    def test_loads_valid_manifest(self, service: CaseSteeringService, case_dir: Path):
        manifest = service.load_manifest(case_dir)
        assert manifest.case_id == "CASE-2024-001"
        assert manifest.case_name == "Test Incident Investigation"
        assert manifest.hosts == ["host01", "host02", "dc01"]
        assert manifest.time_range.start == "2024-01-15T00:00:00Z"
        assert manifest.time_range.end == "2024-01-20T23:59:59Z"

    def test_loads_defaults_for_optional_fields(
        self, service: CaseSteeringService, case_dir: Path
    ):
        manifest = service.load_manifest(case_dir)
        assert manifest.report_language == "ja"
        assert manifest.review_language == "ja"
        assert manifest.report_timezone == "Asia/Tokyo"
        assert manifest.max_chunk_size == 3000
        assert manifest.chunk_overlap == 50
        assert isinstance(manifest.expression_policy, ExpressionPolicy)

    def test_raises_on_missing_file(self, service: CaseSteeringService, tmp_path: Path):
        with pytest.raises(ManifestLoadError, match="not found"):
            service.load_manifest(tmp_path)

    def test_raises_on_invalid_yaml(
        self, service: CaseSteeringService, tmp_path: Path
    ):
        manifest_path = tmp_path / "manifest.yaml"
        manifest_path.write_text("{{invalid: yaml: [", encoding="utf-8")
        with pytest.raises(ManifestLoadError, match="Failed to parse YAML"):
            service.load_manifest(tmp_path)

    def test_raises_on_empty_file(self, service: CaseSteeringService, tmp_path: Path):
        manifest_path = tmp_path / "manifest.yaml"
        manifest_path.write_text("", encoding="utf-8")
        with pytest.raises(ManifestLoadError, match="empty"):
            service.load_manifest(tmp_path)

    def test_raises_on_non_mapping_yaml(
        self, service: CaseSteeringService, tmp_path: Path
    ):
        manifest_path = tmp_path / "manifest.yaml"
        manifest_path.write_text("- a list\n- not a mapping\n", encoding="utf-8")
        with pytest.raises(ManifestLoadError, match="must be a mapping"):
            service.load_manifest(tmp_path)

    def test_raises_validation_error_on_missing_required_fields(
        self, service: CaseSteeringService, tmp_path: Path
    ):
        manifest_path = tmp_path / "manifest.yaml"
        # Missing case_name, scope, hosts, time_range
        manifest_path.write_text(
            yaml.dump({"case_id": "CASE-001"}), encoding="utf-8"
        )
        with pytest.raises(ManifestValidationError) as exc_info:
            service.load_manifest(tmp_path)
        # Should identify which fields are missing
        assert len(exc_info.value.errors) > 0
        error_text = str(exc_info.value)
        assert "case_name" in error_text or "scope" in error_text

    def test_stores_manifest_for_accessors(
        self, service: CaseSteeringService, case_dir: Path
    ):
        service.load_manifest(case_dir)
        # Should not raise
        assert service.manifest.case_id == "CASE-2024-001"


class TestValidateManifest:
    def test_valid_dict_returns_empty_errors(self, service: CaseSteeringService):
        errors = service.validate_manifest(VALID_MANIFEST_DATA)
        assert errors == []

    def test_valid_model_instance_returns_empty_errors(
        self, service: CaseSteeringService, case_dir: Path
    ):
        manifest = service.load_manifest(case_dir)
        errors = service.validate_manifest(manifest)
        assert errors == []

    def test_missing_fields_returns_error_descriptions(
        self, service: CaseSteeringService
    ):
        errors = service.validate_manifest({"case_id": "CASE-001"})
        assert len(errors) > 0
        # Check that errors mention specific missing fields
        all_errors = " ".join(errors)
        assert "case_name" in all_errors

    def test_invalid_type_returns_errors(self, service: CaseSteeringService):
        invalid_data = {**VALID_MANIFEST_DATA, "hosts": "not-a-list"}
        errors = service.validate_manifest(invalid_data)
        assert len(errors) > 0

    def test_non_dict_input_returns_error(self, service: CaseSteeringService):
        errors = service.validate_manifest("not a dict")  # type: ignore
        assert len(errors) == 1
        assert "dict" in errors[0]


class TestReloadManifest:
    def test_reload_picks_up_changes(
        self, service: CaseSteeringService, case_dir: Path
    ):
        service.load_manifest(case_dir)
        assert service.manifest.case_name == "Test Incident Investigation"

        # Modify the manifest
        updated_data = {**VALID_MANIFEST_DATA, "case_name": "Updated Name"}
        manifest_path = case_dir / "manifest.yaml"
        manifest_path.write_text(yaml.dump(updated_data), encoding="utf-8")

        # Reload and verify
        manifest = service.reload_manifest(case_dir)
        assert manifest.case_name == "Updated Name"
        assert service.manifest.case_name == "Updated Name"


class TestAccessorsBeforeLoad:
    def test_get_expression_policy_raises_before_load(
        self, service: CaseSteeringService
    ):
        with pytest.raises(ManifestNotLoadedError):
            service.get_expression_policy()

    def test_manifest_property_raises_before_load(self, service: CaseSteeringService):
        with pytest.raises(ManifestNotLoadedError):
            _ = service.manifest


class TestAccessorsAfterLoad:
    def test_get_expression_policy(
        self, service: CaseSteeringService, case_dir: Path
    ):
        service.load_manifest(case_dir)
        policy = service.get_expression_policy()
        assert isinstance(policy, ExpressionPolicy)



