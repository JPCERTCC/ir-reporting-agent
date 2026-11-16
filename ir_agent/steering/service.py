"""Case Steering Service.

Provides loading, validation, and access to the case manifest configuration.
Reads manifest.yaml from the case directory, validates via Pydantic models,
and exposes accessors for expression policy and LLM configuration.
"""

from pathlib import Path
from typing import Optional

import yaml
from pydantic import ValidationError

from ir_agent.steering.manifest import CaseManifest, ExpressionPolicy


class ManifestNotLoadedError(Exception):
    """Raised when accessing manifest data before loading."""

    pass


class ManifestLoadError(Exception):
    """Raised when manifest.yaml cannot be read or parsed."""

    pass


class ManifestValidationError(Exception):
    """Raised when manifest.yaml fails Pydantic validation."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__(f"Manifest validation failed: {'; '.join(errors)}")


class CaseSteeringService:
    """Manages case manifest loading, validation, and configuration access.

    The service loads manifest.yaml from a case directory, validates it using
    Pydantic models, and provides accessors for the expression policy and LLM
    configuration.
    """

    def __init__(self) -> None:
        self._manifest: Optional[CaseManifest] = None

    @property
    def manifest(self) -> CaseManifest:
        """Return the currently loaded manifest, or raise if not loaded."""
        if self._manifest is None:
            raise ManifestNotLoadedError(
                "No manifest loaded. Call load_manifest(case_dir) first."
            )
        return self._manifest

    def load_manifest(self, case_dir: Path) -> CaseManifest:
        """Load and parse manifest.yaml from the case directory.

        Reads the YAML file, validates it against the CaseManifest Pydantic model,
        and stores the result for subsequent accessor calls.

        Args:
            case_dir: Path to the case directory containing manifest.yaml.

        Returns:
            The validated CaseManifest instance.

        Raises:
            ManifestLoadError: If the file cannot be read or parsed as YAML.
            ManifestValidationError: If the YAML content fails Pydantic validation.
        """
        manifest_path = Path(case_dir) / "manifest.yaml"

        if not manifest_path.exists():
            raise ManifestLoadError(
                f"Manifest file not found: {manifest_path}"
            )

        try:
            raw_text = manifest_path.read_text(encoding="utf-8")
        except OSError as e:
            raise ManifestLoadError(
                f"Failed to read manifest file: {manifest_path}: {e}"
            ) from e

        try:
            data = yaml.safe_load(raw_text)
        except yaml.YAMLError as e:
            raise ManifestLoadError(
                f"Failed to parse YAML in {manifest_path}: {e}"
            ) from e

        if data is None:
            raise ManifestLoadError(
                f"Manifest file is empty: {manifest_path}"
            )

        if not isinstance(data, dict):
            raise ManifestLoadError(
                f"Manifest YAML root must be a mapping, got {type(data).__name__}"
            )

        # Validate using Pydantic
        errors = self.validate_manifest(data)
        if errors:
            raise ManifestValidationError(errors)

        self._manifest = CaseManifest(**data)
        return self._manifest

    def validate_manifest(self, manifest: dict | CaseManifest) -> list[str]:
        """Validate a manifest dict or instance against the CaseManifest schema.

        Uses Pydantic model validation to check required fields and types.

        Args:
            manifest: Either a dict of raw YAML data or a CaseManifest instance.

        Returns:
            A list of validation error strings. Empty list means valid.
        """
        if isinstance(manifest, CaseManifest):
            # Already a valid Pydantic model instance
            return []

        if not isinstance(manifest, dict):
            return [f"Manifest must be a dict, got {type(manifest).__name__}"]

        try:
            CaseManifest(**manifest)
            return []
        except ValidationError as e:
            errors: list[str] = []
            for err in e.errors():
                loc = " -> ".join(str(part) for part in err["loc"])
                msg = err["msg"]
                errors.append(f"{loc}: {msg}")
            return errors

    def reload_manifest(self, case_dir: Path) -> CaseManifest:
        """Re-read the manifest from disk for mid-session configuration updates.

        This allows the analyst to modify manifest.yaml between operations and
        have the service pick up the changes.

        Args:
            case_dir: Path to the case directory containing manifest.yaml.

        Returns:
            The freshly loaded and validated CaseManifest instance.

        Raises:
            ManifestLoadError: If the file cannot be read or parsed.
            ManifestValidationError: If validation fails.
        """
        return self.load_manifest(case_dir)

    def get_expression_policy(self) -> ExpressionPolicy:
        """Return the expression policy from the loaded manifest.

        Returns:
            The ExpressionPolicy defining permitted and prohibited language
            for each confidence level.

        Raises:
            ManifestNotLoadedError: If no manifest has been loaded.
        """
        return self.manifest.expression_policy

