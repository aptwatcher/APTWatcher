"""
Tests for the GLPI attachment upload publication adapter.

Every subprocess interaction is routed through the injected
`transport` callable. No real `glpi-mcp` process is ever spawned.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.publish.glpi_attachment import (
    AttachmentTransportResult,
    GLPIAttachmentAdapter,
)
from core.publish.protocol import PublicationAdapter, PublicationError, PublicationResult


def _seed_bundle(root: Path) -> Path:
    """Create a minimal bundle_dir with one file per artifact kind."""
    (root / "rules").mkdir(parents=True)
    (root / "reports").mkdir()
    (root / "iocs").mkdir()
    (root / "rules" / "family.yar").write_text(
        'rule stub { condition: false }\n', encoding="utf-8"
    )
    (root / "reports" / "Campaign_Report_INC1_20260419.docx").write_bytes(
        b"PK\x03\x04fake-docx"
    )
    (root / "iocs" / "ipv4.csv").write_text(
        "value,type\n203.0.113.10,ipv4\n", encoding="utf-8"
    )
    (root / "bundle.json").write_text(
        '{"incident_id": "INC-1"}\n', encoding="utf-8"
    )
    return root


def test_glpi_attachment_is_a_publication_adapter(tmp_path: Path) -> None:
    adapter = GLPIAttachmentAdapter(ticket_id=42, bundle_dir=tmp_path)
    assert isinstance(adapter, PublicationAdapter)
    assert adapter.name == "glpi"


def test_glpi_attachment_rejects_invalid_ticket_id(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        GLPIAttachmentAdapter(ticket_id=0, bundle_dir=tmp_path)
    with pytest.raises(ValueError):
        GLPIAttachmentAdapter(ticket_id=-3, bundle_dir=tmp_path)


def test_glpi_attachment_dry_run_lists_files(tmp_path: Path) -> None:
    bundle_dir = _seed_bundle(tmp_path / "bundle")
    adapter = GLPIAttachmentAdapter(ticket_id=4242, bundle_dir=bundle_dir)

    result = adapter.publish(
        findings=[],
        iocs=[],
        incident_id="INC-1",
        campaign_tag="CAMP",
        dry_run=True,
    )
    assert isinstance(result, PublicationResult)
    assert result.status == "dry_run"
    assert result.target == "4242"
    assert result.details["ticket_id"] == 4242
    assert result.details["file_count"] == 4
    files = result.details["files"]
    # Sorted; forward-slash normalized by rglob on all platforms for display.
    assert any(f.endswith("family.yar") for f in files)
    assert any("Campaign_Report" in f for f in files)
    assert any(f.endswith("ipv4.csv") for f in files)
    assert any(f.endswith("bundle.json") for f in files)


def test_glpi_attachment_submitted_with_fake_transport(tmp_path: Path) -> None:
    bundle_dir = _seed_bundle(tmp_path / "bundle")
    invocations: list[tuple[list[str], dict[str, object]]] = []

    def fake_transport(cmd: list[str], stdin_body: str) -> AttachmentTransportResult:
        parsed = json.loads(stdin_body)
        invocations.append((cmd, parsed))
        return AttachmentTransportResult(
            returncode=0,
            stdout=json.dumps(
                {"attachment_id": 100 + len(invocations), "ok": True}
            ),
            stderr="",
        )

    adapter = GLPIAttachmentAdapter(
        ticket_id=777,
        bundle_dir=bundle_dir,
        glpi_mcp_command=["glpi-mcp", "--stdio"],
        transport=fake_transport,
    )
    result = adapter.publish(
        findings=[],
        iocs=[],
        incident_id="INC-42",
        campaign_tag="CAMP-A",
        dry_run=False,
    )
    assert result.status == "submitted"
    assert result.target == "777"
    assert result.details["file_count"] == 4
    assert len(invocations) == 4
    for cmd, payload in invocations:
        assert cmd == ["glpi-mcp", "--stdio"]
        assert payload["tool"] == "glpi.attachment.add"
        assert payload["arguments"]["ticket_id"] == 777
        assert payload["arguments"]["filename"]
        assert "INC-42" in payload["arguments"]["comment"]
        assert "CAMP-A" in payload["arguments"]["comment"]


def test_glpi_attachment_nonzero_exit_raises(tmp_path: Path) -> None:
    bundle_dir = _seed_bundle(tmp_path / "bundle")

    def fake_transport(cmd: list[str], stdin_body: str) -> AttachmentTransportResult:
        return AttachmentTransportResult(
            returncode=7,
            stdout="",
            stderr="glpi-mcp: permission denied on ticket 777",
        )

    adapter = GLPIAttachmentAdapter(
        ticket_id=777,
        bundle_dir=bundle_dir,
        transport=fake_transport,
    )
    with pytest.raises(PublicationError) as exc_info:
        adapter.publish(
            findings=[],
            iocs=[],
            incident_id="INC-X",
            campaign_tag="X",
            dry_run=False,
        )
    assert "permission denied" in str(exc_info.value)


def test_glpi_attachment_missing_bundle_dir_in_real_mode_raises(tmp_path: Path) -> None:
    # bundle_dir exists but is empty
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()

    def fake_transport(cmd: list[str], stdin_body: str) -> AttachmentTransportResult:
        return AttachmentTransportResult(returncode=0, stdout="{}")

    adapter = GLPIAttachmentAdapter(
        ticket_id=1,
        bundle_dir=empty_dir,
        transport=fake_transport,
    )
    with pytest.raises(PublicationError):
        adapter.publish(
            findings=[],
            iocs=[],
            incident_id="INC-E",
            campaign_tag="E",
            dry_run=False,
        )


def test_glpi_attachment_dry_run_empty_bundle_is_ok(tmp_path: Path) -> None:
    """Empty bundle in dry-run is fine — operator just sees zero files."""
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    adapter = GLPIAttachmentAdapter(ticket_id=1, bundle_dir=empty_dir)
    result = adapter.publish(
        findings=[],
        iocs=[],
        incident_id="INC-E",
        campaign_tag="E",
        dry_run=True,
    )
    assert result.status == "dry_run"
    assert result.details["file_count"] == 0
    assert result.details["files"] == []
