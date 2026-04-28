import json

from scanners.Rust.rust_sarif import export_to_sarif


def test_export_to_sarif_creates_valid_sarif_file(tmp_path):
    output_path = tmp_path / "rust_report.sarif"

    export_to_sarif([], str(output_path))

    assert output_path.exists(), "SARIF file was not created"

    data = json.loads(output_path.read_text(encoding="utf-8"))

    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert "runs" in data
    assert isinstance(data["runs"], list)