"""Tests for compliance attestation and integrity verification."""

from agent_guard import GovernanceVerifier, GovernanceAttestation, IntegrityVerifier


class TestGovernanceVerifier:
    def test_verify_all_controls(self):
        verifier = GovernanceVerifier()
        attestation = verifier.verify()
        assert attestation.total_controls == 10
        assert attestation.implemented_controls == 10
        assert attestation.coverage_score == 1.0
        assert attestation.fully_compliant

    def test_attestation_has_hash(self):
        verifier = GovernanceVerifier()
        attestation = verifier.verify()
        assert len(attestation.hash) == 64

    def test_controls_detail(self):
        verifier = GovernanceVerifier()
        attestation = verifier.verify()
        control_ids = {c.control_id for c in attestation.controls}
        assert "ASI-01" in control_ids
        assert "ASI-10" in control_ids

    def test_summary(self):
        verifier = GovernanceVerifier()
        summary = verifier.summary()
        assert summary["owasp_coverage"] == "100%"
        assert summary["fully_compliant"]

    def test_export_attestation(self, tmp_path):
        verifier = GovernanceVerifier()
        attestation = verifier.verify()
        out = tmp_path / "attestation.json"
        verifier.export_attestation(attestation, out)
        assert out.exists()
        import json
        data = json.loads(out.read_text())
        assert data["coverage_score"] == 1.0


class TestIntegrityVerifier:
    def test_generate_baseline(self):
        verifier = IntegrityVerifier()
        baseline = verifier.generate_baseline()
        assert "agent_guard.core.engine" in baseline
        assert len(baseline) > 5

    def test_verify_against_baseline(self):
        verifier = IntegrityVerifier()
        baseline = verifier.generate_baseline()
        report = verifier.verify(baseline)
        assert report.all_valid
        assert report.modules_checked > 0

    def test_quick_check(self):
        verifier = IntegrityVerifier()
        assert verifier.quick_check()
