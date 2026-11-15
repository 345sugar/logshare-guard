"""Check evidence-generator contracts without rerunning all historical CLIs."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "reproduce_url_control_advisory.py"
spec = importlib.util.spec_from_file_location("advisory_reproduction", SCRIPT)
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)


class ReproductionTests(unittest.TestCase):
    def test_existing_report_is_not_overwritten_and_no_sources_are_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "report.json"
            destination.write_text("KEEP", encoding="utf-8")
            with patch.object(evidence, "build_report") as build, contextlib.redirect_stderr(io.StringIO()):
                code = evidence.main(["--output", str(destination)])
            self.assertEqual(code, 2)
            build.assert_not_called()
            self.assertEqual(destination.read_text(encoding="utf-8"), "KEEP")

    def test_failed_expectations_are_written_and_return_nonzero(self):
        report = {"advisory": evidence.ADVISORY, "passed": False, "counts": {"snapshots": 1}}
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "nested" / "report.json"
            with patch.object(evidence, "build_report", return_value=report), contextlib.redirect_stdout(io.StringIO()):
                code = evidence.main(["--output", str(destination)])
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(destination.read_text(encoding="utf-8")), report)

    def test_suite_covers_bypass_and_already_rejected_prefixes(self):
        cases = {case["id"]: case for case in evidence.cases()}
        self.assertTrue(cases["c0-prefix-https-00"]["old_bypass"])
        self.assertFalse(cases["c0-prefix-http-09"]["old_bypass"])
        self.assertTrue(cases["scheme-control-HtTp-0d-2"]["old_bypass"])
        self.assertEqual(len(cases), len(evidence.cases()))
        self.assertEqual({case["group"] for case in cases.values()}, {
            "c0-prefix", "scheme-control", "combined-controls", "supported-control", "negative-control"})


if __name__ == "__main__":
    unittest.main()
