import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from logshare_guard.cli import main


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def run_cli(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = main([str(arg) for arg in args])
        return result, stdout.getvalue(), stderr.getvalue()

    def test_check_reports_only_counts_and_does_not_modify_source(self):
        source = self.root / "secret-in-filename.json"
        raw = '{"password":"UNIQUE_PRIVATE_VALUE","wait_minutes":20}'
        source.write_text(raw, encoding="utf-8")
        code, out, err = self.run_cli("check", source)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["findings"], 1)
        self.assertEqual(source.read_text(encoding="utf-8"), raw)
        self.assertNotIn("UNIQUE_PRIVATE_VALUE", out + err)
        self.assertNotIn("secret-in-filename", out + err)
        self.assertEqual(err, "")

    def test_jsonl_redaction_preserves_records_and_non_secret_values(self):
        source, output = self.root / "input.ndjson", self.root / "output.jsonl"
        original = '\ufeff{"password":"PRIVATE_ONE","wait":0}\n\n{"api_key":"PRIVATE_TWO","ok":true}\n'
        source.write_text(original, encoding="utf-8")
        code, out, err = self.run_cli("redact", source, "-o", output)
        self.assertEqual(code, 0)
        text = output.read_text(encoding="utf-8")
        self.assertNotIn("PRIVATE_", text + out + err)
        self.assertEqual([json.loads(line) for line in text.splitlines()], [
            {"password": "[REDACTED]", "wait": 0},
            {"api_key": "[REDACTED]", "ok": True}])
        self.assertEqual(source.read_text(encoding="utf-8"), original)

    def test_invalid_final_record_never_creates_partial_output_or_echoes_input(self):
        source, output = self.root / "input.jsonl", self.root / "output.jsonl"
        source.write_text('{"password":"PRIVATE"}\n{"PRIVATE_INVALID":', encoding="utf-8")
        code, out, err = self.run_cli("redact", source, "-o", output)
        self.assertEqual(code, 2)
        self.assertFalse(output.exists())
        self.assertNotIn("PRIVATE", out + err)

    def test_existing_output_and_source_are_never_overwritten(self):
        source, output = self.root / "input.json", self.root / "output.json"
        source.write_text('{"token":"PRIVATE"}', encoding="utf-8")
        output.write_text("KEEP THIS", encoding="utf-8")
        for destination in (source, output):
            with self.subTest(destination=destination.name):
                self.assertEqual(self.run_cli("redact", source, "-o", destination)[0], 2)
        self.assertEqual(output.read_text(encoding="utf-8"), "KEEP THIS")
        self.assertEqual(source.read_text(encoding="utf-8"), '{"token":"PRIVATE"}')

    def test_strict_json_rejects_duplicate_keys_nan_and_invalid_unicode(self):
        source, output = self.root / "input.json", self.root / "output.json"
        for raw in (b'{"password":"PRIVATE","password":1}', b'{"x":NaN}',
                    b'{"x":1e400}', b'\xffPRIVATE'):
            with self.subTest(raw=raw[:8]):
                source.write_bytes(raw)
                code, out, err = self.run_cli("redact", source, "-o", output)
                self.assertEqual(code, 2)
                self.assertFalse(output.exists())
                self.assertNotIn("PRIVATE", out + err)

    def test_custom_field_and_clean_exit_status(self):
        source = self.root / "input.json"
        source.write_text('{"internalCredential":"PRIVATE"}', encoding="utf-8")
        self.assertEqual(self.run_cli("check", source)[0], 0)
        code, out, err = self.run_cli("check", source, "--secret-key", "internal_credential")
        self.assertEqual(code, 1)
        self.assertNotIn("PRIVATE", out + err)

    def test_deep_input_is_rejected_without_traceback(self):
        source = self.root / "deep.json"
        source.write_text("[" * 2000 + '"PRIVATE"' + "]" * 2000, encoding="utf-8")
        code, out, err = self.run_cli("check", source)
        self.assertEqual(code, 2)
        self.assertNotIn("PRIVATE", out + err)
        self.assertNotIn("Traceback", err)

    def test_missing_file_does_not_echo_path(self):
        code, out, err = self.run_cli("check", self.root / "PRIVATE_PATH.json")
        self.assertEqual(code, 2)
        self.assertNotIn("PRIVATE_PATH", out + err)

    def test_har_auto_format_is_explicitly_unsupported(self):
        source = self.root / "input.har"
        source.write_text("{}", encoding="utf-8")
        self.assertEqual(self.run_cli("check", source)[0], 2)


if __name__ == "__main__":
    unittest.main()
