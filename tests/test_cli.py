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

    def test_control_obscured_urls_are_detected_and_fully_redacted(self):
        urls = (
            "\x00https://user:SYNTHETIC_PASSWORD@example.test/?api_key=SYNTHETIC_TOKEN",
            "ht\ttps://user:SYNTHETIC_PASSWORD@example.test/?api_key=SYNTHETIC_TOKEN",
            "ht\ntps://user:SYNTHETIC_PASSWORD@example.test/?api_key=SYNTHETIC_TOKEN",
            "https\r://user:SYNTHETIC_PASSWORD@example.test/?api_key=SYNTHETIC_TOKEN",
        )
        for extension in ("json", "jsonl"):
            for index, url in enumerate(urls):
                with self.subTest(extension=extension, case=index):
                    source = self.root / f"input-{index}.{extension}"
                    output = self.root / f"output-{index}.{extension}"
                    raw = json.dumps({"url": url, "status": "public"}) + "\n"
                    source.write_text(raw, encoding="utf-8")
                    code, out, err = self.run_cli("check", source)
                    self.assertEqual(code, 1)
                    self.assertEqual(json.loads(out)["rules"], {"invalid_url": 1})
                    self.assertEqual(err, "")
                    self.assertNotIn("SYNTHETIC_", out)
                    code, out, err = self.run_cli("redact", source, "-o", output)
                    self.assertEqual(code, 0)
                    self.assertEqual(json.loads(out)["rules"], {"invalid_url": 1})
                    self.assertEqual(json.loads(output.read_text(encoding="utf-8")),
                                     {"url": "[REDACTED]", "status": "public"})
                    self.assertEqual(err, "")
                    self.assertNotIn("SYNTHETIC_", output.read_text(encoding="utf-8") + out)
                    self.assertEqual(source.read_text(encoding="utf-8"), raw)

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

    def test_check_multiple_formats_aggregates_counts_without_values_or_paths(self):
        first = self.root / "PRIVATE_FIRST.json"
        second = self.root / "PRIVATE_SECOND.ndjson"
        first.write_text('{"password":"PRIVATE_ONE"}', encoding="utf-8")
        second.write_text('{"api_key":"PRIVATE_TWO"}\n{"wait":5}\n', encoding="utf-8")
        originals = [path.read_bytes() for path in (first, second)]
        code, out, err = self.run_cli("check", first, second)
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out), {
            "command": "check", "files": 2, "records": 3,
            "findings": 2, "rules": {"sensitive_key": 2}})
        self.assertEqual(err, "")
        self.assertNotIn("PRIVATE", out)
        self.assertEqual([path.read_bytes() for path in (first, second)], originals)

    def test_control_obscured_urls_in_mixed_batch_keep_security_and_error_contracts(self):
        first = self.root / "SYNTHETIC_PRIVATE.json"
        second = self.root / "SYNTHETIC_PRIVATE.jsonl"
        first.write_text(json.dumps({
            "url": "\x00https://user:SYNTHETIC_PASSWORD@example.test/"}), encoding="utf-8")
        second.write_text(json.dumps({
            "url": "ht\ttps://example.test/?token=SYNTHETIC_TOKEN"})
            + '\n{"status":"public"}\n', encoding="utf-8")
        originals = [path.read_bytes() for path in (first, second)]
        for paths in ((first, second), (second, first)):
            with self.subTest(paths=paths):
                code, out, err = self.run_cli("check", *paths)
                self.assertEqual(code, 1)
                self.assertEqual(json.loads(out), {
                    "command": "check", "files": 2, "records": 3,
                    "findings": 2, "rules": {"invalid_url": 2}})
                self.assertEqual(err, "")
                self.assertNotIn("SYNTHETIC_", out)
        self.assertEqual([path.read_bytes() for path in (first, second)], originals)
        invalid = self.root / "SYNTHETIC_INVALID.json"
        invalid.write_text('{"SYNTHETIC_INVALID":', encoding="utf-8")
        for paths in ((first, second, invalid), (invalid, first, second)):
            with self.subTest(paths=paths):
                code, out, err = self.run_cli("check", *paths)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertNotIn("SYNTHETIC_", err)

    def test_clean_batch_returns_zero(self):
        paths = [self.root / "one.json", self.root / "two.jsonl"]
        for path in paths:
            path.write_text('{"wait":5}', encoding="utf-8")
        code, out, err = self.run_cli("check", *paths)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["files"], 2)
        self.assertEqual(json.loads(out)["records"], 2)
        self.assertEqual(json.loads(out)["findings"], 0)
        self.assertEqual(err, "")

    def test_error_in_batch_takes_precedence_and_emits_no_partial_summary(self):
        first = self.root / "PRIVATE_VALID.json"
        second = self.root / "PRIVATE_INVALID.jsonl"
        first.write_text('{"token":"PRIVATE"}', encoding="utf-8")
        for contents in ('{"PRIVATE":', '{"x":1}\n{"PRIVATE":', None):
            if contents is None:
                second.unlink()
            else:
                second.write_text(contents, encoding="utf-8")
            for paths in ((first, second), (second, first)):
                with self.subTest(contents=contents, paths=paths):
                    code, out, err = self.run_cli("check", *paths)
                    self.assertEqual(code, 2)
                    self.assertEqual(out, "")
                    self.assertNotIn("PRIVATE", err)
                    self.assertNotIn("Traceback", err)

    def test_options_before_between_or_after_batch_paths(self):
        first, second = self.root / "one.data", self.root / "two.data"
        for path in (first, second):
            path.write_text('{"tenantCredential":"PRIVATE"}\n{"wait":5}', encoding="utf-8")
        options = ("--format", "jsonl", "--secret-key", "tenantCredential")
        for args in ((*options, first, second), (first, *options, second), (first, second, *options)):
            with self.subTest(args=args):
                code, out, err = self.run_cli("check", *args)
                self.assertEqual(code, 1)
                self.assertEqual(json.loads(out)["records"], 4)
                self.assertEqual(json.loads(out)["findings"], 2)
                self.assertEqual(err, "")
                self.assertNotIn("PRIVATE", out)

    def test_redact_rejects_multiple_inputs_without_creating_output(self):
        output = self.root / "output.json"
        with self.assertRaises(SystemExit) as caught:
            self.run_cli("redact", self.root / "one.json", self.root / "two.json", "-o", output)
        self.assertEqual(caught.exception.code, 2)
        self.assertFalse(output.exists())

    def test_check_requires_an_input(self):
        with self.assertRaises(SystemExit) as caught:
            self.run_cli("check")
        self.assertEqual(caught.exception.code, 2)

    def test_hook_separator_treats_option_like_filenames_as_inputs(self):
        names = ("-private.json", "--format=jsonl.json", "space name.JSONL")
        for name in names:
            (self.root / name).write_text('{"wait":5}', encoding="utf-8")
        with contextlib.chdir(self.root):
            code, out, err = self.run_cli("check", "--", *names)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["files"], 3)
        self.assertEqual(json.loads(out)["records"], 3)
        self.assertEqual(err, "")


if __name__ == "__main__":
    unittest.main()
