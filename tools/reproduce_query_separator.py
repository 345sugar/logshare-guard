#!/usr/bin/env python3
"""Offline before/after evidence for ambiguous query-separator redaction.

This is a separate issue from GHSA-8mpg-mvq9-qm96. It has no CVE assignment.
The pinned historical source and the working-tree fix are intentionally run on
synthetic local data. No network, package installation, or Git mutation occurs.
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
from urllib.parse import parse_qsl

import reproduce_url_control_advisory as evidence


BASELINE = "9158c1f2828844428e1e9ff3b2507c36b5c9d6fe"
URL = "https://example.test/path?"
MARKER = "%5BREDACTED%5D"


def cases() -> list[dict]:
    return [
        {"id": "sensitive-value-suffix", "query": "password=SYNTHETIC_PREFIX;SYNTHETIC_SUFFIX&view=public",
         "old": f"password={MARKER};SYNTHETIC_SUFFIX&view=public",
         "fixed": f"password={MARKER}&view=public", "old_count": 1, "fixed_count": 1},
        {"id": "raw-semicolon-key", "query": "api;key=SYNTHETIC_SECRET&view=public",
         "old": "api;key=SYNTHETIC_SECRET&view=public", "fixed": f"api;key={MARKER}&view=public",
         "old_count": 0, "fixed_count": 1},
        {"id": "legacy-separator-suffix", "query": "public=1;token=SYNTHETIC_SECRET;SYNTHETIC_SUFFIX&view=public",
         "old": f"public=1;token={MARKER};SYNTHETIC_SUFFIX&view=public",
         "fixed": f"public=1;token={MARKER}&view=public", "old_count": 1, "fixed_count": 1},
        {"id": "encoded-semicolon-value", "query": "password=SYNTHETIC_PREFIX%3BSYNTHETIC_SUFFIX&view=public",
         "old": f"password={MARKER}&view=public", "fixed": f"password={MARKER}&view=public",
         "old_count": 1, "fixed_count": 1},
        {"id": "encoded-semicolon-key", "query": "api%3Bkey=SYNTHETIC_SECRET&view=public",
         "old": f"api%3Bkey={MARKER}&view=public", "fixed": f"api%3Bkey={MARKER}&view=public",
         "old_count": 1, "fixed_count": 1},
        {"id": "custom-normalized-key", "query": "tenant;credential=SYNTHETIC_SECRET&view=public",
         "extra_keys": ["tenant_credential"], "old": "tenant;credential=SYNTHETIC_SECRET&view=public",
         "fixed": f"tenant;credential={MARKER}&view=public", "old_count": 0, "fixed_count": 1},
        {"id": "ordinary-public-query", "query": "public=1;view=public&mode=inspect",
         "old": "public=1;view=public&mode=inspect", "fixed": "public=1;view=public&mode=inspect",
         "old_count": 0, "fixed_count": 0},
        {"id": "separate-sensitive-chunks", "query": "token=SYNTHETIC_ONE&password=SYNTHETIC_TWO&view=public",
         "old": f"token={MARKER}&password={MARKER}&view=public",
         "fixed": f"token={MARKER}&password={MARKER}&view=public", "old_count": 2, "fixed_count": 2},
    ]


def expected(case: dict, historical: bool) -> tuple[str, dict]:
    count = case["old_count" if historical else "fixed_count"]
    return URL + case["old" if historical else "fixed"], {"url_query": count} if count else {}


def inspect_core(sources: dict[str, bytes], historical: bool) -> list[dict]:
    namespace = {"__name__": "query_separator_evidence_core"}
    exec(compile(sources[evidence.SOURCE_FILES[0]], evidence.SOURCE_FILES[0], "exec"), namespace)
    result = []
    for case in cases():
        source = {"url": URL + case["query"], "status": "public"}
        original = copy.deepcopy(source)
        wanted_url, wanted_rules = expected(case, historical)
        wanted = {"url": wanted_url, "status": "public"}
        observed, rules = namespace["redact"](source, extra_keys=case.get("extra_keys", ()))
        result.append({
            "case": case["id"], "input": original, "extra_keys": case.get("extra_keys", []),
            "ampersand_only_interpretation": parse_qsl(case["query"], keep_blank_values=True, separator="&"),
            "expected_output": wanted, "observed_output": observed,
            "expected_rules": wanted_rules, "observed_rules": rules,
            "source_unmodified": source == original,
            "synthetic_secret_retained": "SYNTHETIC_" in json.dumps(observed),
            "passed": observed == wanted and rules == wanted_rules and source == original,
        })
    return result


def inspect_cli(sources: dict[str, bytes], historical: bool) -> list[dict]:
    result = []
    selected = [case for case in cases() if case["id"] in {
        "sensitive-value-suffix", "raw-semicolon-key", "custom-normalized-key", "ordinary-public-query"}]
    with tempfile.TemporaryDirectory(prefix="logshare-query-evidence-") as temporary:
        root = Path(temporary)
        package = root / "logshare_guard"
        package.mkdir()
        (package / "__init__.py").write_text("", encoding="utf-8")
        for name, content in sources.items():
            (package / Path(name).name).write_bytes(content)
        runner = ("import sys; sys.path.insert(0, sys.argv.pop(1)); "
                  "from logshare_guard.cli import main; raise SystemExit(main())")
        for format_name in ("json", "jsonl"):
            for case in selected:
                source = root / f"{case['id']}.{format_name}"
                destination = root / f"{case['id']}.redacted.{format_name}"
                raw = (json.dumps({"url": URL + case["query"], "status": "public"}) + "\n").encode()
                source.write_bytes(raw)
                wanted_url, wanted_rules = expected(case, historical)
                commands = {}
                for command in ("check", "redact"):
                    arguments = [sys.executable, "-I", "-S", "-c", runner, str(root), command, str(source)]
                    for key in case.get("extra_keys", ()):
                        arguments.extend(("--secret-key", key))
                    if command == "redact":
                        arguments.extend(("--output", str(destination)))
                    completed = subprocess.run(arguments, cwd=root, capture_output=True,
                                               text=True, encoding="utf-8", timeout=15)
                    try:
                        summary = json.loads(completed.stdout)
                    except ValueError:
                        summary = None
                    expected_exit = int(bool(wanted_rules)) if command == "check" else 0
                    safe = "SYNTHETIC_" not in completed.stdout + completed.stderr
                    summary_matches = isinstance(summary, dict) and (
                        summary.get("command") == command and summary.get("records") == 1
                        and summary.get("rules") == wanted_rules
                        and summary.get("findings") == sum(wanted_rules.values()))
                    commands[command] = {
                        "exit_code": completed.returncode, "expected_exit_code": expected_exit,
                        "summary": summary, "stderr": completed.stderr,
                        "diagnostics_contain_no_synthetic_secret": safe,
                        "passed": completed.returncode == expected_exit and summary_matches
                        and safe and completed.stderr == "",
                    }
                try:
                    output = json.loads(destination.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    output = None
                wanted = {"url": wanted_url, "status": "public"}
                unchanged = source.read_bytes() == raw
                result.append({"case": case["id"], "format": format_name, "commands": commands,
                               "expected_output": wanted, "observed_output": output,
                               "source_unmodified": unchanged,
                               "passed": all(item["passed"] for item in commands.values())
                               and output == wanted and unchanged})
    return result


def build_report(repo: Path) -> dict:
    snapshots = []
    for label, commit, historical in (("baseline-0.2.0", BASELINE, True), ("working-tree", None, False)):
        sources = evidence.read_sources(repo, commit)
        core = inspect_core(sources, historical)
        cli = inspect_cli(sources, historical)
        snapshots.append({"label": label, "commit": commit,
                          "expectation": "historical defect reproduced" if historical else "defect absent",
                          "source_sha256": {name: hashlib.sha256(value).hexdigest() for name, value in sources.items()},
                          "core": core, "cli": cli, "passed": all(item["passed"] for item in core + cli)})
    return {
        "schema_version": 1, "issue": "URL query separator interpretation mismatch", "cve_id": None,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {"python": platform.python_version(), "implementation": platform.python_implementation(),
                        "platform": platform.platform()},
        "working_tree_head": evidence.git(repo, "rev-parse", "HEAD").decode().strip(),
        "scope": "Local synthetic data only; separate from GHSA-8mpg-mvq9-qm96; no external exploitation established.",
        "counts": {"snapshots": 2, "core_cases_per_snapshot": len(cases()),
                   "cli_cases_per_snapshot": len(snapshots[0]["cli"]),
                   "cli_commands_per_snapshot": 2 * len(snapshots[0]["cli"])},
        "snapshots": snapshots, "passed": all(item["passed"] for item in snapshots),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path, help="New JSON path; never overwrites an existing file")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    arguments = parser.parse_args(argv)
    try:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        with arguments.output.open("x", encoding="utf-8", newline="\n") as handle:
            report = build_report(arguments.repo.resolve())
            json.dump(report, handle, ensure_ascii=True, indent=2)
            handle.write("\n")
    except (OSError, subprocess.SubprocessError) as error:
        print(f"Evidence generation failed ({type(error).__name__}); inspect the local repository and output path.", file=sys.stderr)
        return 2
    print(json.dumps({"issue": report["issue"], "passed": report["passed"], "counts": report["counts"]}, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
