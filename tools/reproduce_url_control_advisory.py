#!/usr/bin/env python3
"""Offline differential evidence for GHSA-8mpg-mvq9-qm96.

Only two allow-listed package files are read from four pinned local Git objects
and the working tree. No checkout, package install, network request or repository
hook is performed. Historical source is executed intentionally, on invented
data in temporary directories. Run only against this trusted repository.
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


ADVISORY = "GHSA-8mpg-mvq9-qm96"
SNAPSHOTS = (
    ("vulnerable-0.1.0", "586459f5f4423aa10225bd01effda47de0734b7a", True),
    ("initial-fix-0.1.1", "5aee1c136b846d2a7ca51f07995d099f138a5d19", False),
    ("main-fix-merge", "17d93dc14114cd55feb5845faa928607f85b1ebd", False),
    ("maintained-0.2.0", "9158c1f2828844428e1e9ff3b2507c36b5c9d6fe", False),
    ("working-tree", None, False),
)
SOURCE_FILES = ("src/logshare_guard/core.py", "src/logshare_guard/cli.py")
MARKER = "[REDACTED]"
SYNTHETIC_VALUES = ("SYNTHETIC_PASSWORD", "SYNTHETIC_TOKEN")
TAIL = "://demo-user:SYNTHETIC_PASSWORD@example.test/path?api_key=SYNTHETIC_TOKEN&view=public"
SCHEMES = ("http", "https", "HtTp", "hTtPs")
# Python's str.strip removes these C0 characters. In the historical code they
# expose the scheme before original-string validation, so these already fail
# closed. Keep them as controls rather than claiming every C0 prefix bypassed.
STRIPPED_C0 = frozenset((9, 10, 11, 12, 13, 28, 29, 30, 31))


def git(repo: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), *arguments], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    )
    return result.stdout


def cases() -> list[dict]:
    result = []
    for scheme in SCHEMES:
        for code in range(32):
            result.append({"id": f"c0-prefix-{scheme}-{code:02x}",
                           "group": "c0-prefix", "url": chr(code) + scheme + TAIL,
                           "old_bypass": code not in STRIPPED_C0})
        for code in (9, 10, 13):
            for position in range(1, len(scheme) + 1):
                result.append({"id": f"scheme-control-{scheme}-{code:02x}-{position}",
                               "group": "scheme-control",
                               "url": scheme[:position] + chr(code) + scheme[position:] + TAIL,
                               "old_bypass": True})
        for prefix in ("\x00 \t", "\x1b\x00", "\t\x00"):
            result.append({"id": f"combined-{scheme}-{prefix.encode().hex()}",
                           "group": "combined-controls",
                           "url": prefix + scheme[0] + "\n" + scheme[1:] + TAIL,
                           "old_bypass": True})
    result.extend((
        {"id": "ordinary-sensitive-url", "group": "supported-control",
         "url": "https" + TAIL, "expected_url":
         "https://example.test/path?api_key=%5BREDACTED%5D&view=public",
         "expected_rules": {"url_userinfo": 1, "url_query": 1}},
        {"id": "public-url", "group": "negative-control",
         "url": "https://example.test/path?view=public", "expected_rules": {}},
        {"id": "ordinary-prose", "group": "negative-control",
         "url": "See https://example.test/public for a public example.", "expected_rules": {}},
        {"id": "non-http-scheme", "group": "negative-control",
         "url": "custom://example.test/public", "expected_rules": {}},
    ))
    return result


def expected(case: dict, vulnerable: bool) -> tuple[str, dict]:
    if "expected_rules" in case:
        return case.get("expected_url", case["url"]), case["expected_rules"]
    if vulnerable and case["old_bypass"]:
        return case["url"], {}
    return MARKER, {"invalid_url": 1}


def read_sources(repo: Path, commit: str | None) -> dict[str, bytes]:
    return {name: git(repo, "show", f"{commit}:{name}") if commit
            else (repo / name).read_bytes() for name in SOURCE_FILES}


def core_evidence(sources: dict[str, bytes], vulnerable: bool) -> list[dict]:
    namespace = {"__name__": "advisory_evidence_core"}
    source = sources[SOURCE_FILES[0]]
    exec(compile(source, SOURCE_FILES[0], "exec"), namespace)
    redact = namespace["redact"]
    observations = []
    for case in cases():
        original = {"url": case["url"], "context": {"status": "public"}}
        before = copy.deepcopy(original)
        wanted_url, wanted_rules = expected(case, vulnerable)
        wanted = {"url": wanted_url, "context": {"status": "public"}}
        try:
            observed, rules = redact(original)
            source_unmodified = original == before
            passed = observed == wanted and rules == wanted_rules and source_unmodified
            observations.append({"case": case["id"], "group": case["group"],
                                 "input": before, "expected_output": wanted,
                                 "observed_output": observed, "expected_rules": wanted_rules,
                                 "observed_rules": rules, "source_unmodified": source_unmodified,
                                 "passed": passed})
        except Exception as error:  # Record a failure and keep the remaining evidence.
            observations.append({"case": case["id"], "group": case["group"],
                                 "input": before, "error_type": type(error).__name__,
                                 "passed": False})
    return observations


def cli_evidence(sources: dict[str, bytes], vulnerable: bool) -> list[dict]:
    selected = {case["id"]: case for case in cases()}
    # Cover both sides of the historical boundary, both URL schemes, and the
    # ordinary supported URL path. Core evidence covers the full matrix above.
    identifiers = ("c0-prefix-https-00", "c0-prefix-http-09",
                   "scheme-control-HtTp-0d-2", "ordinary-sensitive-url", "public-url")
    observations = []
    with tempfile.TemporaryDirectory(prefix="logshare-cve-evidence-") as temporary:
        root = Path(temporary)
        package = root / "logshare_guard"
        package.mkdir()
        (package / "__init__.py").write_text("", encoding="utf-8")
        for name, content in sources.items():
            (package / Path(name).name).write_bytes(content)
        # -I excludes external PYTHONPATH and user site packages; -S excludes
        # site initialization. Only this explicitly extracted package is added.
        runner = ("import sys; sys.path.insert(0, sys.argv.pop(1)); "
                  "from logshare_guard.cli import main; raise SystemExit(main())")
        for format_name in ("json", "jsonl"):
            for identifier in identifiers:
                case = selected[identifier]
                source = root / f"{identifier}.{format_name}"
                output = root / f"{identifier}.redacted.{format_name}"
                input_value = {"url": case["url"], "status": "public"}
                input_bytes = (json.dumps(input_value) + "\n").encode("utf-8")
                source.write_bytes(input_bytes)
                wanted_url, wanted_rules = expected(case, vulnerable)
                wanted_value = {"url": wanted_url, "status": "public"}
                commands = {}
                for command in ("check", "redact"):
                    arguments = [sys.executable, "-I", "-S", "-c", runner, str(root),
                                 command, str(source)]
                    if command == "redact":
                        arguments.extend(("--output", str(output)))
                    process = subprocess.run(arguments, cwd=root, capture_output=True,
                                             text=True, encoding="utf-8", timeout=15)
                    try:
                        summary = json.loads(process.stdout)
                    except ValueError:
                        summary = None
                    expected_exit = int(bool(wanted_rules)) if command == "check" else 0
                    diagnostics_safe = not any(value in process.stdout + process.stderr
                                               for value in SYNTHETIC_VALUES)
                    summary_matches = isinstance(summary, dict) and (
                        summary.get("command") == command and summary.get("records") == 1
                        and summary.get("findings") == sum(wanted_rules.values())
                        and summary.get("rules") == wanted_rules
                    )
                    commands[command] = {
                        "exit_code": process.returncode, "expected_exit_code": expected_exit,
                        "summary": summary, "stderr": process.stderr,
                        "diagnostics_contain_no_synthetic_secret": diagnostics_safe,
                        "passed": process.returncode == expected_exit and summary_matches
                        and diagnostics_safe and process.stderr == "",
                    }
                try:
                    output_value = json.loads(output.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    output_value = None
                unchanged = source.read_bytes() == input_bytes
                passed = (all(item["passed"] for item in commands.values())
                          and output_value == wanted_value and unchanged)
                observations.append({"case": identifier, "format": format_name,
                                     "commands": commands, "expected_output": wanted_value,
                                     "observed_output": output_value,
                                     "source_unmodified": unchanged, "passed": passed})
    return observations


def build_report(repo: Path) -> dict:
    results = []
    for label, commit, vulnerable in SNAPSHOTS:
        sources = read_sources(repo, commit)
        core = core_evidence(sources, vulnerable)
        cli = cli_evidence(sources, vulnerable)
        results.append({
            "label": label, "commit": commit,
            "expectation": "historical defect reproduced" if vulnerable else "defect absent",
            "source_sha256": {name: hashlib.sha256(content).hexdigest()
                              for name, content in sources.items()},
            "core": core, "cli": cli,
            "passed": all(item["passed"] for item in core + cli),
        })
    return {
        "schema_version": 1, "advisory": ADVISORY,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {"python": platform.python_version(),
                        "implementation": platform.python_implementation(),
                        "platform": platform.platform()},
        "working_tree_head": git(repo, "rev-parse", "HEAD").decode().strip(),
        "scope": "Local synthetic data only; no external exploitation or CVE acceptance established.",
        "counts": {"snapshots": len(results), "core_cases_per_snapshot": len(cases()),
                   "cli_cases_per_snapshot": len(results[0]["cli"]),
                   "cli_commands_per_snapshot": 2 * len(results[0]["cli"])},
        "snapshots": results, "passed": all(item["passed"] for item in results),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path,
                        help="New JSON report path; existing files are never overwritten")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1],
                        help="Trusted local logshare-guard Git repository")
    arguments = parser.parse_args(argv)
    try:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        # Reserve the destination before running historical code. Exclusive
        # creation prevents replacing a file, including symlinks and the source.
        with arguments.output.open("x", encoding="utf-8", newline="\n") as handle:
            report = build_report(arguments.repo.resolve())
            json.dump(report, handle, indent=2, ensure_ascii=True)
            handle.write("\n")
    except (OSError, subprocess.SubprocessError) as error:
        print(f"Evidence generation failed ({type(error).__name__}); inspect the local repository and output path.",
              file=sys.stderr)
        return 2
    print(json.dumps({"advisory": ADVISORY, "passed": report["passed"],
                      "counts": report["counts"]}, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
