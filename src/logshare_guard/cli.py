"""A small, local-only CLI. Diagnostics never include input values."""

import argparse
from collections import Counter
import json
import math
from pathlib import Path
import sys

from .core import redact

MAX_INPUT_BYTES = 32 * 1024 * 1024


class InputError(ValueError):
    pass


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("Duplicate JSON keys are not supported.")
        result[key] = value
    return result


def _reject_constant(_value):
    raise InputError("Non-finite numbers are not valid JSON.")


def _finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise InputError("Number exceeds the supported finite range.")
    return result


def _parse(text):
    try:
        return json.loads(text, object_pairs_hook=_strict_object,
                          parse_constant=_reject_constant, parse_float=_finite_float)
    except (ValueError, RecursionError):
        raise InputError("Invalid or unsupported JSON input.") from None


def _read_records(path, format_name):
    if format_name == "auto":
        if path.suffix.lower() == ".har":
            raise InputError("HAR files are outside this tool's supported scope.")
        format_name = "jsonl" if path.suffix.lower() in {".jsonl", ".ndjson"} else "json"
    with path.open("rb") as handle:
        raw = handle.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise InputError("Input exceeds the 32 MiB limit.")
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise InputError("Input must be UTF-8.") from None
    if format_name == "json":
        return [_parse(text)], format_name
    records = []
    for line in text.splitlines():
        if line.strip():
            records.append(_parse(line))
    if not records:
        raise InputError("Input contains no JSON records.")
    return records, format_name


def _parser():
    parser = argparse.ArgumentParser(
        description="Check or redact selected secret fields in local JSON/JSONL logs. "
                    "Free text and unknown fields still need manual review.")
    parser.add_argument("command", choices=("check", "redact"))
    parser.add_argument("input", type=Path, nargs="+",
                        help="One or more files for check; exactly one file for redact")
    parser.add_argument("--format", choices=("auto", "json", "jsonl"), default="auto")
    parser.add_argument("--secret-key", action="append", default=[], metavar="KEY",
                        help="Additional exact field name to redact; repeat as needed")
    parser.add_argument("-o", "--output", type=Path,
                        help="New output file for redact; existing files are never overwritten")
    return parser


def main(argv=None):
    parser = _parser()
    args = parser.parse_intermixed_args(argv)
    if args.command == "redact" and args.output is None:
        parser.error("redact requires --output")
    if args.command == "check" and args.output is not None:
        parser.error("--output is only supported for redact")
    if args.command == "redact" and len(args.input) != 1:
        parser.error("redact accepts exactly one input file")
    try:
        sanitized = []
        counts = Counter()
        record_count = 0
        # Check files one at a time: the limit applies to each file and check
        # does not retain redacted copies across the batch. Only report success
        # after every input was parsed and checked successfully.
        for path in args.input:
            records, format_name = _read_records(path, args.format)
            for record in records:
                result, findings = redact(record, extra_keys=args.secret_key)
                if args.command == "redact":
                    sanitized.append(result)
                counts.update(findings)
            record_count += len(records)
        if args.command == "redact":
            if format_name == "jsonl":
                output = "".join(json.dumps(record, ensure_ascii=True, allow_nan=False) + "\n"
                                 for record in sanitized)
            else:
                output = json.dumps(sanitized[0], ensure_ascii=True, allow_nan=False,
                                    indent=2) + "\n"
            # Parse and redact every record before creating any output. Exclusive
            # creation also protects the source and existing symlink/hardlink targets.
            with args.output.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(output)
        summary = {"command": args.command, "files": len(args.input), "records": record_count,
                   "findings": sum(counts.values()), "rules": dict(sorted(counts.items()))}
        print(json.dumps(summary, sort_keys=True))
        return 1 if args.command == "check" and counts else 0
    except InputError as error:
        print("Error: " + str(error), file=sys.stderr)
    except FileExistsError:
        print("Error: Output already exists; choose a new file.", file=sys.stderr)
    except OSError:
        print("Error: Cannot read input or write output. Check paths and permissions.", file=sys.stderr)
    except (ValueError, TypeError, RecursionError, OverflowError):
        print("Error: Invalid or unsupported input structure.", file=sys.stderr)
    return 2
