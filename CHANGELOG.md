# Changelog

## 0.2.1 — pending release

- Prevent partial credential disclosure when a sensitive URL query value
  contains a literal semicolon. Check complete ampersand-delimited keys before
  legacy semicolon parsing, including punctuation-normalized keys such as
  `api;key`, and redact ambiguous sensitive suffixes conservatively.
- Track this query-separator issue separately from GHSA-8mpg-mvq9-qm96;
  neither this entry nor the review draft assigns a new CVE or GHSA identifier.
- Add an offline differential reproducer for GHSA-8mpg-mvq9-qm96, pinned
  historical revisions, and machine-readable validation evidence in CI.
- Document the threat model, exact affected source, repair rationale, and a
  CVE submission draft. These documents do not imply a CVE assignment or an
  independent audit.
- Parse JSONL records at LF boundaries, retaining legal Unicode line-separator
  characters inside JSON strings. CRLF record endings remain supported. This
  is an input compatibility correction, separate from the published advisory.

## 0.2.0

- `check` accepts multiple files, including mixed JSON and JSONL inputs when
  using automatic format detection. The 32 MiB input limit applies per file.
- Reports add a `files` count. `records`, `findings`, and `rules` aggregate all
  inputs. Repeated paths count as repeated inputs.
- An unreadable or invalid input returns exit code 2 without printing a partial
  report, even if an earlier input contained findings.
- `redact` continues to require exactly one input and a new output path.
- Add a pre-commit hook, English usage guide, contribution guide, and security
  maintenance policy.

## 0.1.1 — 2026-10-11

### Security

- Recognize HTTP(S) URL candidates whose schemes are obscured by leading C0
  control characters or embedded TAB/CR/LF. The original malformed string is
  fully redacted, preventing supported URL credentials from passing through
  unchanged while `check` reports zero findings.
- Add regression coverage for URL classification, ordinary prose preservation,
  and JSON/JSONL CLI detection and redaction using synthetic data only.

This source release fixes version 0.1.0. The project has not been published on
PyPI. Review output manually before sharing; the documented redaction scope
and limitations still apply. The review and patch used AI assistance.

## 0.1.0

- Initial local JSON/JSONL redaction CLI and Python API.
- Explicit sensitive field rules and HTTP(S) URL handling.
- Count-only CLI reports and exclusive output file creation.

Version numbers identify source/package versions; they do not imply a PyPI
publication, independent audit, or third-party use.
