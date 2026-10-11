# Changelog

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
