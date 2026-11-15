# Security evidence

These documents connect the project's security claims to source history, explicit threat assumptions, and offline reproduction. They are maintainer materials prepared with AI assistance, not an independent audit or a CVE acceptance decision.

## Existing public issue

- [Technical advisory: GHSA-8mpg-mvq9-qm96](GHSA-8mpg-mvq9-qm96.md) — control-obscured URL classification, affected/fixed commit matrix, minimal reproduction, impact limits, and proposed CWE.
- [CVE submission record and supporting draft](CVE-SUBMISSION.md) — the verified GitHub request submitted on 2026-11-15, prepared supporting fields, an unsent standalone cover note, and remaining factual questions. No CVE number or acceptance has been observed.
- [Security model and review checklist](THREAT-MODEL.md) — trust boundaries, supported behavior, negative controls, and how to interpret evidence.

The existing issue was fixed in source 0.1.1. Maintained source 0.2.0 retains that fix; an earlier development snapshot carrying 0.2.0 metadata did not. The advisory's full commit matrix is authoritative for the snapshots examined here.

## Separate finding from this review

- [Semicolon query interpretation](query-separator-review.md) — a different redaction problem reproduced in the maintained 0.2.0 baseline, with its own 0.2.1 source fix merged into `main` through PR #3. It has no assigned CVE/GHSA identifier in this package; the older advisory's CVE request does not cover this finding. No packaged release is asserted. Do not infer that the old 0.1.1 scheme-control fix resolved this separate issue.

## Reproduce the evidence

Run from the repository root with Python 3.11 or newer and Git available. The harnesses use local source snapshots and invented fixtures; they make no requests to the fixture URLs. A full clone containing the pinned commits is required. No package installation is needed for these harnesses.

```console
python tools/reproduce_url_control_advisory.py --output security-evidence/url-controls.json
python tools/reproduce_query_separator.py --output security-evidence/query-separator.json
```

Each output path must be new. Generated reports are local artifacts, not edits to the public advisory. Read the recorded environment, source hashes, per-case observations, and final result. A successful differential run means the known defective snapshots behaved as expected and the proposed fixed snapshots met the encoded checks; it does not mean the defective snapshots are safe.

The regular unit tests and the completed CI runs provide additional evidence. [Main run 43711757313](https://github.com/345sugar/logshare-guard/actions/runs/43711757313) passed all six matrix jobs with evidence artifacts for merged-main revision `0052c477861a14c1853b2c8bc4dee08fc5635d43`. No report claims real-world exploitation, third-party adoption, a corporate affiliation, or a guaranteed CVE assignment.
