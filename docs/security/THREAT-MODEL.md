# Security model and review checklist

This document describes the supported security boundaries of `logshare-guard` and the evidence needed to evaluate GHSA-8mpg-mvq9-qm96. It is not a claim that every secret format is recognized or that the repository has passed an independent security audit.

## Assets, workflow, and trust boundaries

The asset is sensitive data already present in a local JSON/JSONL/NDJSON file. `logshare-guard` runs with the caller's filesystem permissions, parses that file, traverses its JSON values, and either returns aggregate findings (`check`) or creates a new transformed file (`redact`). The caller decides whether and where to distribute that file. No network transfer is part of the tool's workflow.

| Boundary | Intended behavior | Relevant failure |
| --- | --- | --- |
| Untrusted input bytes to JSON values | Reject unsupported or malformed input with a fixed diagnostic; do not echo input contents | Diagnostic leakage, ambiguous parsing, or processing partial invalid input |
| Parsed values to redaction policy | Replace complete values under explicitly supported sensitive keys; handle supported HTTP(S) components and malformed URL candidates | A supported secret passes through, or a sensitive container is only partly replaced |
| URL classification to validation | Account for parser-ignored syntax during classification, then reject controls in the original string | GHSA-8mpg-mvq9-qm96: early classification skips validation and preserves a secret-bearing string |
| Process results to console | Emit aggregate counts and fixed rule identifiers | Input values, keys, or paths leak through diagnostics (argument parsing has its separately documented behavior) |
| Process results to filesystem | Create a new output file after successful parsing and transformation; do not overwrite input or an existing output | Unintended write or source loss; write failures can still leave an incomplete transformed file |
| Transformed file to a recipient | Caller reviews remaining content and chooses the recipient | Secrets outside the supported policy, or a redaction bypass, are shared |

## What this issue does and does not establish

The historic bypass is a mismatch between URL recognition and validation. It is reproducible in a synthetic string value under a neutral JSON key. A control-obscured URL under a sensitive parent key is already replaced by that parent rule, so it is not evidence of this bypass in that context.

Exposure is conditional on real sensitive data being present and the resulting file being accessible to an unauthorized recipient. The fixture demonstrates retention, not theft. A receiver, network attacker, or local user does not automatically gain the ability to inject secrets into another user's input. Any such capability must be shown separately for a particular deployment.

The public report has no established outside victim or exploitation incident. The proof of concept does not support claims of remote code execution, network exfiltration by the CLI, authentication bypass in another application, or a particular CVSS score.

## Scope limits

The redaction policy is finite. Arbitrary prose, embedded serialized JSON, unlisted keys, secret key names, arbitrary URL paths, unsupported encodings, and general personal information are outside the promised coverage. A broader detector would be a separate product feature and needs its own false-positive and false-negative analysis.

The tool's process and filesystem are trusted for execution. It is not a sandbox for hostile Python objects, a privilege boundary against a user who controls the process, a log collector, an automatic incident responder, or a secure deletion tool. A finding count is not a declaration that a file is safe to publish.

## Evidence quality

Keep three kinds of statements separate:

- **Observed:** a pinned source snapshot produced a recorded output on the named interpreter and OS; the source input was unchanged; the expected synthetic marker was present or absent.
- **Derived:** the early classifier caused the skipped URL safeguards; the source diff explains why the patch routes the original input into validation. Review the code and counterexamples as well as the demonstration.
- **Not established:** production exposure, third-party use, the first public-access time of each Git object, all parser/runtime combinations, CVE eligibility, external review, or company attribution.

The differential harness should be run from the reviewed checkout:

```console
python tools/reproduce_url_control_advisory.py --output url-control-evidence.json
```

Its report records environment and per-snapshot source hashes as well as expected and observed core and CLI behavior. A `passed` result means that the harness expectations held; the historic vulnerable snapshot is expected to demonstrate the bypass, not to behave securely. Inspect the snapshot-level results rather than describing `passed` as proof that every tested revision is safe.

The generated case family targets the historic bug, including control-character classification boundaries and representative JSON/JSONL CLI paths. Retain normal URL and ordinary-prose controls so the demonstration does not succeed merely because a proposed fix replaces every string. An exhaustive loop over a finite case family is not exhaustive security testing of all strings or all application behavior.

## Review and submission checklist

### Reproducibility

- [ ] Run the differential harness from the exact revision to be reviewed; retain its JSON report without editing observed values.
- [ ] Confirm the report identifies every pinned Git commit and hash of the loaded source.
- [ ] Check the vulnerable snapshot's false-negative `check` and unchanged secret-bearing `redact` output, not only an isolated regex result.
- [ ] Check that fixed snapshots remove the affected URL while preserving independent public fields.
- [x] Confirm completed CI separately from local runs: [main run 43711757313](https://github.com/345sugar/logshare-guard/actions/runs/43711757313) passed all six matrix jobs with evidence artifacts for `0052c477861a14c1853b2c8bc4dee08fc5635d43`. Re-run checks for later code changes.
- [ ] Verify diagnostics contain no fixture secrets and input files remain unchanged. Use invented values and fresh output paths throughout.

### Factual accuracy

- [ ] Describe 0.1.0 source and the affected 0.2.0 development snapshot separately from the fixed maintained 0.2.0 source.
- [ ] Confirm the distribution history. Do not label source metadata as a published PyPI release or invent download counts, users, or incidents.
- [x] State root cause, preconditions, consequence, and limits. CWE-180 was selected in the published GHSA on 2026-11-15 and remains subject to CNA review; no numeric severity score is asserted.
- [ ] Confirm the bug was not deliberately inserted as an educational/training vulnerability. The maintainer's factual history matters; document it if questioned rather than inferring intent from tests.
- [ ] Preserve the existing individual-maintainer and AI-assistance attribution. Any organizational credit must correspond to real work and dates.

### Submission

- [x] Inspect the existing GHSA's authenticated request state before requesting a CVE. Submission was verified on 2026-11-15 by the UI confirmation and [request timeline event](https://github.com/345sugar/logshare-guard/security/advisories/GHSA-8mpg-mvq9-qm96#event-1368234). Disclose any other request or reservation history that becomes known to the assigned CNA.
- [ ] Provide the relevant public advisory, full source identifiers, fix, and a reproducible evidence report to the appropriate CNA.
- [ ] Resolve ambiguous source-version fields with the CNA; avoid a misleading blanket affected-version range.
- [ ] Record the CNA's actual response and any assigned identifier. Only request confirmation has been observed so far; no CVE number or acceptance is recorded.
- [ ] Keep CVE assignment separate from any later organization's access-program application or company-credential claim.

## Primary references

- [Existing public advisory](https://github.com/345sugar/logshare-guard/security/advisories/GHSA-8mpg-mvq9-qm96)
- [CVE CNA rules](https://www.cve.org/ResourcesSupport/AllResources/CNARules): vulnerability determination, assignment scope, public availability, exclusions, and credit handling.
- [GitHub repository security advisories](https://docs.github.com/en/code-security/concepts/vulnerability-reporting-and-management/repository-security-advisories): CNA request and publication workflow.
- [Python URL parsing](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlsplit): normalization behavior and validation limitations.
- [CWE-180](https://cwe.mitre.org/data/definitions/180.html): proposed root-cause classification.

