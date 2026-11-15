# URL control characters bypass credential redaction

- Advisory: [GHSA-8mpg-mvq9-qm96](https://github.com/345sugar/logshare-guard/security/advisories/GHSA-8mpg-mvq9-qm96)
- Product: `logshare-guard`, maintained by `345sugar`
- Status: published maintainer advisory; no CVE identifier shown on the public advisory as checked on 2026-11-15
- Document purpose: technical evidence for review of the existing advisory, not a new vulnerability announcement or an assertion of CVE eligibility.

## Summary

The affected source fails to recognize certain HTTP(S) URL strings before deciding whether to apply URL redaction. A leading NUL or another non-stripped C0 control character, or a TAB, CR, or LF inserted into the scheme, can cause the initial URL classifier to return early. The original string is then preserved, including URL user information and supported sensitive query values. For an otherwise clean input containing one such URL, `check` returns zero findings with exit status 0. `redact` succeeds but writes the original URL to its output.

The flaw is in `logshare-guard`'s classification and validation order. It is not a vulnerability in Python's URL parser. The 0.1.1 source fix recognizes the parser-normalized candidate and then rejects control characters in the original input, replacing the complete malformed URL with `[REDACTED]`.

## Affected and fixed source

The project distributes source through GitHub. The version labels below are source metadata, not evidence of a PyPI publication, GitHub release, or downstream installation. Use the full commit identifier when reproducing this issue.

| Source snapshot | Version metadata | Status for this issue |
| --- | --- | --- |
| [`586459f5f4423aa10225bd01effda47de0734b7a`](https://github.com/345sugar/logshare-guard/commit/586459f5f4423aa10225bd01effda47de0734b7a) | 0.1.0 | Affected initial implementation |
| [`28c3d1ca7d6a734d7c549b198d6073af63bcae17`](https://github.com/345sugar/logshare-guard/commit/28c3d1ca7d6a734d7c549b198d6073af63bcae17) | 0.2.0, development branch | Contains the same vulnerable URL-classification implementation; this is not the later maintained 0.2.0 source |
| [`5aee1c136b846d2a7ca51f07995d099f138a5d19`](https://github.com/345sugar/logshare-guard/commit/5aee1c136b846d2a7ca51f07995d099f138a5d19) | 0.1.1 | Initial fix |
| [`17d93dc14114cd55feb5845faa928607f85b1ebd`](https://github.com/345sugar/logshare-guard/commit/17d93dc14114cd55feb5845faa928607f85b1ebd) | 0.1.1 | Fix merged into `main` |
| [`9158c1f2828844428e1e9ff3b2507c36b5c9d6fe`](https://github.com/345sugar/logshare-guard/commit/9158c1f2828844428e1e9ff3b2507c36b5c9d6fe) | 0.2.0 | Later maintained `main`, retaining the fix |

Consequently, a simple claim that every 0.2.0 checkout is affected would be incorrect. There is no evidence here of an affected PyPI artifact. No claim is made about versions or commits that have not been inspected.

## Root cause and weakness classification

In the affected `redact_url` implementation, `original.strip()` is tested against `^https?:` before the original-input control-character check is reached. Embedded TAB/CR/LF breaks that prefix match. Some leading C0 controls, such as NUL, survive `str.strip()` and also prevent a match. The early return skips all URL safeguards.

Python's documented URL parsing behavior removes TAB/CR/LF and, on supported interpreter revisions with the relevant behavior, leading C0 controls and spaces. This makes the early classification inconsistent with a consumer that recognizes the normalized URL. The disclosure reproducer records the actual interpreter instead of assuming identical normalization across every Python patch version. [Python URL parsing documentation](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlsplit)

**Proposed root-cause mapping: CWE-180, Incorrect Behavior Order: Validate Before Canonicalize.** This is a suggested mapping for CNA review: classification is used as a security gate before accounting for canonicalization. The consequence is retention of sensitive data in the proposed shared output. A generic log-insertion classification would obscure the root cause because this tool transforms an existing log rather than originating its credentials. [CWE-180](https://cwe.mitre.org/data/definitions/180.html)

## Preconditions and impact

An exposure requires all of the following:

1. The user runs an affected source snapshot.
2. A string value contains an affected URL shape and a real secret in a component the tool promises to redact, such as user information or an `api_key` query parameter.
3. No enclosing sensitive-key or sensitive `name`/`value` rule already replaces the entire value. For example, the neutral key `url` reaches URL processing, whereas a `password` key is redacted first.
4. The user or another process subsequently shares or otherwise exposes the result to someone who should not receive the secret.

The `check` false negative can remove a warning from that workflow; `redact` can create an output file that still contains the secret. The CLI itself makes no network request and does not automatically publish its output. An adversary's ability to influence URL formatting, and the distribution of secrets in the surrounding application, are deployment-specific assumptions, not established attack preconditions for an observed deployment.

No external affected user, disclosure of a real credential, or exploitation in the wild has been established. Tests use invented values exclusively. The evidence establishes a redaction bypass and false negative, not remote code execution, access to unrelated files, or automatic account compromise.

The existing advisory labels severity **Moderate**, as a qualitative maintainer assessment. No CVSS score is assigned in this document. A numeric score would need an explicit attack path and justified metrics for access, privileges, user interaction, and downstream confidentiality impact; a potential credential leak alone does not establish those metrics.

## Minimal reproduction

Use a local checkout of a pinned source snapshot, Python 3.11 or newer as required by the project, and only the invented fixture below. Preserve the JSON escapes; they decode to actual control characters inside the JSON string.

```json
{"url":"\u0000 https://demo-user:SYNTHETIC_PASSWORD@example.test/?api_key=SYNTHETIC_TOKEN"}
```

Save this as `control-url.json`. With that checkout's `src` on `PYTHONPATH`, run:

```console
python -m logshare_guard check control-url.json
python -m logshare_guard redact control-url.json -o control-url.redacted.json
```

Choose a new output filename for each run. The CLI intentionally refuses to overwrite an existing file. The URL is synthetic and is never requested.

| Observation | Affected snapshot | Fixed snapshot |
| --- | --- | --- |
| `check` exit status | 0 | 1 |
| `check` findings | 0 | 1, with rule `invalid_url` |
| `redact` exit status | 0 | 0 |
| Value written under `url` | Original URL and synthetic secrets remain | `[REDACTED]` |
| Original input file | Unchanged | Unchanged |

An embedded scheme-control example is `{"url":"ht\ttps://example.test/?api_key=SYNTHETIC_TOKEN"}`. Not every control character is a bypass on the old implementation: controls already removed by `strip()` can reach its original validation and be rejected. Representative negative controls are ordinary prose, a public HTTP(S) URL without secrets, and a normal secret-bearing URL that the old implementation already redacts.

## Automated differential evidence

From the updated repository root, run the offline evidence harness:

```console
python tools/reproduce_url_control_advisory.py --output url-control-evidence.json
```

It compares pinned historical snapshots and the current worktree using local Git objects and synthetic data. It records the interpreter, platform, source hashes, expected and observed behavior, and a pass/fail result. The report path must be new. Retain the generated JSON alongside the exact revision of the harness when submitting evidence. See [the evidence checklist](THREAT-MODEL.md#review-and-submission-checklist) for interpretation and remaining gates.

A successful run proves the assertions encoded in that run on that environment. It does not prove an independent audit, universal parser equivalence, absence of every possible redaction bypass, or a CVE assignment. CI configuration is not a substitute for a completed CI run.

The local run reviewed on 2026-11-15 used CPython 3.12.10 on Windows 11. It passed the expected-behavior assertions for five snapshots, with 198 core cases and 10 CLI cases (20 CLI invocations) per snapshot: 990 core observations and 100 CLI invocations in total. Each core set included 128 leading-control cases, 54 scheme-control cases, 12 combined cases, and four controls. These counts describe one local run, not independent review or cross-platform CI results. Fresh reports should be generated after changes to the harness or worktree.

## Remediation and remaining boundaries

Update to a fixed source snapshot and repeat the redaction from the original input. The fix uses normalized input only to identify a URL candidate; it checks the original string and fully replaces malformed candidates. It does not silently repair and preserve a control-bearing URL.

If output from an affected run was already shared, inspect what was shared and handle any actual exposed credentials according to the relevant system's incident procedure. Re-running the tool cannot remove copies already shared elsewhere.

The documented limits still apply: free-text secrets, unknown keys, secrets in key names, unsupported encodings, and arbitrary URL path content are not covered. `check` exit 0 is a count of no matched rules, not a general approval to publish a file.

## Timeline and attribution

| Date | Evidence |
| --- | --- |
| 2026-10-10 | Git history records the initial implementation and the separate development snapshot listed above. Commit dates do not independently prove the first time each object was publicly accessible. |
| 2026-10-11 | Git history records the 0.1.1 fix and merge. GitHub shows the public GHSA publication date as October 11. |
| 2026-10-12 | The later 0.2.0 merge retains the security fix. |
| 2026-11-15 | This evidence package was prepared for review of the already-published issue. |

The publisher and project maintainer is [345sugar](https://github.com/345sugar). Discovery, reproduction, review, and patch preparation used AI assistance. This is a finding in the maintainer's own project; independent acceptance or third-party certification is not claimed. No company is attributed in this package. Any later attribution correction must describe actual contributions and dates, rather than imply that a company performed work before it existed.

