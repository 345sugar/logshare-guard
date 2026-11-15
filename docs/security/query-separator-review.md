# Semicolon query interpretation can retain sensitive values

Status: maintainer review finding, identified 2026-11-15; no CVE or GHSA identifier assigned in this package. Source 0.2.1 at [commit `6f224719b003d9371f507bc60ba03af17837eda2`](https://github.com/345sugar/logshare-guard/commit/6f224719b003d9371f507bc60ba03af17837eda2), on the unmerged `codex/cve-evidence-review` branch, contains the candidate fix. This is pending release, not a claim that `main`, a GitHub release, or PyPI has been updated. Retain the working-source hashes in the evidence report as well as this commit identifier.

This issue is distinct from [GHSA-8mpg-mvq9-qm96](GHSA-8mpg-mvq9-qm96.md). The older advisory concerns controls that hide the HTTP(S) scheme. This finding concerns how a normally recognized HTTP(S) URL's query is segmented. The two example URLs below contain no control characters and still reproduce after the older fix.

## Summary and root cause

The affected query handler splits on both `&` and `;` before identifying and masking sensitive query keys. This assumes every literal semicolon is a parameter boundary. Under an ampersand-only query interpretation, a semicolon can instead be part of a value or part of a key. Python's `urllib.parse.parse_qsl` defaults to `&` as its sole separator. The redactor's alternative interpretation can leave part of a sensitive value unchanged or prevent the complete sensitive key from being recognized. [Python query parsing documentation](https://docs.python.org/3/library/urllib.parse.html#urllib.parse.parse_qsl)

The project's documented key-normalization rule removes punctuation before matching explicitly supported sensitive keys. For example, an ampersand-only key `api;key` normalizes to `apikey`, just as `api_key` does. Splitting that key first bypasses the expected match.

**Suggested classification: CWE-115, Misinterpretation of Input**, subject to further review. The concrete defect is a security-relevant interpretation of query delimiters that can defeat the redaction policy. The broader parser-differential concept also describes the mechanism, but no final CNA classification is claimed. [CWE-115](https://cwe.mitre.org/data/definitions/115.html)

## Affected source evidence

Both examples were executed against the `core.py` obtained from each of the following Git objects on CPython 3.12.10, Windows 11. All produced the same affected results shown below:

| Commit | Source metadata / context |
| --- | --- |
| `586459f5f4423aa10225bd01effda47de0734b7a` | Initial 0.1.0 implementation |
| `28c3d1ca7d6a734d7c549b198d6073af63bcae17` | 0.2.0 development snapshot |
| `5aee1c136b846d2a7ca51f07995d099f138a5d19` | 0.1.1 scheme-control fix |
| `17d93dc14114cd55feb5845faa928607f85b1ebd` | 0.1.1 fix merged into main |
| `9158c1f2828844428e1e9ff3b2507c36b5c9d6fe` | Maintained 0.2.0 baseline for this review |

The historical query handler is independently fixable from the scheme-control classifier. A CNA must decide identifier scope if either finding is submitted. Do not add this behavior to the old advisory's fixed-version claim: 0.1.1 fixed the older scheme-control issue, not this query issue. No affected PyPI distribution is asserted.

## Minimal local reproduction

Use synthetic inputs and a pinned affected checkout, with its `src` on `PYTHONPATH`. The Python API demonstration makes no network request:

```python
from logshare_guard.core import redact

cases = [
    "https://example.test/?password=SYNTHETIC_PREFIX;SYNTHETIC_SUFFIX&view=public",
    "https://example.test/?api;key=SYNTHETIC_SECRET",
]
for value in cases:
    print(redact({"url": value}))
```

### Case A: sensitive value truncated at a semicolon

Input query:

```text
password=SYNTHETIC_PREFIX;SYNTHETIC_SUFFIX&view=public
```

Under `&`-only parsing, the complete password value is `SYNTHETIC_PREFIX;SYNTHETIC_SUFFIX`. The affected redactor produces:

```text
password=%5BREDACTED%5D;SYNTHETIC_SUFFIX&view=public
```

The rules count is `{"url_query": 1}`, but the suffix remains in the output. A nonzero finding therefore does not demonstrate that the complete supported value was removed. The remaining suffix alone is not necessarily a usable credential; its security significance depends on its content and the deployment.

### Case B: a sensitive key split before normalization

Input query:

```text
api;key=SYNTHETIC_SECRET
```

Under `&`-only parsing the key is `api;key`. The affected redactor splits it into `api` and `key`, matches neither, and returns the URL unchanged with an empty rules dictionary. The entire synthetic secret remains. For a CLI input containing only this value, that corresponds to a zero-finding check under the affected implementation.

## Fix requirements and review status

The candidate 0.2.1 fix covers both plausible query interpretations conservatively:

1. Identify a sensitive complete key within an `&`-delimited field before treating literal semicolons as legacy separators.
2. If a sensitive value starts within such a field, remove its entire possible value through the end of that field; a semicolon must not expose a tail of that value.
3. Retain detection of sensitive fields introduced by legacy semicolon delimiters.
4. Preserve unrelated ampersand-delimited fields and ordinary public URLs where that can be done safely.
5. Test duplicate fields, encoded key punctuation, mixed case, empty fields, and explicit custom sensitive keys. Test normal JSON and JSONL command behavior as well as the core function.

Ambiguous public semicolon suffixes may be removed together with a sensitive value. This is a deliberate confidentiality-oriented tradeoff and should be explained to users; rewritten URLs are for diagnosis and must not be replayed as requests.

The separate query evidence harness compares the pinned maintained 0.2.0 baseline with the current worktree:

```console
python tools/reproduce_query_separator.py --output security-evidence/query-separator.json
```

Use a new output path. Retain the exact source hashes, interpreter/OS, and expected/observed before-and-after results. The candidate fix commit and source version are recorded above; retain completed regression/CI results and record any future advisory identifier only after it exists. The older URL-control differential harness does not, by itself, verify this query-separator fix.

The local differential run reviewed on 2026-11-15 passed on CPython 3.12.10, Windows 11: two snapshots with eight core cases and eight CLI cases per snapshot, for 16 core observations and 32 CLI invocations. The baseline retained the expected synthetic values; the working fix removed them where required while preserving the encoded public controls. This is local evidence for those cases, not a completed cross-platform CI result or an independent audit. Re-run the harness for the exact source revision submitted for review.

## Impact and attribution limits

Potential impact is retention of supported sensitive query data in output a user may later share. Exposure requires real sensitive data and a subsequent unauthorized recipient or access path. The tool itself does not transmit the result. An enclosing sensitive JSON key may already remove the whole value. No external affected user, real credential exposure, or in-the-wild exploitation was established during this review.

This was an AI-assisted maintainer review of the maintainer's own software. No independent certification, company credit, CVE acceptance, or numerical CVSS score is asserted. Preserve these distinctions when producing any later public advisory or submission.
