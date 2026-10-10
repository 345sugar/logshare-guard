# logshare-guard

[日本語](README.md) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md)

**A small Python CLI for redacting selected credential fields before sharing logs.**

It reads local JSON, JSONL, or NDJSON files and replaces recognized values with
`[REDACTED]`. It has no runtime dependencies and makes no network calls. Use it
interactively, to check several log files in CI, or as a pre-commit hook.
This is an early project maintained by [345sugar](https://github.com/345sugar).

```json
{"wait_minutes":25,"Authorization":"Bearer SYNTHETIC_TOKEN"}
```

becomes:

```json
{"wait_minutes":25,"Authorization":"[REDACTED]"}
```

## Install and run

Requires Python 3.11 or later. A virtual environment is recommended.
The project is not currently distributed on PyPI.

```console
git clone https://github.com/345sugar/logshare-guard.git
cd logshare-guard
python -m pip install .
logshare-guard check examples/synthetic.jsonl
logshare-guard redact examples/synthetic.jsonl -o demo.redacted.jsonl
```

You can also invoke the CLI as `python -m logshare_guard`.
The example intentionally contains synthetic credentials, so `check` exits with
code `1`. It prints counts, without printing secret values or record contents.

`redact` accepts exactly one input file and requires a new output path. It does
not overwrite the input or an existing output. All records are parsed and
redacted before creating the output. The parent directory must already exist.

Add custom field names with repeated `--secret-key` options:

```console
logshare-guard redact input.json -o shared.redacted.json --secret-key internalCredential
```

By default, `.jsonl` and `.ndjson` use JSONL; other supported files use JSON.
Use `--format json` or `--format jsonl` to override this for every input.
Files must be UTF-8, optionally with a BOM, and no larger than 32 MiB each.
Blank JSONL lines are skipped. Duplicate keys, NaN/Infinity, overflowing floating
point numbers, invalid encoding or JSON, and excessively nested structures fail.

| Exit code | Meaning |
| --- | --- |
| `0` | No selected fields found by `check`, or `redact` completed |
| `1` | `check` found selected fields or URL components |
| `2` | Input/output failure, unsupported input, or invalid arguments |

## Check several files in CI

After installing the tool in your CI environment, pass explicit file paths:

```console
logshare-guard check -- logs/request.json logs/events.jsonl
```

The default format detection can handle a mix of JSON and JSONL files.
One aggregate JSON object is printed after all files are checked. For example,
two files with three records and one selected field produce:

```json
{"command":"check","files":2,"findings":1,"records":3,"rules":{"sensitive_key":1}}
```

Any finding makes the command exit with `1`. Any read or parse failure makes it
exit with `2`, without printing a partial success summary. It does not print
per-file results or paths, modify files, recurse into directories, or expand
wildcards. The `--` separator treats subsequent arguments as filenames.

## Use with pre-commit

Install this tool and [pre-commit](https://pre-commit.com/) 4.4 or later in the
same Python environment. Add this local hook to the consuming project's
`.pre-commit-config.yaml`; it uses the installed package:

```yaml
repos:
  - repo: local
    hooks:
      - id: logshare-guard
        name: Check JSON logs for selected secret fields
        entry: python -m logshare_guard check
        language: unsupported
        args: [--]
        files: '(?i)\.(json|jsonl|ndjson)$'
```

```console
python -m pip install "pre-commit>=4.4"
pre-commit install
pre-commit run logshare-guard --all-files
```

Narrow `files` to `(?i)^logs/.*\.(json|jsonl|ndjson)$` if only that directory
contains logs. To add a custom key, use
`args: [--secret-key, internalCredential, --]`, retaining the final `--`.
Configuration fields such as `token`, including already redacted
values, still trigger findings. The hook does not change files. Pre-commit can
split files across invocations, so each summary covers one invocation. Its own
diagnostics and other hooks' output are outside this tool's control.

This repository also contains a Python hook with ID `logshare-guard`. For remote
hook use, select a published commit containing the hook definition and pin `rev`
to its reviewed full SHA. Do not refer to a release tag that does not exist.

## What is covered

- Nested objects and arrays. A selected field's entire value is replaced,
  regardless of its type.
- Fields such as `Authorization`, `Cookie`, `Set-Cookie`, `password`, `token`,
  `access_token`, `refresh_token`, `api_key`, and `X-API-Key`. See
  `DEFAULT_SENSITIVE_KEYS` in [core.py](src/logshare_guard/core.py) for the list.
- Case-insensitive key comparison after removing non-ASCII-alphanumeric
  characters: `api_key`, `API-KEY`, and `apiKey` match. Substring matching is not used.
- Name/value objects such as `{"name":"Authorization","value":"..."}`.
- Whole-string HTTP(S) URLs: user information is removed; selected query values
  and fragments are redacted. Duplicate query keys, encoded keys, and `;`
  separators are handled. Invalid HTTP(S) URL candidates are replaced entirely.

Counts describe replacement locations, not unique secrets. A selected field
containing an object counts once. Already redacted fields still count on later
checks. Reports contain fixed rule names and counts. File parse and I/O errors
omit input values and filenames; argument errors may echo invalid arguments.

## Limits

**A successful check or completed redaction does not establish that a file is
safe to publish.**

Free-text secrets, JSON embedded in strings, unknown keys, secrets in key names,
URL paths and unknown query parameters, unusual encodings, and personal data in
general are outside the detection scope. HAR, custom cookie array formats,
binary files, and streaming large files are unsupported. Treating HAR as JSON
does not produce a safe HAR file.

URL spelling, JSON whitespace, and escaping can change. Redacted URLs are for
diagnostics, not replaying requests. Output retains the remaining original data,
so review it before sharing. File permissions follow the execution environment.
A failed disk write can leave a partially written, redacted output file.

## Development

Tests use synthetic values, without network calls, real logs, or working
credentials. From the repository, without installing:

```powershell
$env:PYTHONPATH = 'src'
python -m unittest discover -s tests -v
```

On macOS/Linux:

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```

The GitHub Actions configuration targets Python 3.11, 3.12, and 3.13 on Linux and
Windows. Consult actual CI runs for their results. See [CONTRIBUTING.md](CONTRIBUTING.md)
for changes and [SECURITY.md](SECURITY.md) before reporting a sensitive problem.

This initial project was implemented and reviewed with AI assistance. It does
not claim external vulnerability discoveries or third-party security certification.

MIT License
