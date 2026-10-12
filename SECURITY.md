# Security policy / セキュリティ方針

## Maintainer / 保守担当

[345sugar](https://github.com/345sugar) maintains logshare-guard, including the
review of security reports, fixes, and regression tests. This is an early
project. There is no guaranteed response time or long-term support commitment.
Reports should identify the version or commit used; fixes are developed on
`main` rather than maintained across older release branches.

保守担当は **345sugar** です。セキュリティ報告の確認、修正、回帰テストを担当します。
初期段階のプロジェクトで、応答時間・長期サポートの保証はありません。
報告には利用したバージョンまたはコミットを添えてください。
修正は `main` を対象とし、過去のリリース系列ごとの保守は行っていません。

## Reporting / 報告方法

The verified public contact channel is
[GitHub Issues](https://github.com/345sugar/logshare-guard/issues).
A dedicated private reporting channel is not documented at present.
For a sensitive issue, open an issue requesting a private contact method, with
**no vulnerability details, reproduction files, logs, or credentials**. Wait
for a private channel before sending sensitive material. Do not post sensitive
details in a public issue or pull request.

公開の連絡窓口は [GitHub Issues](https://github.com/345sugar/logshare-guard/issues) です。
現時点で専用の非公開報告窓口は案内していません。
機密性のある問題は、**脆弱性の詳細・再現ファイル・ログ・認証情報を書かずに**、
非公開の連絡方法を問い合わせるIssueを作成してください。
非公開の連絡手段が用意されるまで、詳細を公開IssueやPRへ投稿しないでください。

Once a suitable channel is available, a useful report includes the affected
commit, Python/OS versions, expected and actual behavior, and a minimal example
using invented values. Never send real credentials or other people's logs.

連絡手段が整ったら、対象コミット、Python・OSのバージョン、期待した動作と実際の動作、
架空の値だけを使う最小の再現例を用意してください。実際の認証情報や他人のログは送らないでください。

## Scope / 対象範囲

Relevant problems include unintended disclosure by the tool, a failure to redact
a documented supported field or URL component, and unintended file writes.
Documented limitations in the [README](README.en.md#limits) are not promises of
coverage. Improvements to coverage are welcome as ordinary feature requests.

本ツール自身による意図しない情報表示、対応を明記したフィールド・URL要素の伏字漏れ、
意図しないファイル書き込みなどを対象とします。
[READMEの限界](README.md#限界と共有前の確認) に記載した範囲は検出を保証していません。
対応範囲の拡張は通常の機能提案として歓迎します。

No bug bounty, CVE assignment, or third-party certification is promised by this policy.
この方針は、報奨金、CVEの発行、第三者の認証を約束するものではありません。
