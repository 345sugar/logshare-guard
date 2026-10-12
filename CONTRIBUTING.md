# Contributing / 開発への参加

Maintainer / 保守担当: [345sugar](https://github.com/345sugar)

## Issues and changes

Use [Issues](https://github.com/345sugar/logshare-guard/issues) for ordinary bugs
and suggestions. Describe the expected behavior, actual behavior, Python/OS
versions, and a minimal example containing only invented values. For sensitive
problems, follow [SECURITY.md](SECURITY.md) first.

通常の不具合・提案はIssuesへ、期待する動作・実際の動作・Python/OSのバージョン・
架空の値による最小例を添えてください。機密性のある問題は先にSECURITY.mdを確認してください。

## Local development

Use Python 3.11 or later in a virtual environment:

```console
python -m pip install -e .
python -m unittest discover -s tests -v
```

No runtime dependencies are required. Tests must use synthetic inputs and stay
offline. The CI matrix covers Python 3.11–3.13 on Windows and Linux; a local
passing result does not imply every CI job passed.

実行時の外部依存はありません。テストには架空の入力を使い、ネットワーク接続を必要と
しないようにしてください。CIはPython 3.11〜3.13、Windows/Linuxを対象としています。

## Before opening a pull request

- Keep the change focused and explain the user-visible behavior.
- Add a regression test for a behavior change, using only synthetic data.
- Preserve generic diagnostics: input values and file paths must not leak into
  parsing or I/O error messages.
- Preserve exclusive output creation and the exit-code contract.
- Update both [Japanese](README.md) and [English](README.en.md) guides when
  supported behavior or limits change.
- State which checks you actually ran and any remaining limitation.

変更の目的と利用者への影響を説明し、動作変更には架空データの回帰テストを添えてください。
解析・入出力エラーへの入力値やパスの漏出を避け、出力の上書き防止・終了コードを維持します。
対応範囲や制限を変更したら日英のREADMEを更新し、実行した検証と残る制限を記載してください。

Contributions are reviewed under the repository's [MIT License](LICENSE).
AI assistance is welcome; contributors remain responsible for reviewing their
changes and reporting test results accurately.

本リポジトリはMIT Licenseです。AIの利用は可能ですが、変更内容の確認と正確な検証結果の
記載は投稿者が行ってください。
