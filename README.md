# logshare-guard

**ログを共有する前に、認証情報を伏せる小さなPython CLI。**

JSON / JSONL / NDJSONのローカルファイルを読み、指定したフィールドの値を
`[REDACTED]` に置換します。実行時の外部依存・通信はありません。

ログ収集・保存ツールを開発する中で、デバッグ用ログをIssueやチャットへ
貼る前の確認を助けるために作りました。現在は初期版です。

```json
{"wait_minutes":25,"Authorization":"Bearer SYNTHETIC_TOKEN"}
```

↓

```json
{"wait_minutes":25,"Authorization":"[REDACTED]"}
```

## はじめる

Python 3.11以上を使います。リポジトリを取得したディレクトリで実行してください。
まだPyPIでは配布していません。

```console
python -m pip install .
python -m logshare_guard check examples/synthetic.jsonl
python -m logshare_guard redact examples/synthetic.jsonl -o demo.redacted.jsonl
```

`check` は秘密値や行の内容を表示せず、該当箇所の件数をJSONで返します。
対象フィールドがあれば終了コードは `1` です。コマンドの故障を示すものではありません。

`redact` は新しいファイルを作ります。入力ファイルと既存の出力ファイルは
上書きしません。全レコードを読み取り、検査が終わってから出力を作ります。
出力先フォルダはあらかじめ作成してください。

独自フィールドを追加できます。

```console
python -m logshare_guard redact input.json -o shared.redacted.json --secret-key internalCredential
```

`--secret-key` は複数回指定できます。拡張子が `.jsonl` / `.ndjson` なら
JSONL、それ以外はJSONとして読みます。明示するときは `--format jsonl` を使います。
UTF-8（BOMありも可）、最大32 MiB。JSONLの空行は省きます。
JSONの重複キー、NaN / Infinity、浮動小数点の範囲を超える数値、
不正な文字コード・JSON、深すぎる構造はエラーにします。

| 終了コード | 意味 |
| --- | --- |
| `0` | `check` で対象なし、または `redact` が完了 |
| `1` | `check` で対象フィールド・URLを検出 |
| `2` | 入出力エラー、未対応の入力、引数の誤り |

## 対応範囲

- 入れ子のオブジェクト・配列をたどって、機密フィールドの値を型にかかわらず丸ごと置換。
- `Authorization` / `Cookie` / `Set-Cookie` / `password` / `token` /
  `access_token` / `refresh_token` / `api_key` / `X-API-Key` など。
  完全な一覧は [core.py](src/logshare_guard/core.py) の `DEFAULT_SENSITIVE_KEYS` を参照。
- キーの比較では大文字・小文字の差を無視し、ASCII英数字以外を除去。
  例：`api_key` / `API-KEY` / `apiKey` は同じ扱いです。部分一致はしません。
- `{"name":"Authorization","value":"..."}` 形式の値にも対応。
- 文字列全体がHTTP(S) URLの場合、ユーザー情報を除去し、機密クエリ値と
  fragmentを置換。重複クエリ、エンコードされたキー、`;` 区切りも検査。
- 解析できないHTTP(S) URL候補は文字列全体を置換。
- 標準出力は固定のルール名・件数のみ。入力ファイルの解析・入出力エラーには
  入力値やファイル名を含めません。コマンドの引数エラーでは、不正な引数が表示されます。

件数は置換箇所の数です。同じ秘密が2か所にあれば2件と数え、
機密フィールド内のオブジェクトを丸ごと置換した場合は1件と数えます。
既に `[REDACTED]` になっているフィールドも検出対象なので、再検査でも件数が出ます。

## 限界と共有前の確認

**終了コード0や置換の完了は、公開して安全という判定ではありません。**

自由文中の秘密、JSONを文字列に埋め込んだもの、未登録のキー、キー名そのものに
含まれる秘密、URLのパスや未登録クエリ、特殊なエンコード、個人情報全般は
検出対象外です。HAR、Cookieの独自配列形式、バイナリ、巨大ログ向けの
ストリーミング処理には対応していません。HARを単にJSONとして処理しても
安全な共有用HARにはなりません。

URLの表記・JSONの空白やエスケープは変化することがあります。
マスキング後のURLは診断用で、リクエストの再送には使わないでください。
出力は秘密以外の元データを含むため、内容を確認してから共有してください。
実行環境のファイルアクセス権限は引き継ぎます。ディスクへの書き込みが失敗すると、
マスキング済みの途中ファイルが残る可能性があります。

## 開発と検証

テスト用の値はすべて架空です。ネットワーク・実データ・有効な認証情報は使いません。

インストールせずに実行する場合（PowerShell）：

```powershell
$env:PYTHONPATH = 'src'
python -m unittest discover -s tests -v
python -m logshare_guard redact examples/synthetic.jsonl -o demo.redacted.jsonl
```

macOS / Linux：

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
```

GitHub Actionsのテスト設定はPython 3.11 / 3.12 / 3.13、Linux / Windowsを対象にしています。
ローカルで実行済みの内容と、CIの実行結果は区別して確認してください。

この初期版はAIの支援を受けて実装・レビューしています。
既存ソフトウェアの脆弱性発見や、第三者によるセキュリティ認証を主張するものではありません。
改善提案には、秘密を含まない最小の再現例を添えてください。

MIT License
