# IR Reporting Support Agent

[English](README.md)

インシデント調査報告書の**作成**と**レビュー**を支援するツールです。Python CLI と、Claude Code や
Codex などのコーディングエージェントを組み合わせて使います。報告書のすべての所見は、人間が承認した
証拠に紐づきます。

- **報告書を作成**: ログ・エクスポート・メモから `reports/final_report.md` を生成
- **ベンダー報告書をレビュー**(PDF / Word / Markdown / テキスト): セカンドオピニオンとして `final_review.md` を生成

## セットアップ

**必要なもの:** Python 3.10 以上と、コーディングエージェント(Claude Code 推奨、Codex も利用可)。
別途 LLM の API キーは不要です。エージェント自身のモデルを使います。

```bash
git clone <this-repo>
cd ir-reporting-agent
pip install -e .
```

リポジトリのルートでエージェントを起動します。

```bash
claude   # Claude Code(.claude/skills/ を自動で利用)
codex    # Codex CLI(AGENTS.md を自動で読み込み)
```

## 使い方

### 報告書を作成する

1. ケースディレクトリを作成し、ログ・エクスポート・メモを `artifacts/` 以下に置きます
   (テキスト、CSV、syslog、EVTX のテキストエクスポート、Markdown など):

   ```
   my-case/
   └── artifacts/
       ├── AD01/security_events.evtx.txt
       ├── FS01/edr_process_network.csv
       └── VPN/sslvpn.log
   ```

2. 対象のケースをエージェントに伝えます。例:

   ```
   ./my-case を分析して、次のチェックポイントまで進めてください
   ```

   Codex の場合は「AGENTS.md に従って」を付け加えます。

3. 3 つのチェックポイントで、内容を承認・却下・修正します。

   | チェックポイント | 確認する内容 |
   |---|---|
   | 1. 証拠 | 抽出された証拠候補 |
   | 2. 分析 | 分析結果と未解決事項 |
   | 3. ドラフト | 報告書ドラフト |

   チャットで回答するか、`my-case/reviews/*.md` のレビュー文書を直接編集します。

4. 最終報告書は `my-case/reports/final_report.md` に出力されます。

作業が中断した場合は、エージェントに続きを依頼するか、次のコマンドで現在のステップを確認します。

```bash
ir-agent --case-dir ./my-case status   # "Next step" に次の作業が表示されます
```

`artifacts/` のファイルを更新した場合は、エージェントに `ingest` の再実行を依頼してください。
影響を受けるステップは stale と表示され、再実行されます。

試用には、架空の VPN 侵害シナリオのサンプルケース `sample_cases/case-2026-vpn-compromise` を使えます。

### ベンダー報告書をレビューする

レビュー対象のファイルをエージェントに渡します。ケースディレクトリは不要です。

```
~/Downloads/vendor_report.pdf をレビューチェックリストに沿ってレビューしてください
```

Codex の場合: `AGENTS.md に従って ~/Downloads/vendor_report.pdf をレビューしてください`

出力は `reviews/<report-stem>/<run-id>/final_review.md` で、次の内容を含みます。

- 全チェック項目の評価(充足 / 一部充足 / 未充足 / 該当なし / 不明)
- 過大な主張(overclaim)の指摘と改善提案
- 自組織で別途確認すべき事項
- AI 支援レビューの限界

> レビューは報告書に書かれた内容のみが対象です。報告書にないログや証拠、ベンダーが実際に行った
> 作業は検証できません。最終判断は人間のレビュアーが行います。


## 開発

```bash
pip install -e ".[dev]"
pytest          # テスト
ruff check .    # lint
mypy ir_agent/  # 型チェック
```

エージェントの動作ルールとワークフローの詳細は [AGENTS.md](AGENTS.md) を参照してください。
レビュー用チェックリストは `.claude/skills/ir-review-report/references/` にあります。

`ir-agent bulk-mark-reviews` はレビュー文書を一括承認するテスト専用のコマンドです。
実ケースでは使用しないでください。

## ライセンス

[LICENSE.txt](LICENSE.txt) を参照してください。
