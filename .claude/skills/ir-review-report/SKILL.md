---
name: ir-review-report
description: >-
  Shared internal resources for IR report review scripts, schemas, and
  references. Do not use this combined skill directly for ordinary report
  review. Use ir-review-report-customer for customer/requester-side review, or
  ir-review-report-reporter for reporter/author-side review.
---

# IR 報告書レビュー共通リソース

通常のレビューではこの Skill を直接使用しません。必ず次のどちらか一方を使用します。

- `ir-review-report-customer`: ユーザー向け / 依頼者向けレビュー
- `ir-review-report-reporter`: レポーター向け / 作成者向けレビュー

## 参照ファイル

- `references/checklist_customer.md`: ユーザー向けチェックリスト
- `references/checklist_reporter.md`: レポーター向けチェックリスト
- `references/json_contracts.md`: Agent が作成する JSON の最小契約と例
- `references/review_model.md`: 判定・指摘・主要結論レビューの判断基準
- `references/scripts_index.md`: `scripts/` の各スクリプトが何をするかの一覧。
  独自の検証・集計スクリプトを書く前に必ず確認します
- `scripts/`: 正規化、分割、検証、レンダリング用スクリプト

## 共通ルール

- `CUS-*` と `REP-*` を同じ `results.json` に混在させません。
- `results.json` は Agent が本文とチェックリストを読んで埋めます。
- `check_claims.py` は報告書内の主張抽出検査用です。チェックリスト判定には使いません。
- `final_review.md` は `review_status.py` が生成します。手編集しません。
- 完了報告前に `scripts/review_status.py` の出力が `DONE` になるまで進めます。
  品質検証は `review_status.py` が自動で行うため、個別のスクリプトで代用しません。
- 次に何を実行すべきか分からない、または検証用の一回限りのスクリプトを書きたくなったときは、
  書く前に `scripts/review_status.py --review-dir <dir> --mode <mode>` を実行します。
  レビュー実行ディレクトリの中身から状態を再計算し、次に実行すべき具体的なコマンドを返します。

## SubAgent workflow

- `create_review_chunks.py` で `source_index.json` 全体を chunk 化します。
- `create_subagent_tasks.py` で `subagent_tasks/CHK-NNN.json` を作成します。
- 各 task は、担当 chunk、対象チェック項目、主要結論レビュー観点、出力スキーマを含みます。
- 親 Agent は task ごとに SubAgent を Agent ツールで並列起動し、task のパスだけを渡します。
  SubAgent は `observation_output_path` に観測結果を書き込みます。
- Agent ツールが使えない場合に限り、親 Agent が task を順番に処理します。
- 観測結果は `subagent_observations/CHK-NNN.json` に保存します。
- `merged_observations.json` と `coverage_ledger.json` は `review_status.py` が作成します。
- `coverage_ledger.json` の `coverage_complete` が `true` になるまで最終 JSON を確定しません。
- `merged_observations.json` の反映先は固定です（`checklist_observations → results.json`,
  `conclusion_observations → claim_assessments.json`, `issue_observations → issues.json`,
  `open_questions → issues.json` または `claim_assessments.json`）。詳細は
  `references/review_model.md` の「3. issues.json と主要結論の書き方」を参照します。`open_questions` を
  未対応のまま残すと検証が FAIL します。

JSON の形は `references/json_contracts.md` を確認してください。
