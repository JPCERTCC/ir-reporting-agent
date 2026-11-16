# ir-review-report スクリプト内部仕様（保守者向け）

**この文書は人間の保守者向けです。レビューを実行する Agent は参照しません。**
Agent が実行するのは `review_status.py` と、その `NEXT STEP` が案内するスクリプトだけです
（`references/scripts_index.md` 参照）。ここに載っているスクリプトのうち `review_status.py` が
実行するものは、`review_io.require_via_review_status()` により単独実行できません
（直接実行すると `review_status.py` の実行を促して終了します）。

## review_status.py の動き

- レビューフォルダの中身から状態を毎回再計算し、次に実行すべきことを表示します。パスは
  `review_dir` を基準に解決するため、実行時のカレントディレクトリに依存しません。
- 各段階で次を自動実行します: 観測の統合（merge）と集約（aggregate）、未判定行への根拠 span の
  事前入力（prefill）、`issues.json` / `claim_assessments.json` の雛形生成、7つの品質ゲート、
  最終文書と閲覧用 HTML の生成。
- Agent が書いたファイルの検証（coverage / claim_assessments / absence_grounding / issues）は、
  最初の失敗で止まらず毎回すべて実行し、指摘を1回でまとめて報告します。全 gate 分の修正指示は
  `repair_instructions.json`（`failed_gates` / 各 repair の `gate`）に書き出します。
- 実行のたびに `run_log.jsonl` に記録します（gate ごとの失敗理由 `summary`、修正対象
  `repair_targets` を含む）。同じ gate が3回連続 FAIL すると停止ルールを案内します。

## chunk 化と SubAgent（手順 5-7）

| script | 入力 | 出力 | 何をするか |
|---|---|---|---|
| `create_review_chunks.py` | `source_index.json` | `review_chunks/` | 全 span を漏れなく chunk に分割する（重要度選別はしない） |
| `create_subagent_tasks.py` | `review_chunks/` | `subagent_tasks/` | chunk ごとに、SubAgent へ渡す task JSON（担当 chunk・チェック項目・出力先）を作る |
| `merge_subagent_observations.py` | `subagent_observations/` | `merged_observations.json`, `coverage_ledger.json` | 各 chunk の観測結果を統合し、span の網羅漏れを検出する。観測に含まれる存在しない span ID は自動で修復（`SPN, xxxx` のような誤記）または除外し、`coverage_ledger.json` の `sanitized_span_ids` に記録する（SubAgent の元ファイルは変更しない） |
| `aggregate_observations.py` | `merged_observations.json`, `results.json` | `aggregation_worksheet.json` | 観測を checklist_id / topic / 指摘の重複候補ごとにグルーピングする（**判定はしない**。手順8の判断材料を作るだけ） |
| `apply_suggested_results.py` | `aggregation_worksheet.json`, `results.json` | `results.json`（未判定行のみ更新） | worksheet の `suggestion`（全 observation が同じ verdict で一致・根拠 span あり、または観測0件で未記載）を転記する。`--all-auto` は「すべて／各／一貫」等を含む項目の `met` を除く自動転記対象だけ、`--ids` は Agent が読んで確認した項目。判定済みの行は上書きしない |
| `prefill_result_spans.py` | `merged_observations.json`, `results.json` | `results.json`（未判定・span 未入力の行のみ） | 観測された根拠 span を事前入力する。verdict / rationale は入れない。`review_status.py` が自動実行 |
| `init_issues_skeleton.py` | `results.json`, `merged_observations.json`, `source_index.json` | `issues.json`（雛形。既存ファイルは上書きしない） | partial / not_met / unknown 全件と `open_questions` に対する接地済み issue を作り、category / severity / reason / suggested_revision に項目文由来の既定値を入れる（`auto_filled` に一覧）。`review_status.py` が自動実行 |
| `init_claims_skeleton.py` | `merged_observations.json`, `source_index.json` | `claim_assessments.json`（雛形。既存ファイルは上書きしない） | topic ごとに1行の `conclusion_inventory`（観測のある topic は必ず reported）、対応する ASM / CNS / REC を作る。`review_verdict` と評価文は `【要記入】`。`review_status.py` が自動実行 |

判定（手順8）で「103件の observation を手作業で突き合わせるのは大変」と感じたら、
自分でスクリプトを書く前に `aggregation_worksheet.json` を開いてください。
すでに checklist_id ごと・topic ごとにグルーピングされ、observation 間の
verdict の食い違いも `conflicting` フラグで示されています。

## 判定・指摘の検証（手順 8-9、review_status.py が内部実行）

| script | 検証対象 | 何を保証するか |
|---|---|---|
| `check_coverage.py` | `results.json` | checklist 全項目に有効な verdict があるか |
| `check_claim_assessments.py` | `claim_assessments.json` | 主要結論の棚卸し・整合性評価・妥当性評価が要件を満たすか。`stated_conclusion` が topic ラベルの言い換えで終わっていないか。`reported` 結論の `assessment_ids` が、自分自身の topic を実際に評価した assessment を指しているか（他 topic の評価の使い回しを検出） |
| `check_absence_grounding.py` | `results.json` + `aggregation_worksheet.json` | 安全網（`prefill_result_spans.py` の事前入力で通常は発火しない）。`not_met`/`unknown`（根拠 span なし）の行が、SubAgent が観測した span を無視していないか。文言は見ない。観測 0 件の項目には何も要求しない |
| `check_issues.py` | `issues.json` + `results.json` | 指摘が根拠に接地しているか、`partial`/`not_met` に対応 issue があるか、`unknown` 全件に `external_confirmation` issue があるか |
| `render_review.py` | 上記の検証済み JSON | `final_review.md` をコードで生成する（本文を LLM が自由記述しない） |
| `check_review_doc.py` | `final_review.md` | サマリー本文が集計結果と一致し、issue が本文から漏れていないか |
| `render_review_html.py` | `final_review.md` | `final_review.html` | 閲覧用の派生 HTML（目次・重大度/判定バッジ・チェックリスト絞り込み）。`review_status.py` が DONE 時に自動実行。正本は `final_review.md` |
| `check_review_run.py` | レビュー実行ディレクトリ全体 | 必須ファイルが揃い、独自スクリプトや野良ファイルが紛れ込んでいないか、`open_questions` が issues.json/claim_assessments.json のいずれかから参照され未対応のまま残っていないか |

最終確認は上記7ゲートを実行する `review_status.py` 自身が正本です。これを再実行するだけの
別スクリプトは持ちません（かつて `check_review_completion.py` がありましたが、
`review_status.py` と役割が完全に重複し、ゲートを追加・変更するたびに二重メンテナンスが
必要になっていたため削除しました）。

## 失敗時の復旧

| script | 使うタイミング |
|---|---|
| `make_repair_instructions.py` | gate FAIL の生ログを、`target_file` / `json_path` / `instruction` を持つ具体的な修正指示に変換する（`review_status.py` が自動実行） |
| `review_io.py` | （直接実行しない）他スクリプトが使うアトミック書き込みヘルパー。生成物が壊れた状態で残らないようにする |

## link_assessment_issues.py

`review_status.py` が、検証の直前に毎回実行します。`claim_assessments.json` の弱い評価
（`partially_supported` / `unsupported`、`minor_` / `major_inconsistency`、
`partially_mapped` / `not_mapped`）ごとに専用の issue（`assessment_ids` / `recommendation_ids`
で評価を指す、`auto_for` 付き）を `issues.json` に作り、評価側の `issue_ids` を「専用 issue ＋
Agent が書いた実在する issue ID」に置き換えます。`issue_id` を持たない issue には ISS-NNN を
振り、実在しない ID（観測 ID など）は除きます。評価が `supported` に変わったら、自動生成した
issue は消えます。`check_claim_assessments.py`（`--issues`）は、`issue_ids` が実在する
issue を指しているかも検証します。

## review_io.py

直接実行しません。他スクリプトが使うアトミック書き込みと、JSON 読み込みの失敗理由の整形、
`review_status.py` 経由でしか動かさないためのガード（`require_via_review_status`）を持ちます。

## 最終確認について

最終確認は上記のゲートを実行する `review_status.py` 自身が正本です。これを再実行するだけの
別スクリプトは持ちません（かつての `check_review_completion.py` は、`review_status.py` と
役割が完全に重複し、ゲートを追加・変更するたびに二重メンテナンスが必要だったため削除しました）。
