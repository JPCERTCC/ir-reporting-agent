---
name: ir-review-report-customer
description: >-
  Review an externally submitted incident-investigation report from the
  customer/requester perspective only, using checklist_customer.md. Use this
  when the user asks for a user-side, customer-side, requester-side, 被害組織側,
  ユーザー向け, or 依頼者向け review of a report. Do not run the reporter
  checklist or produce an integrated review unless explicitly requested.
---

# IR 報告書レビュー（ユーザー向け）

外部から受領したインシデント調査報告書を、被害組織・依頼者の観点でレビューします。
評価基準は `references/checklist_customer.md` のみです。

JSON を作成・修正する前に、必要な最小スキーマだけを
`../ir-review-report/references/json_contracts.md` で確認します。

## 目的

受領したインシデント調査報告書の**本文**を、ユーザー向けチェックリストに照らして評価し、
「依頼者として何が足りないか、何を追加確認すべきか」を指摘として返します。

- 評価するのは、報告書がチェックリストの求める事項を記載しているかと、
  主要結論が本文中の根拠・論理・確度表現で支えられているかです。
- 調査自体の再実施や、技術的な真偽の判定はしません。報告書に書かれていない事実は補いません。
- 契約書・合意記録など報告書外の資料が必要な項目は、推測せず `unknown` として
  確認すべき資料を明示します。
- 判定の基準は `../ir-review-report/references/review_model.md` に従います。

成果物は、チェックリスト全項目の判定（`results.json`）、根拠付きの指摘（`issues.json`）、
主要結論の評価（`claim_assessments.json`）、およびそれらから生成する `final_review.md` です。

## 絶対ルール

- 正式成果物は `reviews/<report-stem>/<run-id>_customer/final_review.md` のみです。
- `final_review.md` は `review_status.py` が生成します。手編集しません。
- `results.json` は customer checklist 全項目を判定します。項目の省略は禁止です。
- 本文から判定できる項目（`unknown_allowed: false`）に `unknown` を使いません。記載不足は `not_met` または `partial` にします。
- 報告書外の資料が必要な項目（`unknown_allowed: true`）だけ `unknown` を使い、`unknown_reason` と `external_confirmation_needed` を必ず記入します。
- `issues.json` の指摘は必ず `source_span_ids` または `absence_check_ids` に接地します。
- `claim_assessments.json` を必ず作成し、主要結論の妥当性を評価します。
- 独自 Python スクリプトを作成して判定を生成しません。実行してよいスクリプトは、この手順に書かれたものと `review_status.py` の `NEXT STEP` が案内するものだけです。`merged_observations.json` の集約・グルーピングは `review_status.py` がすでに行うため、同等のスクリプトを自分で書きません。
- この禁止は「判定ロジックの自動化」だけでなく、**verdict / rationale / category / severity を一括で書き込むスクリプト**（見た目は単なる JSON 書き込みでも、実質的にはその場しのぎの判定ロジックを埋め込んだものになる）にも及びます。57項目・100件超の observation が対象でも、`results.json` / `issues.json` / `claim_assessments.json` の各行は1件ずつ、その項目の observation・本文該当箇所を読んでから Edit/Write ツールで書きます。複数項目に一字一句同じ rationale / external_confirmation_needed をコピーしません（項目ごとに何を確認したか・何が不足しているかは異なるはずです）。件数が多く時間がかかること自体は理由になりません。例外は、公式スクリプトの `apply_suggested_results.py`（SubAgent の観測が一致している行の転記）だけです（自分で書いたスクリプトは例外になりません）。issues.json / claim_assessments.json の雛形は `review_status.py` が自動生成します。
- 手順 6 では、chunk ごとに SubAgent を Agent ツールで起動します。親 Agent が全 task を自分で処理するのは、Agent ツールが使えない場合だけです。
- 迷ったとき、次に何をすべきか分からなくなったとき、または検証用の独自スクリプトを書きたくなったときは、**書く前に** `review_status.py --review-dir "$REVIEW_DIR" --mode customer` を実行し、その `NEXT STEP` にだけ従います。 手順 7〜11 は、この review_status.py の実行に置き換えます。
- 品質ゲートが PASS していない場合は「完了」と報告しません。

## 作業ディレクトリ

```bash
PYTHON="${PYTHON:-python3}"
REPORT_STEM=<入力ファイル名から拡張子を除いた識別名>
RUN_ID=$(date +%Y%m%d-%H%M%S)_<model-or-agent>_customer
REVIEW_DIR=reviews/${REPORT_STEM}/${RUN_ID}
mkdir -p "$REVIEW_DIR"
```

## 手順

1. 報告書を正規化します。

   ```bash
   "$PYTHON" .claude/skills/ir-review-report/scripts/prepare_report.py \
     --report <report> --out "$REVIEW_DIR/normalized.txt"
   ```

2. 原文 span を作成します。

   ```bash
   "$PYTHON" .claude/skills/ir-review-report/scripts/build_source_index.py \
     --source "$REVIEW_DIR/normalized.txt" \
     --out "$REVIEW_DIR/source_index.json"
   ```

3. `run_manifest.json` を保存します。

   必須キー: `run_id`, `review_mode: "customer"`, `report_path`, `model`。

4. 機械チェックと checklist 雛形を作成します。

   ```bash
   "$PYTHON" .claude/skills/ir-review-report/scripts/mechanical_checks.py \
     --report "$REVIEW_DIR/normalized.txt" > "$REVIEW_DIR/mechanical_checks.json"

   "$PYTHON" .claude/skills/ir-review-report/scripts/init_results_template.py \
     --mode customer \
     --out "$REVIEW_DIR/results.json"
   ```

5. span を必ず chunk 化し、task を作成します。

   ```bash
   "$PYTHON" .claude/skills/ir-review-report/scripts/create_review_chunks.py \
     --source-index "$REVIEW_DIR/source_index.json" \
     --out-dir "$REVIEW_DIR/review_chunks" \
     --mode customer

   "$PYTHON" .claude/skills/ir-review-report/scripts/create_subagent_tasks.py \
     --chunk-dir "$REVIEW_DIR/review_chunks" \
     --out-dir "$REVIEW_DIR/subagent_tasks" \
     --mode customer
   ```

6. task ごとに SubAgent を起動し、観測結果を作成させます。

   - `subagent_tasks/task_manifest.json` の `tasks` を全件、Agent ツールで起動します。
     各 task は独立しているため、1 メッセージ内で複数の Agent 呼び出しを並列に発行します。
     件数が多い場合は数件ずつのバッチに分けて構いません。
   - `subagent_type` は `general-purpose` を使います。
   - プロンプトには task JSON の中身ではなく、`task_manifest.json` の `task_path` を渡します。
     親 Agent が task を読み込むとコンテキストを消費し、chunk 分割の意味がなくなります。
   - プロンプトのひな形:

     ```text
     IR 報告書レビューの chunk 観測タスクです。
     1. <task_path> だけを Read してください。報告書原本や他の task は読まないでください。
     2. task の instructions と output_schema に従い、観測結果 JSON を作成してください。
     3. task 内の observation_output_path に Write してください。
     4. 最終応答は、書き込んだパス、covered_span_ids の件数、
        checklist / conclusion / issue の observation 件数だけにしてください。
     ```

   - 親 Agent は各 SubAgent の応答（パスと件数）だけを確認し、observation の中身は読みません。
   - SubAgent 実行機能（Agent ツール）がない環境に限り、親 Agent が task を 1 件ずつ処理します。
     この場合は理由を `run_manifest.json` の `notes` に記録します。
   - 空の observation（`covered_span_ids: []`）を書いて完了扱いにしません。

7. SubAgent 観測結果を統合します。

   統合は `review_status.py` が自動で行います（個別のスクリプトはありません）。
   `merged_observations.json` を checklist_id / topic / 指摘の重複候補ごとに
   グルーピングした `aggregation_worksheet.json` も作られます（判定は行わず、
   機械的なグルーピングだけです）。

   ```bash
   "$PYTHON" .claude/skills/ir-review-report/scripts/review_status.py \
     --review-dir "$REVIEW_DIR" --mode customer
   ```

   出力が「SubAgent 観測 + coverage 統合」で止まる場合、`NEXT STEP` に列挙された
   chunk の `task_path` だけを対象に、手順 6 の要領で SubAgent を再起動し、
   このコマンドを再実行します。全 chunk が完了するまで手順 8 に進みません。

8. `results.json` → `issues.json` / `claim_assessments.json` の順に作成・更新します。

   SubAgent の観測から機械的に決まる部分は、スクリプトが先に入力します。Agent が書くのは
   判断だけです。判定ルールと集約手順は `../ir-review-report/references/review_model.md` の
   「2. チェックリスト項目の判定」「3. issues.json と主要結論の書き方」に、JSON のキー・許可値・
   最小例は `json_contracts.md` に従います。

   - `results.json`: customer checklist 全項目を判定します。省略禁止です。
     `review_status.py` が、判断が必要な項目の SubAgent 観測（verdict の内訳、各観測の
     rationale と根拠 span の抜粋）を要約して表示します。その要約を見て1件ずつ判断します
     （`aggregation_worksheet.json` を開き直したり、表示用のスクリプトを書いたりしません）。
     未判定の行には、SubAgent が観測した根拠 span が事前入力されています。
     SubAgent の観測が一致している項目（全員が同じ verdict、または観測0件で未記載）は
     `apply_suggested_results.py --all-auto` で転記できます。転記後の残り（食い違い、
     unknown、条件付き項目など）が判断の対象です。観測0件の項目のために報告書を検索し直す
     必要はありません。
   - `issues.json` と `claim_assessments.json`: results.json の判定がそろうと、
     `review_status.py` が雛形を自動生成します（`auto_filled` に機械入力した項目の一覧）。
     `issues.json` は判定・観測・open_questions から全項目が入力済みです。各項目を観測と
     本文に照らして見直します。`claim_assessments.json` は主要結論の一覧・根拠 span・
     対応する評価行まで入力済みです。Agent が書くのは、各評価行の `review_verdict` と
     `reason`（根拠・論理・確度を1つにまとめた評価）で、報告書自身が認めている限界が
     あれば任意の `limitations` に書きます。`issue_ids` は書きません。`partially_supported`
     などの弱い評価には、専用の issue と `issue_ids` が自動で入るので、その issue の内容を
     見直します。SubAgent が観測した topic を `not_reported` にする場合は、
     `override_reason` に理由が必要です。

   `issues.json` と `claim_assessments.json` は、自分で新規に Write しません。
   `review_status.py` を実行すると、無い方の雛形を自動生成します。雛形を経由せずに書いた
   ファイルは SubAgent の観測が反映されず、`review_status.py` が毎回警告します。

   独自の一括判定・一括修正スクリプトは書きません（例外は `apply_suggested_results.py` のみ。
   雛形の生成は `review_status.py` が行います）。57項目・100件超の observation が
   対象でも、判断は1件ずつ行います。

9. `review_status.py` を再実行し、`NEXT STEP` に従って完了まで進めます。

   ```bash
   "$PYTHON" .claude/skills/ir-review-report/scripts/review_status.py \
     --review-dir "$REVIEW_DIR" --mode customer
   ```

   - `results.json` / `issues.json` / `claim_assessments.json` が未完成の間は、
     `NEXT STEP` の指示に従ってそれらを埋め、再実行します。
   - 品質ゲート（一覧は `references/scripts_index.md`）は `review_status.py` が
     順番に実行します。個別に実行する必要はありません。
   - 検証は、Agent が書いたファイルの指摘を1回でまとめて報告します。
     `repair_instructions.json` の指示に従ってまとめて直し、再実行します。
     同一 gate が3回連続 FAIL したら、自己修正を止めて失敗 gate・原因・次に修正する
     ファイルをユーザーに報告します（`run_log.jsonl` から `review_status.py` 自身が
     検出します）。通すことだけを目的に、SubAgent の観測を捨てません。
   - 出力が `DONE` になれば完了です。`final_review.md`（と自動生成される
     閲覧用 `final_review.html`。正本ではなく手編集もしません）のパスを報告します。

## FAIL 時の対応

- `review_status.py` を再実行し、`NEXT STEP` を確認します。gate FAIL の場合は
  `repair_instructions.json` が最新の失敗内容に更新されています。
- `repair_instructions.json` の `repairs[].target_file` / `json_path` / `instruction`
  に従って対象 JSON を直接修正し、独自の判定・補正スクリプトは書きません。
- `review_status.py` の出力が「直近 3 回連続で FAIL」と報告した場合、
  または入力ファイル（`normalized.txt` / `source_index.json` など）が
  壊れていて再生成が必要な場合だけ、自己修正を止めてユーザーに報告します。
- 停止時は「レビュー未完了」と明記し、失敗 gate、原因、次に修正するファイルを報告します。
