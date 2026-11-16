# scripts/ 一覧（Agent が実行するもの）

**迷ったら、何かを書く・別のスクリプトを試す前に、`review_status.py` を実行してください。**
その出力（`NEXT STEP`）の指示だけに従います。詰まっても、他のスクリプトで回避しません。
進めない場合は、状況をユーザーに報告して止まります。

## 常に使う: `review_status.py`

```bash
python .claude/skills/ir-review-report/scripts/review_status.py --review-dir "$REVIEW_DIR" --mode customer
```

- レビューフォルダの中身から「今どこまで進んでいて、次に何をすべきか」を毎回計算して表示します。
  手順やこれまでのコマンドを覚えている必要はありません。
- 観測の統合と集約、`issues.json` / `claim_assessments.json` の雛形、品質検証、最終文書の生成は、
  **すべて `review_status.py` が必要な段階で自動的に行います**。個別に実行するスクリプトは
  ありません（実行しても単独では動きません）。
- 検証が FAIL したら、指摘を1回でまとめて表示し、修正指示を `repair_instructions.json` に書きます。
  同じ検証が3回連続で FAIL したら、自己修正を止めてユーザーに報告します。

## 手順 1〜5 で Agent が実行するスクリプト

| script | 入力 | 出力 | 何をするか |
|---|---|---|---|
| `prepare_report.py` | 元の報告書ファイル（pdf/docx/txt/md） | `normalized.txt` | 形式を自動判定し、プレーンテキストに正規化する |
| `build_source_index.py` | `normalized.txt` | `source_index.json` | 本文を `SPN-*` span に分割し、根拠として参照できるようにする |
| `mechanical_checks.py` | `normalized.txt` | stdout（→ `mechanical_checks.json`） | 目視不要な機械的チェック（文字化け、日付整合性など） |
| `init_results_template.py` | mode | `results.json`（雛形） | checklist 全項目分の空行を作る。判定はしない |
| `create_review_chunks.py` | `source_index.json` | `review_chunks/` | 全 span を漏れなく chunk に分割する |
| `create_subagent_tasks.py` | `review_chunks/` | `subagent_tasks/` | chunk ごとに、SubAgent へ渡す task JSON を作る |

## 判定の途中で使う: `apply_suggested_results.py`

`review_status.py` が案内したときだけ実行します。SubAgent の観測が一致している項目
（全員が同じ verdict、または観測0件で未記載）を `results.json` の未判定行へ転記します。

```bash
python .claude/skills/ir-review-report/scripts/apply_suggested_results.py --review-dir "$REVIEW_DIR" --all-auto
```

`--all-auto` は自動転記の対象だけを転記します（「すべて／各／一貫」等を含む項目の `met` は
対象外）。自分で読んで確認した項目は `--ids <ID>` で転記できます。判定済みの行は上書きしません。

## 必要なときだけ使う補助スクリプト（`review_status.py` の流れには含まれない）

| script | 何をするか |
|---|---|
| `compare_runs.py` | 2つのレビュー実行結果を diff し、再現性を確認する |
| `check_claims.py` | 報告書内の主張を確度・根拠つきで機械チェックする。checklist の verdict 判定には使わない |
| `check_evidence_ids.py` | 証拠ID（E-\* など）の定義漏れ・重複・不整合を検出する |
| `check_report_metadata.py` | 報告書メタデータの日付整合性、ドラフト表記の残存、ATT&CK付録の接地を検出する |
