---
name: ir-case-workflow
description: >-
  Orchestrate an ir-agent incident-reporting case end to end: run every
  mechanical step automatically and stop only at the three human checkpoints
  (evidence approval, claims/gaps approval, draft approval), collecting the
  human's decisions in chat and transcribing them verbatim. Use this whenever
  the user asks to advance a case — ケースを解析して, 続きを進めて, 次に進めて,
  報告書作成まで進めて, ワークフローを進めて, "run the case", "continue the
  workflow" — or asks what the next step is. Do not use for reviewing an
  externally submitted report (that is ir-review-report).
---

# IR ケースワークフロー実行

ケースを次の人間チェックポイントまで**自動で**進める。ユーザーはコマンド名を知らなくてよい。
体験としては「3 回の承認」だけになる:

| チェックポイント | 人間が判断すること |
|---|---|
| CP1: 証拠の承認 | 抽出された証拠候補を台帳に載せてよいか |
| CP2: 分析結果・不足事項の承認 | 分析結果の妥当性と、不足事項の扱い(連続で 1 セッション) |
| CP3: ドラフトの最終承認 | 報告書ドラフトを最終版にしてよいか |

## 基本動作

1. まず現在地を確認する: `ir-agent --case-dir <case-dir> status`
   ("Next step" が次にやることを教えてくれる)
2. **機械ステップは確認なしで連続実行**する(下表)。エラーが出たら止めて報告。
3. **チェックポイントに到達したら止める**。レビュー文書の内容を要約し、HTML レビュー画面の
   パスを添えて提示する。ユーザーの決定を受け取ったら(HTML から書き出した JSON、または
   チャットでの口述)、下記の手順で転記し、apply/approve コマンドを実行して次へ進む。
4. stale フェーズがあれば先にそれを解消する(該当ステップの再実行)。

## フェーズ表

| フェーズ | 実行内容 | 種別 |
|---|---|---|
| 取り込み | `init`(未初期化なら)→ `ingest --artifacts-dir <dir>` → `normalize-events`(構造化ログがあれば) | 自動 |
| 証拠抽出 | Skill `ir-extract-evidence` → `extract-candidates`(検証) | 自動 |
| 証拠レビュー準備 | `review-evidence` | 自動 |
| **CP1** | 証拠候補の承認/却下/編集 | **人間** |
| 反映 | `promote-evidence --analyst-id <id>` | 自動 |
| IoC抽出(任意) | `extract-iocs`(承認済み証拠から `data/iocs.jsonl` と `reports/iocs.csv` を生成。ドラフトのIoC付録の土台) | 自動 |
| 分析 | `build-coverage` → `build-timeline` → `map-attack` | 自動 |
| 上流相関(推奨) | `ground-evidence-fields`(証拠フィールドの接地確認)→ `build-correlation-hints`(関連候補の生成)→ Skill `ir-correlate-evidence`(分析結果の統合案作成)→ `validate-analysis-groups`(分析結果の接地検証) | 自動 |
| 分析結果 | `build-claims`(分析結果の作成)→ `review-claims` | 自動 |
| **CP2a** | 分析結果の承認/却下/編集 | **人間** |
| 反映+不足事項 | `apply-claim-review --analyst-id <id>` → `check-gaps` → `review-gaps` | 自動 |
| **CP2b** | 不足事項の disposition(CP2a と同じセッションで続けて聞く) | **人間** |
| 反映+計画 | `apply-gap-disposition --analyst-id <id>` → `plan-report` → `approve-report-plan --analyst-id <id>`(計画の要点を提示してから) | 自動 |
| ドラフト | Skill `ir-draft-report`(雛形の【要記入】を執筆)→ `check-draft`(PASS で登録)→ Skill `ir-review-quality` | 自動 |
| **CP3** | ドラフトの最終承認(品質レビュー結果を添えて提示) | **人間** |
| 完成 | `approve-draft --analyst-id <id>` → `finalize-report` | 自動 |

上流相関の 4 ステップは推奨(通常フローでは実行する)。機械検証であり承認では
ない。LLM が提案したグルーピングの妥当性は CP2a で人間がレビューする(レビュー
文書に `group_basis` と関連ヒント・エンティティリンクが表示される)。
`validate-analysis-groups` で rejected/warning が出たら、`ir-correlate-evidence`
の手順に従って候補を修正して再実行してから `build-claims` に進む。

CP2a と CP2b は別文書だが、**同じ会話の中で連続して**処理する(ユーザーから見れば
1 つのチェックポイント)。`approve-report-plan` は実行前に計画のセクション構成を
1 段落で提示し、異議がなければそのまま進める。

## チェックポイントでの提示方法

レビュー文書をそのまま貼らない。**要約 + 要注意項目**を提示する:

- 件数の全体像(承認候補 N 件、信頼度分布)
- **要注意項目を先に列挙**: 低信頼度(possible/unknown)の解釈、単一ソースの観測、
  矛盾の可能性、インジェクション痕跡、過大主張になりうる解釈。それぞれ 1 行で
  「ID / 内容 / なぜ注意か」
- 残りは「特に問題は見当たらない」とまとめ、一括承認できることを伝える
- CP2b では、`check-gaps` が出力する「ソース網羅状況」の 1 行と、ケース全体の
  不足事項(`related_claim_id: CASE-SCOPE`。未提供ホスト・未抽出・未承認のファイル)を
  先頭に示す。未抽出が多い場合は、CP3 に進む前に `ir-extract-evidence` へ戻って
  追加抽出する選択肢も示す(戻るかどうかは人間が決める)。詳細は
  `ir-agent --case-dir <case-dir> source-coverage` で確認できる
- 決定の選択肢を明示する(ラベルと意味は `ir_agent/governance/review_options.py` が正本):
  - 証拠: 承認 / 却下 / 保留
  - 分析結果: 承認 / 文言を直して承認(修正文を口述)/ 確度を下げて承認 / 却下 / 保留
  - 不足事項: 制約として報告書に書く / 追加調査として推奨対策に回す / 調査対象外とする / 保留
- **人間に求めるのは判定だけ**。理由は任意で、述べられなければ定型文を記録する
  (下記)。理由や記入欄コメントの記入を催促しない
- **HTML レビュー画面を案内する**。`review-evidence` / `review-claims` / `review-gaps` は
  Markdown と同名の `.html` を生成する(例: `reviews/claim_review_001.html`)。ブラウザで開くと、
  項目ごとのプルダウンと理由欄、要注意バッジ、進捗、絞り込みで判定できる。要注意の項目は
  一括設定の対象外で、1 件ずつ判定する。判定後に「決定をファイルに保存」または「決定をコピー」
  で JSON を書き出し、そのパスか中身をチャットで伝えてもらう。

## 決定の受け取り方

- **HTML から書き出した JSON(推奨)**:

  ```bash
  ir-agent --case-dir <case-dir> import-review-decisions --decisions <JSON のパス>
  ```

  JSON がチャットに貼り付けられた場合は、その内容をそのまま
  `reviews/<レビュー文書名>.decisions.json` に保存してから取り込む。取り込みは、JSON が
  現在のレビュー文書から作られたもの(SHA-256 一致)で、判定値が選択肢にあり、判定者の ID が
  入っている場合だけ成功する。エラーが出たら内容をユーザーに伝え、HTML で直してもらう
  (エージェントが JSON を作ったり書き換えたりしない)。成功したら、表示される apply
  コマンドを実行する。
- **チャットでの口述**: 下記の口述筆記ポリシーに従って Markdown の YAML ブロックに転記する。
  転記後に `render-review-html --review reviews/<文書名>.md` で HTML を作り直してよい。

## 口述筆記ポリシー(重要)

判断の主体は常に人間。エージェントは**転記者**に徹する。HTML 画面の JSON も人間の決定で
あり、`import-review-decisions` が一字一句転記する(エージェントが中身を作らない)。

- ユーザーがチャットで明示した決定だけを、レビュー文書の YAML ブロックに
  **一字一句そのとおり**転記してよい。
  - 明示の例: 「EV-012 は却下、理由は誤検知」「残りは全部承認」「CLM-3 の文言を
    『〜の可能性がある』に修正して承認」
  - 明示でない例: 「よしなに」「任せる」「適当に」→ 転記しない。判断材料を示して
    決定を求め直す。
- `analyst_id` は最初のチェックポイントでユーザーの ID(名前・ハンドル)を確認し、
  以後のコマンドで使い回す。エージェント自身の名前は使わない。
- `decision_reason` / `disposition_reason` はユーザーが述べた理由を書く。理由が
  述べられなかった場合は「approved via chat instruction by <analyst_id>」と記録する。
- エージェントが自分の判断で decision/disposition を埋めることは**禁止**。
  `bulk-mark-reviews` は実ケースで使わない。

## 進め方の例

```
👤「./cases/acme を解析して」
🤖 status 確認 → init/ingest → 証拠抽出スキル → 検証 → review-evidence
   「証拠候補 38 件を抽出しました。要注意は 3 件: …。残り 35 件は問題なさそうです。
    どうしますか?(あなたの analyst ID も教えてください)」
👤「analyst-01。EV-012 は却下、理由は重複。残りは承認」
🤖 転記 → promote-evidence → 分析 4 ステップ → review-claims
   「分析結果 21 件です。要注意 2 件: …」
   (…CP2a → CP2b → 計画提示 → ドラフト → 品質レビュー → CP3 → finalize)
```

## 注意

- 各コマンドはワークフロー状態機械が順序を守らせる。ブロックされたらその理由を
  ユーザーに伝える(先行フェーズの再実行が必要、など)。
- ドラフト生成・品質レビューは必ず該当スキル(`ir-draft-report` / `ir-review-quality`)
  の手順に従う。`check-draft` が PASS しないドラフトで CP3 に進まない。
  `workflow_state.json` は手で編集しない。
- CP3 では `reviews/quality_review_NNN.md`(総合所見・修正すべき指摘・人間が記入すべき
  事項)を要約して提示する。承認後にドラフトを変更すると `finalize-report` は止まる
  (`check-draft` → `approve-draft` をやり直す)。CP3 で何を提示し何を待つかは
  `status` の CP3 案内に従う(レビュー担当者記入欄が空のままでは `approve-draft` は
  止まり、`finalize-report` は承認者の ID を引き継ぐ)。
- 途中で止まっているケースを引き継ぐ場合も、常に `status` から始めれば正しい位置に戻れる。
