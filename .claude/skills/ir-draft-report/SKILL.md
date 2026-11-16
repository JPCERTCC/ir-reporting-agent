---
name: ir-draft-report
description: >-
  Generate the Japanese incident-investigation draft report
  (reports/draft_report.md) for an ir-agent case from approved evidence,
  claims, timeline, and gaps. Use this whenever the user asks to draft the
  report, 報告書作成, ドラフト生成, インシデント調査報告書, or when the case
  workflow is at report_plan_approved and the next step is drafting.
---

# IR 調査報告書ドラフト生成

承認済みの証拠・分析結果・タイムライン・不足事項だけを根拠に、日本語の調査報告書ドラフト
`reports/draft_report.md` を作る。構造と機械的に決まる部分はスクリプトが生成し、
エージェントは文章(所見・考察・推奨)だけを書く。

## 手順

1. **素材と雛形の生成**:

   ```bash
   python .claude/skills/ir-draft-report/scripts/build_case_material.py --case-dir <case-dir>
   ```

   - `reports/case_material.json`: 唯一の事実ソース(EV-### エイリアス、承認済み分析結果、
     逐語の証拠抜粋、タイムライン、不足事項)。
   - `reports/draft_report.md`: 雛形。見出し・固定文・記入欄コメント・メタデータ・2.4 の表・
     4章の逐語ログ抜粋・付録A〜C は生成済み。1.2/1.3 は manifest の範囲・ホスト・期間を
     自動記入済み。記入欄コメント(問い合わせ先・1.1 など)は人間が任意で埋める欄であり、
     エージェントは書かず、最終承認の条件にもしない。既にドラフトがある場合は作らない
     (作り直すなら退避してから再実行)。
2. **執筆**: case_material.json を通読し、雛形の `【要記入: …】` をすべて文章に置き換える。
   各マーカーには、そこに書くべき分析結果(CLM-…)・証拠(EV-…)・不足事項(GAP-…)が
   書いてある。章をまたぐ攻撃の流れ(初期侵入 → 横展開 → 持ち出し)が一貫するよう、
   一気に書く。
3. **検証と登録**:

   ```bash
   ir-agent --case-dir <case-dir> check-draft
   python .claude/skills/ir-draft-report/scripts/lint_ja_style.py \
     --file <case-dir>/reports/draft_report.md
   ```

   `check-draft` は全問題を 1 回で出す。まとめて直して再実行し、PASS で
   `draft_report_generated` が記録される(workflow_state.json は手で編集しない)。
   `lint_ja_style.py` は助言で、定型文・引用に由来する警告は残してよい。
4. **報告**: 章ごとの要点、引用した証拠数、根拠不足で書けなかった箇所を要約する。
   次は `ir-review-quality`。

## 執筆規則

文章表現は `references/ja_writing_norms.md` に従う(本節の規則が優先)。

### 根拠

- 事実・日時・ホスト・ユーザー・IP・ファイル名・ツール名・原因・影響は case_material.json に
  あるものだけを書く。ないものは「提供資料からは確認できませんでした」と書く。
- 主要な所見・推論・推奨には「（証拠ID: EV-001, EV-002）」を付ける。不足事項は
  「（不足事項ID: GAP-…）」として証拠 ID と混ぜない。
- 制約(単一証拠、低確度、未取得ログ、対象外データ)は該当所見の中に書く。
  独立した「調査上の制約」章は作らない。
- `source_coverage` は提供資料の使われ方(未提供 / 未抽出 / 未承認)を示す。
  「未提供」は収集上の制約、「未抽出」「未承認」は解析上の制約として書き分け、
  関連ホストの節に対応する不足事項(related_claim_id が CASE-SCOPE のもの)の ID を添える。
  未抽出の資料を「ログがなかった」と書かない。

### 確度と文体

- です・ます調。確認済み事項は過去形(「確認されました」)で、「確認されています」は使わない。
- 確度で表現を変える: confirmed「確認されました」、probable「〜と考えられます」、
  possible「可能性があります」、unknown / not_observed「確認できませんでした」。
- 分析担当者の声で書く。「提供された証拠を精読した結果」「ケース材料によると」
  「整合します」のような生成過程を語る表現は使わない。
- 本文・表の時刻は report_timezone(既定 UTC)で「2026-05-02 07:18 (UTC)」形式。
  ログの時刻を別のタイムゾーンに換算しない。ISO 形式の生値はコードブロック内のログ抜粋だけ。
  check-draft がラベルと証拠時刻(引用した EV の時刻 ±1 分)を照合する。
- 攻撃関連の IP・ドメイン・URL は本文・表で defang(`203[.]0[.]113[.]10`、`hxxps://`)。
  内部 IP とコードブロック内は原文のまま。
- 強調記法(太字・斜体)と Mermaid は使わない。「Claim」「ギャップ」ではなく
  「分析結果」「不足事項」と書く。

### 各章で書くこと

- 2章 サマリー: 攻撃経路・影響・未確認事項・優先対応を 3〜6 点に統合する。うち 1 点は
  事業影響・情報漏えいの可能性・再侵入リスク・残存リスクを確度付きで述べる
  (定量化できなければその旨を明記する)。
- 2.4 タイムライン: 「事象」列に短い要約を書く。確度列は攻撃活動としての解釈確度であり、
  3章本文の確度と一致させる。
- 3章: 各節は確認事実 → 複数証拠のつながり(同一アカウント・同一 IP・時刻の近接)の考察
  → 制約の順に最低 2 段落。分析結果を箇条書きで並べない。`group_basis` のある分析結果は
  その根拠を考察に使う。観測のない段階も見出しを残し、確認できなかった旨と関連する
  不足事項を書く。
- 4章: 各ホストの小節に確認事実・時系列・考察・制約を書く。生成済みの抜粋は改変しない。
  末尾の 2 表(侵害・侵害疑いのアカウント/ホスト、窃取・窃取疑いデータ)は、未確認でも
  確認状況(確認済み/疑い/未確認)を明記して埋める。
- 5章: 各対応に、対応する調査結果・不足事項、目的、対象、優先度、期待効果、実施上の注意、
  依存関係を書く。
- 付録A: 不要な行(OS 標準ファイル等)は削除し、残す行の「概要/役割」を書く。
  付録B: 3章の記述・確度と整合しない行は直すか削除する。付録C・D と記入欄コメントは
  書き換えない。

報告書の構成(見出し・固定文・記入欄・表の列)は
`ir_agent/reporting/templates/report_template_ja.md` が唯一の定義で、雛形と
`check-draft` はどちらもそこから作られる。構成を変えるときはこのファイルだけを編集する。
