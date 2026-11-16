---
name: ir-review-quality
description: >-
  Run a quality review of an ir-agent draft incident report against the same
  JPCERT-style quality checklists used for external reports, plus internal
  evidence-grounding checks against the case ledger, writing findings to
  reviews/quality_review_NNN.md. Use this whenever the user asks to review the
  draft report, 品質チェック, チェックリスト確認, レポートレビュー, check the
  report quality, or after ir-draft-report has produced a draft and before
  human approval.
---

# IR 報告書品質レビュー(自作ドラフトの自己レビュー)

ベンダーに求める品質を、自分の報告書にも同じ基準で課す。中身は次の 2 つだけで、
このスキル独自の判定はしない:

1. **機械検査**: `ir-agent check-draft` と同じ検査(構造、【要記入】の残り、
   CP2 で承認した分析結果・不足事項の反映、4章抜粋の逐語一致、証拠にない IP)と、
   ソース網羅状況(提供ファイル → 証拠台帳 → 本文の追跡。台帳に証拠があるのに
   引用されていないファイル、本文で触れられていない未抽出・未承認・未提供の資料を列挙)。
2. **チェックリストレビュー**: 外部報告書レビューの手順そのもの
   (`ir-review-report-reporter`)を、ドラフトを入力にして DONE まで実行する。

結果は `write_quality_summary.py` が `reviews/quality_review_NNN.md` に集約する。
ドラフトは書き換えない(修正が必要なら `ir-draft-report` に戻る)。承認はしない —
承認は人間の役割(`ir-agent approve-draft`)。

## 手順

1. 前提: `ir-agent --case-dir <case-dir> check-draft` が PASS していること
   (`status` が draft_report_generated 済みを示す)。FAIL なら `ir-draft-report` へ戻る。
2. **チェックリストレビュー**: `ir-review-report-reporter` の SKILL.md の手順に、
   次の 2 点だけ読み替えて従い、`review_status.py` が DONE を返すまで進める。
   - 入力報告書: `<case-dir>/reports/draft_report.md`
   - 作業フォルダ: `REVIEW_DIR=<case-dir>/reviews/quality/$(date +%Y%m%d-%H%M%S)_<model-or-agent>_reporter`

   ドラフトでは「レビュー担当者記入欄」(問い合わせ先、1.1〜1.3、1.5、2.1、2.2、付録D)が
   仕様上未記入なので、それに関する項目は本文どおり `not_met` と判定してよい
   (集約時に「人間が記入すべき事項」として別に示される)。
3. **集約**:

   ```bash
   python .claude/skills/ir-review-quality/scripts/write_quality_summary.py \
     --case-dir <case-dir> --review-dir "$REVIEW_DIR"
   ```

   レビューが DONE でない、別ファイルを対象にしている、レビュー開始後にドラフトが
   変更された、のいずれかなら書き出さずに止まる。ドラフトを直した場合は
   check-draft からやり直し、新しい作業フォルダでレビューする。
4. **報告**: `quality_review_NNN.md` の総合所見、機械検査の結果、修正すべき指摘
   (重大度の高い順)、ソース網羅状況、人間が記入・確認すべき事項を要約してユーザーに伝える。
   修正すべき指摘があれば `ir-draft-report` での修正を提案する。
