---
name: ir-correlate-evidence
description: >-
  Propose entity links and multi-evidence analysis groups for an ir-agent case
  from the approved evidence ledger, field grounding, and correlation hints,
  writing data/entity_link_candidates.jsonl and
  data/analysis_group_candidates.jsonl for CLI validation. Use this whenever
  the user asks to correlate evidence, 相関分析, 分析結果の統合, エンティティ
  リンクの提案, group evidence into analysis results, or when the case workflow
  is at correlation_hints_built and the next step is validate-analysis-groups.
---

# IR 証拠相関・分析結果統合案の作成

承認済み証拠台帳と機械生成の相関ヒントを読み、複数証拠に支えられた
分析結果グループとエンティティリンクの**候補**を提案する。
出力は未信頼データとして扱われ、`ir-agent validate-analysis-groups` が
機械的に接地検証する。人間の承認は後段の CP2(`review-claims`)で行われる。

```text
No Grounding, No Correlation.
No Correlation Evidence, No Integrated Analysis Result.
No Unsupported Entity, No Claim Text.
```

## 前提

`<case-dir>/workflow_state.json` の `completed_phases` に
`correlation_hints_built` があること。なければ先に:

```bash
ir-agent --case-dir <case-dir> ground-evidence-fields
ir-agent --case-dir <case-dir> build-correlation-hints
```

## 入力(すべて読み込む)

- `data/evidence_ledger.jsonl` — 承認済み証拠(withdrawn は除外)
- `data/field_grounding.jsonl` — 接地済みフィールド値(`derived` 派生値含む)
- `data/correlation_hints.jsonl` — 機械生成の相関候補(材料であり結論ではない)
- `data/timeline.jsonl` — 時系列
- `data/attack_mappings.jsonl` — 証拠単位の ATT&CK 候補
- `data/data_coverage.jsonl` — データカバレッジ

## 出力 1: `data/entity_link_candidates.jsonl`

同一エンティティ(IP、アカウント、ホスト、ファイル等)が複数証拠に現れる
ことを示すリンク。1 行 1 JSON:

```json
{"entity_link_id": "ENTL-001",
 "entity_type": "ip_address",
 "canonical_label": "10.8.14.23",
 "members": [
   {"evidence_id": "<evidence_id>", "field": "tunnel_ip", "value": "10.8.14.23"},
   {"evidence_id": "<evidence_id>", "field": "src_ip", "value": "10.8.14.23"}
 ],
 "link_reason": "VPN割当IPとWindowsログオンの接続元IPが一致します",
 "related_hint_ids": ["HINT-..."],
 "review_status": "pending"}
```

- `field` / `value` は `field_grounding.jsonl` に存在する値のみ使う
  (`derived` の `tunnel_ip` のような派生フィールドも可)。
- 相関ヒントを参考にしつつ、意味的に確からしいリンクを追加してよい。
  ただし**証拠に存在しない値を新規作成してはいけない**。

## 出力 2: `data/analysis_group_candidates.jsonl`

複数証拠を意味的に束ねた分析結果案。1 行 1 JSON:

```json
{"analysis_group_id": "AGRP-001",
 "title": "AD01における資格情報関連ファイル取得",
 "report_section": "3.2",
 "claim_text": "AD01において、…が記録されました。",
 "claim_category": "interpretation",
 "supporting_evidence": ["<evidence_id>", "<evidence_id>"],
 "related_entity_link_ids": ["ENTL-001"],
 "related_hint_ids": ["HINT-..."],
 "attack_mappings": [
   {"technique_id": "T1003.003", "technique_name": "OS Credential Dumping: NTDS",
    "tactic": "Credential Access",
    "supporting_evidence": ["<evidence_id>"],
    "mapping_reason": "…が記録されました"}
 ],
 "limitations": ["取得後の復号・解析・外部送信までは本証拠群のみでは確認できません"],
 "group_basis": "同一ホスト、同一アカウント、近接時刻、…が一致します",
 "review_status": "pending"}
```

## ルール(必読)

- **証拠に存在しない値(IP、ホスト、ユーザー、パス、ハッシュ、時刻)を
  claim_text に書かない**。書いた値は接地検証で warning になる。
- 分析結果は必ず 1 件以上の `evidence_id` を持つ。
- 可能な限り複数証拠に支えられた分析結果へ統合する。単一証拠に留める場合は、
  なぜ統合しないかを `limitations` または `group_basis` に記載する。
- `report_section` は固定値から選ぶ:
  `3.1` 初期侵入 / `3.2` 認証情報取得・アカウント悪用 / `3.3` 内部探索・横展開 /
  `3.4` 永続化 / `3.5` C2通信・プロキシ・外部通信 / `3.6` 情報窃取・情報持ち出し /
  `3.7` 防衛回避・痕跡消去 / `context` 背景情報 / `limitation` 調査上の制約
- `claim_category` は `observed_fact` / `interpretation` / `causal_relationship` /
  `impact_assessment` / `data_exfiltration_assessment` /
  `intrusion_vector_assessment` / `attribution_assessment` から選ぶ。
- 事実と解釈を分離する。攻撃者の意図、侵入原因、情報漏えい内容など、
  証拠から直接確認できない事項は断定しない(例: 暗号化通信のみで「漏えいした」、
  ログオン記録のみで「認証情報が窃取された」、外部IP通信のみで「C2サーバ」と
  断定しない)。
- ATT&CK は証拠の `attack_mapping_candidates` / `attack_mappings.jsonl` に
  ある technique のみ使う。**新しい technique を推測して追加しない**。
- `limitations` は空にしない。制約が本当にない場合のみ空とし、CP2 で
  確認される warning を受け入れる。
- 確度(confidence)は書かない。確度は CLI が機械計算する。
- 日本語の `claim_text` は「です・ます調」を原則とし、確認済み事項は過去形で
  記載する。

## 手順

1. 入力を全て読み、証拠間の関連(相関ヒント + 意味的関連)を整理する。
2. 上記スキーマで 2 つの JSONL を `<case-dir>/data/` に書く。
3. 検証を実行する:

   ```bash
   ir-agent --case-dir <case-dir> validate-analysis-groups
   ```

4. `rejected` / `warning` が報告されたら、理由を確認して候補を修正し再実行する
   (存在しない証拠ID・許可外の report_section・許可外の ATT&CK ID は rejected、
   未接地の値・空の limitations は warning)。
5. ユーザーに要約を報告する: リンク数、グループ数、複数証拠グループの割合、
   注目すべき横断関連(例: VPN 割当 IP と AD ログオン元 IP の一致)。
   次ステップは `ir-agent build-claims`(分析結果の作成)。
