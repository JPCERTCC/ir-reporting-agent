# JSON 契約（IR 報告書レビュー）

Agent が作成・修正する JSON の最小契約です。迷った場合はこの形に合わせます。

## 共通

- `source_span_ids` は `source_index.json` に存在する `SPN-*` だけを入れます。
- 未記載の指摘は、無関係な span ではなく `absence_check_ids` に接地します。
- 空配列、行番号、ページ番号、任意文字列は根拠 ID として使いません。
- 許可値を自然言語で言い換えません。

## results.json

`init_results_template.py` の出力を全項目埋めます。

```json
{
  "metadata": {"schema_version": "1.0", "mode": "customer"},
  "results": [
    {
      "checklist_id": "CUS-1-1",
      "section": "1",
      "item": "問い合わせ先が記載されているか",
      "level": "必須",
      "unknown_allowed": false,
      "verdict": "not_met",
      "applicability": "applicable",
      "rationale": "報告書内に問い合わせ先が確認できない。",
      "source_span_ids": [],
      "absence_check_ids": ["ABS-CUS-1-1"],
      "unknown_reason": null,
      "external_confirmation_needed": ""
    }
  ]
}
```

### verdict

`met / partial / not_met / unknown / not_applicable`

- 本文から判定できる項目（`unknown_allowed: false`）は `unknown` にしません。
- `unknown` は `unknown_allowed: true` かつ報告書外資料が必要な場合だけ使います。
  その場合は次を必ず入れます。
  - `unknown_reason`: `external_information_missing / applicability_unknown /
    extraction_incomplete` のいずれか
  - `external_confirmation_needed`: 確認すべき報告書外資料（例: 調査依頼時の合意書、
    証拠保全記録）
- `not_met` / `partial` の品質欠陥は `issues.json` に対応 issue を作ります
  （level による扱いは「issues と level」参照）。
- 判定の考え方と、SubAgent 観測から `results.json` への集約手順は
  `review_model.md` を参照します。

## issues.json

トップレベルは配列、または `{"issues": [...]}` のどちらでも可です。
各 issue には `category`, `severity`, `checklist_ids`, `reason`,
`suggested_revision` を入れます。

任意フィールド `source_observation_ids` に、この issue の元になった
`merged_observations.json` の `observation_id`（または `open_questions` の
`question_id`）を入れられます。複数 observation を1つの issue に統合した場合や、
`open_questions` を issue化した場合の traceability 用です（`review_model.md`
の「3. issues.json と主要結論の書き方」参照）。省略可能で、`review_status.py` の検証は `open_questions` が
残っている場合にだけこの値を参照します。

### 本文上の根拠に接地する例

```json
{
  "category": "evidence_integrity",
  "severity": "high",
  "checklist_ids": ["CUS-3.2.3-3"],
  "status": "not_met",
  "source_span_ids": ["SPN-0123"],
  "absence_check_ids": [],
  "reason": "情報持ち出しの判断に必要なログ、転送量、対象ファイルが提示されていない。",
  "suggested_revision": "外部通信ログ、転送量、対象ファイル、判断できない場合の制約を追記する。"
}
```

### 未記載に接地する例

```json
{
  "category": "missing_required_item",
  "severity": "medium",
  "checklist_ids": ["CUS-1-1"],
  "status": "not_met",
  "source_span_ids": [],
  "absence_check_ids": ["ABS-CUS-1-1"],
  "reason": "問い合わせ先が報告書内に確認できない。",
  "suggested_revision": "問い合わせ先、担当部署、連絡方法を追記する。"
}
```

### issues と level

`results.json` の項目の `level` により、`issues.json` の扱いが変わります。

| level / verdict | 扱い |
|---|---|
| 必須 / 推奨 / `-` の `partial` / `not_met` | 対応する品質欠陥 issue が必須（`category` は `optional_enhancement` / `external_confirmation` 以外） |
| 任意 の `partial` / `not_met` | `optional_enhancement`（`severity: low`）。品質欠陥として `high` 以上にしない |
| `unknown` | `category: external_confirmation` の issue が必須。品質欠陥にはしない（検証が unknown 全件の issue 存在を確認する） |

### 根拠 ID（absence_check_ids）

- 未記載を根拠にする場合の ID は `ABS-<checklist_id>`（例: `ABS-CUS-1-1`）とします。
- 主要結論の未記載は `ABS-CON-<topic>`（例: `ABS-CON-exfiltration`）とします。
- ID は、全 chunk の SubAgent が読み終えたうえで、どの chunk にもその観点の記載が
  観測されなかったことを表します（`observation_count: 0`）。報告書を検索し直して確認する
  必要はありません。
- `results.json` で `not_met` / `unknown` かつ `source_span_ids` が空（未記載扱い）の行は、
  検証が `aggregation_worksheet.json` と突き合わせます。
  SubAgent がその checklist_id に対して span 付きの observation を実際に残していた場合、
  それを引用せずに未記載扱いにすると FAIL します（文言のチェックではなく、
  SubAgent が既に集めた証拠を握りつぶしていないかの構造チェックです）。
  observation が 0 件の項目には何も要求しません。

### category

`evidence_integrity / unsupported_claim / certainty_inconsistency /
cross_section_inconsistency / missing_required_item / countermeasure_mapping /
format_or_usability / external_confirmation / optional_enhancement`

### severity

`critical / high / medium / low / info`

`external_confirmation` は品質欠陥にしません。`optional_enhancement` は `low` にします。

### 自動入力の印（`auto_filled` / `override_reason`）

雛形（`review_status.py` が自動生成）が入力した行には、
`auto_filled`（機械入力したフィールド名の配列）が付きます。検証・レンダリングは無視する
補助フィールドで、Agent は消さず、確認・修正したフィールドをそのまま上書きします。
`claim_assessments.json` の `conclusion_inventory` で、SubAgent が根拠 span 付きで観測した
topic を `not_reported` にする行には、任意フィールド `override_reason`（なぜ観測を採用しないか）
が必須です。`【要記入】` が残っている issue / 評価行は検証で FAIL します。

## claim_assessments.json

主要結論レビューは次の4配列で構成します。

```json
{
  "conclusion_inventory": [
    {
      "conclusion_id": "CON-001",
      "topic": "initial_access",
      "presence": "reported",
      "stated_conclusion": "VPNアカウントの悪用により初期侵入した可能性が高い。",
      "assessment_ids": ["ASM-001"],
      "source_span_ids": ["SPN-0101"],
      "absence_check_ids": []
    }
  ],
  "consistency_assessments": [
    {
      "consistency_id": "CNS-001",
      "related_conclusion_ids": ["CON-001"],
      "consistency_verdict": "consistent",
      "source_span_ids": ["SPN-0101"],
      "absence_check_ids": [],
      "reason": "サマリーと詳細章の説明に矛盾はない。"
    }
  ],
  "claim_assessments": [
    {
      "assessment_id": "ASM-001",
      "topic": "initial_access",
      "conclusion": "VPNアカウントの悪用により初期侵入した可能性が高い。",
      "stated_confidence": "highly_likely",
      "review_verdict": "supported",
      "reason": "VPN認証ログと接続元の説明が対応し、確度表現も根拠に対して過大ではない。",
      "limitations": ["VPN装置の詳細ログが一部不足している。"],
      "source_span_ids": ["SPN-0101"],
      "issue_ids": []
    }
  ],
  "recommendation_assessments": [
    {
      "recommendation_id": "REC-001",
      "recommendation": "VPNアカウントのMFAを強化する。",
      "linked_finding_ids": ["ASM-001"],
      "review_verdict": "mapped",
      "reason": "初期侵入経路の評価に対応している。",
      "source_span_ids": ["SPN-0201"],
      "issue_ids": []
    }
  ]
}
```

Agent が書くのは、各評価行の `review_verdict` と `reason` だけです（雛形が他を入力します）。
`reason` には、根拠・論理・確度の観点から見た評価を1つにまとめて書きます。
報告書自身が認めている限界（調査できなかったこと、ログ不足など）を分けて示したいときは、
任意の `limitations`（文字列の配列）に書きます。どの評価行にも無ければ、最終レビューの表に
「限界」列は出ません（雛形は空の `limitations` を用意しません）。
`conclusion_inventory` の `reason` と `suggested_revision`（各評価行・整合性・推奨対策）は
任意です。以前の形式にあった `support_summary` / `evidence_assessment` /
`logic_assessment` / `confidence_assessment` は不要になりました
（あっても検証は通り、レンダリングでは `reason` にまとめて表示されます）。

`conclusion_inventory` / `consistency_assessments` / `claim_assessments` /
`recommendation_assessments` の各行にも、任意フィールド `source_observation_ids`
を付けられます。用途は `issues.json` と同じです（`review_model.md` 参照）。
`open_questions` を conclusion 側で対応した場合は、ここに `question_id` を入れます。

### topic

`initial_access / scope / lateral_movement / persistence / c2_external /
exfiltration / impact / limitations / recommendations / other`

必ず確認する topic:

`initial_access, scope, lateral_movement, persistence, c2_external,
exfiltration, impact, limitations, recommendations`

### presence

`reported / not_reported / not_applicable / not_assessable`

- `reported`: `source_span_ids` と `assessment_ids` が必要です。
- `not_reported`: `absence_check_ids` が必要です。

### stated_confidence

`confirmed / highly_likely / possible / unknown / negative`

### claim_assessments.review_verdict

`supported / partially_supported / unsupported / not_assessable`

`partially_supported` / `unsupported` は `issue_ids` が必要ですが、Agent は書きません。
`review_status.py` が、その評価専用の issue（`assessment_ids` で評価を指す）を作り、
`issue_ids` を埋めます。実在しない ID（観測 ID など）は除かれ、評価を `supported` に
変えた場合は自動生成した issue も消えます。`consistency_assessments`（`minor_` /
`major_inconsistency`）と `recommendation_assessments`（`partially_mapped` /
`not_mapped`）も同様です。

### consistency_verdict

`consistent / minor_inconsistency / major_inconsistency / not_assessable`

### recommendation_assessments.review_verdict

`mapped / partially_mapped / not_mapped / not_assessable`

`linked_finding_ids` は `ASM-*` を参照します。`CON-*` は使いません。

## subagent_observations/CHK-NNN.json

SubAgent（Agent ツールで task ごとに起動）が、task 内の `observation_output_path` に作成します。
各 task の `output_schema.allowed_values` は、このドキュメントの許可値と同一です。

```json
{
  "chunk_id": "CHK-001",
  "review_mode": "customer",
  "covered_span_ids": ["SPN-0001", "SPN-0002"],
  "checklist_observations": [
    {
      "observation_id": "OBS-CHK-001-001",
      "checklist_id": "CUS-1-1",
      "candidate_verdict": "met",
      "rationale": "問い合わせ先が記載されている。",
      "source_span_ids": ["SPN-0001"],
      "absence_check_ids": [],
      "confidence": 0.82
    }
  ],
  "conclusion_observations": [
    {
      "observation_id": "OBS-CHK-001-002",
      "topic": "initial_access",
      "stated_conclusion": "VPNアカウントの悪用が初期侵入経路とされている。",
      "source_span_ids": ["SPN-0018"],
      "confidence_language": "highly_likely",
      "notes": "詳細章との照合が必要。"
    }
  ],
  "issue_observations": [
    {
      "observation_id": "OBS-CHK-001-003",
      "category": "evidence_integrity",
      "severity_hint": "medium",
      "related_checklist_ids": ["CUS-3.2.3-3"],
      "reason": "情報持ち出しの可能性が記載されているが、根拠ログがない。",
      "source_span_ids": ["SPN-0025"],
      "suggested_revision": "根拠ログまたは確認できなかった旨を追記する。"
    }
  ],
  "open_questions": [
    {
      "question_id": "Q-CHK-001-001",
      "question": "依頼者に追加確認すべき事項。",
      "reason": "chunk内の記載だけでは判定できない理由。",
      "source_span_ids": ["SPN-0028"],
      "related_checklist_ids": ["CUS-2-4"]
    }
  ]
}
```

SubAgent は担当 chunk しか見ません。次の点に注意します。

- `checklist_observations` は、chunk 内に該当する記載がある項目についてだけ出します。
  chunk 内に記載がない項目の observation は出しません（chunk 単独では `not_met` と言えません）。
- `candidate_verdict` は、その chunk の記載だけで見た暫定判定です。
- 最終判定と未記載判定は、親 Agent が全 chunk を集約して行います。
- `covered_span_ids` は、実際に読んだ core span を漏れなく入れます。
- `open_questions` に項目を入れる場合は文字列ではなく object にします。
  質問がなければ `[]` にします。

`open_questions` の必須キー:

`question_id, question, reason, source_span_ids`

`related_checklist_ids` は分かる場合だけ入れます。

必須 top-level key:

`chunk_id, review_mode, covered_span_ids, checklist_observations,
conclusion_observations, issue_observations, open_questions`

禁止 top-level key:

`reviewed_span_ids, checklist_relevant_observations, potential_issues,
claim_extractions, evidence_hits`

## merged_observations.json

`review_status.py` が生成します。手書きしません。

```json
{
  "chunks": [],
  "checklist_observations": [],
  "conclusion_observations": [],
  "issue_observations": [],
  "open_questions": []
}
```

`chunk_observations` だけの独自形式にしません。

## coverage_ledger.json

`review_status.py` が生成します。

```json
{
  "source_span_count": 149,
  "chunks": [
    {
      "chunk_id": "CHK-001",
      "assigned_span_ids": ["SPN-0001"],
      "covered_span_ids": ["SPN-0001"],
      "missing_assigned_span_ids": [],
      "status": "completed"
    }
  ],
  "uncovered_span_ids": [],
  "duplicate_coverage_span_ids": [],
  "coverage_complete": true
}
```

`coverage_complete` が `false` の場合は完了できません。
