# レビュー判断基準

**Agent が判断するときの基準だけ**を書いています。次の内容は別のファイルにあります。

- JSON の形・許可値・例: `json_contracts.md`
- スクリプトが何を自動でやるか・次に何を実行するか: `scripts_index.md` と `review_status.py` の `NEXT STEP`

## 1. 目的と範囲

インシデント調査報告書の**本文**を、チェックリストに照らして評価します。

- 評価するのは「チェックリストが求める事項が書かれているか」と「主要結論が本文の根拠・論理・確度表現で支えられているか」です。
- 調査の再実施、ログの再解析、技術的な真偽の判定はしません。書かれていない事実を補いません。
- 観点は mode で決まります。`customer`（依頼者が受領時に確認すべき事項）と `reporter`（作成者が品質を確認すべき事項）を混ぜません。

## 2. チェックリスト項目の判定

### 判定の意味

| 判定 | 意味 |
|---|---|
| `met` | 項目の詳細要件を本文が満たしている |
| `partial` | 一部だけ満たしている（何が足りないかを `rationale` に書く） |
| `not_met` | 満たしていない、または本文に記載がない |
| `not_applicable` | 条件付き項目（「［依頼している場合］」等）で、条件が本文から満たされないと分かる（`applicability: "not_applicable"` と理由を書く） |
| `unknown` | 判断に報告書外の資料が必要。`unknown_reason`（`external_information_missing / applicability_unknown / extraction_incomplete`）と `external_confirmation_needed`（確認すべき資料）が必須 |

- `unknown` を使えるのは `unknown_allowed: true` の項目（契約書・合意記録・証拠保全記録などが要る項目）だけです。本文から判断できる項目（`evaluable_from_report: true`）には使いません。
- `unknown_allowed: true` の項目でも、報告書が本来含めるべき内容（証拠ID一覧、調査範囲、ハッシュ値など）が無ければ `unknown` ではなく `not_met` です。
- `level`（必須/推奨/任意）は判定を変えません。指摘の重さだけに影響します。

### SubAgent の観測がある／ない／食い違うとき

観測は「その chunk の記載だけで見た暫定判定」です。最終判定は Agent が決めます。

| 状況 | 扱い |
|---|---|
| 全員が同じ verdict で一致し、根拠 span がある | 自動転記の候補（`suggestion`）。ただし「すべて／各／一貫」を含む項目の `met` は、全体で成り立つかを自分で確認する |
| 食い違っている（`conflicting`） | 根拠 span を読み直して決め、採用した span と理由を `rationale` に書く。決まらなければ保守的な方（`met`＜`partial`＜`not_met`） |
| 観測が0件 | 全 chunk を SubAgent が読み終えたうえで記載がなかったものとして扱う。**報告書を検索し直さない**。`unknown_allowed: false` の項目は `not_met` を、調査前の合意事項（`pre_engagement`）の項目は `unknown`（確認すべき報告書外の資料つき）を自動転記。それ以外の `unknown_allowed: true` の項目と条件付き項目は、項目の性質から `not_met` / `unknown` / `not_applicable` を選ぶ |

### 根拠 span

- `source_span_ids` は最終判定の根拠になった span だけを入れます。目次・表紙・ヘッダー・フッターだけの span は根拠にできません。
- `not_met` / `unknown` を根拠 span なしで判定するときは `absence_check_ids`（`ABS-<checklist_id>`）を入れます。SubAgent が span を観測していたのに、それを無視して未記載扱いにはできません。

## 3. issues.json と主要結論の書き方

雛形（`auto_filled` が機械入力した項目）は出発点です。項目ごとに観測と本文を読んで見直します。

- span は、対応する項目の observation が持つ `source_span_ids` をそのまま使います。span ID を推測や記憶で選び直さず、実在する根拠が見つからない issue は作りません。
- category は observation の分類を尊重します（複数 observation を統合した結果として変わるのは正常な判断です）。`unknown` の項目は必ず `external_confirmation` の issue になります。
- 複数 observation や `open_questions` を1つの issue にまとめたときだけ、元の ID を `source_observation_ids` に残します（全件の台帳は作りません）。
- `stated_conclusion` は topic ラベルの言い換え（「initial_access に関する記載がある」等）にせず、対象ホスト・手法・時刻・確度など、本文を読まないと書けない内容にします。
- SubAgent が観測した topic を `not_reported` にするなら、`override_reason` に理由を書きます。
- `partially_supported` / `unsupported` などの弱い評価には、その評価専用の issue が自動で作られ、`issue_ids` も自動で入ります。`issue_ids` は書きません（実在しない ID は除かれます）。issue の `reason` と `suggested_revision` を見直します。

| merged_observations.json | 反映先 |
|---|---|
| `checklist_observations` | `results.json`（`checklist_id` ごと） |
| `conclusion_observations` | `claim_assessments.json`（`topic` ごと） |
| `issue_observations` | `issues.json`（`related_checklist_ids` で対応付け） |
| `open_questions` | `issues.json`（雛形が自動で入れる）。放置は禁止 |

## 4. 主要結論レビュー

チェックリスト評価とは別に、次の順で評価します。

1. 主要結論を棚卸しする（topic: `initial_access, scope, lateral_movement, persistence, c2_external, exfiltration, impact, limitations, recommendations`）
2. 結論間の整合性を評価する
3. 各結論の根拠・論理・確度・限界を評価する（評価行には `review_verdict` と、根拠・論理・確度をまとめた `reason` を書く。限界は任意の `limitations` に書く）
4. 推奨対策が主要結論・未確認事項・残存リスクに対応しているか評価する

記載がなければ `not_reported`、事案上対象外なら `not_applicable` です。

- **根拠**: 本文・表・タイムライン・証拠ログ・IoC・付録に接地しているか。
- **論理**: 証拠から結論への飛躍がないか。サマリーが詳細章より強く断定していないか。代替仮説や調査限界が無視されていないか。
- **確度**: 次に正規化します。否定や不明の表現を `confirmed` にしません。

| 値 | 表現例 |
|---|---|
| `confirmed` | 確認した、特定した、実行された、判明した |
| `highly_likely` | 可能性が高い、強く疑われる、ほぼ確実 |
| `possible` | 可能性がある、疑いがある、示唆される、とみられる |
| `unknown` | 確認できない、断定できない、特定できない、不明 |
| `negative` | 確認されなかった、痕跡はなかった、検出されなかった |

典型的な品質欠陥: 根拠なし断定／確度の過大表現／サマリーと詳細章の矛盾／タイムライン・影響範囲・侵害範囲の不整合／C2 や情報持ち出しなど重要結論の証拠不足／推奨対策が所見や残存リスクに紐づいていない／調査制約や未確認事項が結論に反映されていない。

## 5. IoC / 外部通信

外部 IP を一括して「C2」と書きません。報告書の記載に基づき役割を保持します（複数あれば根拠を示して複数付与）:
`VPN接続元 / C2疑い通信先 / 情報持ち出し疑いの送信先 / プロキシ通信先 / DNS問い合わせ先 / 未分類の外部通信先`
