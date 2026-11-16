# サンプルケース: VPN侵害疑いからファイルサーバーステージングまで

このサンプルケースは、IR Evidence-Grounded Reporting Agent のテスト用に
作成した架空のインシデントレスポンスデータセットです。システム別フォルダに、
整形済みのフォレンジックエクスポートと、粗い分析メモ、コンソール出力の貼り付け、
OCRテキスト、チャット抜粋、引き継ぎメモを意図的に混在させています。

## シナリオ

外部IPから `svc-vpn-backup` を使用した VPN 認証成功が確認されています。
その後、同じ VPN 割当アドレスから `WEB01` へのアクセス、Web ルート配下の
Web shell らしきファイル、`AD01` でのドメイン探索、`FS01` でのアーカイブ作成と
SFTP 通信が観測されています。正常系の操作、Firewall のブロックログ、
認証失敗、取得できなかったテレメトリ、分析者の不確実なコメントも含めており、
gap や断定しすぎの検出を試せるようにしています。

## 構成

```text
case-2026-vpn-compromise/
  manifest.yaml
  artifacts/
    AD01/
    Firewall/
    VPN/
    WEB01/
    FS01/
    WIN10-023/
```

## 実行例

```bash
cd ir-reporting-agent
ir-agent --case-dir sample_cases/case-2026-vpn-compromise ingest \
  --artifacts-dir sample_cases/case-2026-vpn-compromise/artifacts
ir-agent --case-dir sample_cases/case-2026-vpn-compromise normalize-events
ir-agent --case-dir sample_cases/case-2026-vpn-compromise extract-candidates
```

このデータセットは架空のものです。IPアドレスは可能な範囲でドキュメント用レンジを
使用しています。正規化されたログ形式だけでなく、実際のIR作業中に発生しがちな
雑多で重複のある資料に対して extractor を試せるよう、あえて一部を粗い状態にしています。

## 自由記述入力のテスト観点

Artifact は固定スキーマに従う必要はありません。このケースには、平文の調査メモ、
日本語中心のメモ、OCR風テキスト、ターミナル出力の貼り付け、半構造化リストが含まれます。
任意の `artifact_metadata.yaml` は、取得ツール、Artifact 種別、システム役割などの
文脈を補足します。ただし metadata は文脈であり、それ自体は証拠として扱わない想定です。

このサンプルケースでは `llm_extract_structured_artifacts: true` を設定しているため、
LLM 抽出は CSV や syslog 形式の Artifact も参照します。ルールベース parser は有用ですが、
Evidence Candidate 生成の唯一の入口ではありません。

意図的に自由記述にしているファイル例:

- `artifacts/case_handoff_notes.md`
- `artifacts/VPN/operator_chat_paste.txt`
- `artifacts/Firewall/firewall_admin_clipboard.txt`
- `artifacts/AD01/freeform_investigation_notes.txt`
- `artifacts/WEB01/screenshot_ocr_notes.txt`
- `artifacts/FS01/freeform_triage_notes.txt`
- `artifacts/WIN10-023/helpdesk_ticket_notes.md`
