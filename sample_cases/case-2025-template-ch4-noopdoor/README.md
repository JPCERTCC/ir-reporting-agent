# サンプルケース: テンプレート4章ベース NOOPDOOR類似侵害調査

このサンプルケースは、`incident_forensic_report_template_ja.md` の4章
「対象別調査結果詳細」に記載された証拠・ログ抜粋を、IR Evidence-Grounded
Reporting Agent のテスト用Artifactとして再構成したものです。

## シナリオ

2025年5月10日、外部IP `89[.]233[.]109[.]69` から
`SAMPLE\svc-backup` を用いたSSL-VPN接続が確認されました。その後、
`SAMPLE\Administrator` によるADサーバーへのログオン、内部探索、
`NTDS.dit` とレジストリハイブへのアクセス、FS01への `UIAnimation.xml`
配置と `MSBuild.exe` 実行、AVMGMT01での `NOOPLDR.dll` 配置、WEB01での
GOST類似バイナリ実行、CLIENT-001での同様の痕跡が確認されています。

## 構成

```text
case-2025-template-ch4-noopdoor/
  manifest.yaml
  artifacts/
    VPN/
    AD01/
    AD02/
    FS01/
    AVMGMT01/
    WEB01/
    CLIENT-001/
    Firewall/
```

## テスト観点

- 章4のような報告書品質へ近づくLLMレポート生成
- 日本語の自由記述メモと構造化ログの混在
- VPN、AD、ファイルサーバー、管理サーバー、公開Web、クライアント端末の横断相関
- 「可能性が高い」「未特定」「確認できない」といった制約表現
- `NOOPDOOR` 類似挙動、`MSBuild.exe` 悪用、GOST類似プロキシ、SFTP外部送信疑い
- 証拠保全付録でのレポート用証拠IDと元ログの追跡

## 実行例

```bash
cd ir-reporting-agent
ir-agent --case-dir sample_cases/case-2025-template-ch4-noopdoor ingest \
  --artifacts-dir sample_cases/case-2025-template-ch4-noopdoor/artifacts
ir-agent --case-dir sample_cases/case-2025-template-ch4-noopdoor normalize-events
ir-agent --case-dir sample_cases/case-2025-template-ch4-noopdoor extract-candidates
```

このケースは、実在組織のログではなく、テンプレート文書の検証用記述を元にした
架空データセットです。
