# ケース引き継ぎメモ

このケースは `incident_forensic_report_template_ja.md` 4章の証拠をArtifact化したもの。
証拠番号 E-101 などは元テンプレート上の番号であり、本ツールのEvidence Ledger IDとは別物。

## 初動メモ

2025-05-10 02:14 JST に `vpn-tokyo-01` で `SAMPLE\svc-backup` のSSL-VPN接続成功。
接続元 `89[.]233[.]109[.]69` は通常利用元と異なるとされる。
2025-05-10 03:02 JST に `SAMPLE\Administrator` が `AD01` へログオンしており、
時刻の近接性からVPN経由の侵入と整合する。ただし、VPN端末とADログオン端末を直接結びつける
単一ログは残っていない。

## 重要な制約

- VPN侵入原因は特定できない。脆弱性悪用、認証情報悪用、設定不備の可能性が残る。
- FS01の `collect_20250517.rar` はMFT上のファイル名痕跡のみで、ファイル本体は未取得。
- SFTP通信は暗号化されており、送信内容と送信ファイル名は確認できない。
- WEB01はディスク保全が限定的で、bash_historyにも削除痕跡がある。
- 2025-06-01のnetstatは取得時点の状態であり、TCP 47000待受の開始時刻を示さない。

## 期待するレポート上の論点

- 初期侵入: SSL-VPN接続とADログオンの時刻近接性
- 認証情報取得: AD01でのVSS、NTDS.dit、SYSTEM/SAM/SECURITYコピー試行
- 内部探索: whoami、net group、nltest、setspn
- 永続化: FS01のUpdateCheckタスク、AVMGMT01のレジストリ書き込み
- C2/外部通信: FS01から45[.]77[.]183[.]161、AVMGMT01から207[.]148[.]90[.]45、WEB01から207[.]148[.]103[.]42
- 情報持ち出し疑い: dir /s、collect_20250517.rar痕跡、SFTP通信量増加
