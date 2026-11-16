# FS01分析メモ

`FS01` では、SMB経由で `C:\ProgramData\Microsoft\UIAnimation.xml` が配置され、
その後 `MSBuild.exe` により実行された痕跡が確認された。`UIAnimation.xml` は
MSBuildで実行可能なXML形式で、難読化されたC#コードを含むとされる。

マルウェア分析では、外部C2サーバーへの接続、ファイル送受信、任意コマンド実行、
TCP 47000番での待受機能を有するNOOPDOOR類似の挙動が確認された。

`collect_20250517.rar` はMFT上のファイル名痕跡のみで、ファイル本体は取得できていない。
SFTP通信と外部通信量増加の時刻は近接しているが、送信内容は暗号化されており確認できない。
