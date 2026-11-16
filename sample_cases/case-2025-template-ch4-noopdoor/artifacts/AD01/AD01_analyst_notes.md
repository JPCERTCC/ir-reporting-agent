# AD01分析メモ

VPN接続後、`SAMPLE\Administrator` によるAD01ログオンが確認された。
その後、`whoami /all`、`net group "Domain Admins" /domain`、`nltest /dclist:SAMPLE`、
`setspn -T SAMPLE -Q */*` が実行されており、現在の権限、ドメイン管理者、
ドメインコントローラー、サービスアカウントを確認する内部探索と考えられる。

03:18に `vssadmin create shadow /for=C:` が実行され、03:25頃に `NTDS.dit`、
`SYSTEM`、`SAM`、`SECURITY` へのアクセスおよびコピー試行が確認された。
03:41にはEventID 1102によりセキュリティログ消去が確認されている。
