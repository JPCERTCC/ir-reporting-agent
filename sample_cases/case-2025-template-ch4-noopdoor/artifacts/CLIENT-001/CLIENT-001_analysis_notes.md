# CLIENT-001分析メモ

CLIENT-001では、2025年5月13日に `SAMPLE\Administrator` によるログオン、
`C:\ProgramData\Microsoft\UIAnimation.xml` の一時配置、`MSBUILD.EXE` の実行痕跡、
`HKCU\Software\Licenses\4F2C91` のレジストリ痕跡が確認された。

FS01と類似する `UIAnimation.xml` および `MSBUILD.EXE` の組み合わせであるため、
同一または類似した手口の展開先である可能性がある。ただし、CLIENT-001上での
外部通信やデータ持ち出しは、この抜粋からは確認できない。
