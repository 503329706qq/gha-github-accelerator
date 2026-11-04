# gha 基准记录

同一台机器、同一时段分别测直连与经 gha；每项 5 次取 p50。TTFB = time_starttransfer。


## 2026-11-03 14:49:42 — Direct

| URL | 成功 | TTFB p50 | 速度 p50 |
|---|---|---|---|
| https://github.com/ | 0/5 | - ms | - KB/s |
| https://raw.githubusercontent.com/octocat/Hello-World/master/README | 5/5 | 715 ms | 0 KB/s |
| https://codeload.github.com/pallets/flask/zip/refs/heads/main | 5/5 | 619 ms | 713 KB/s |
| https://api.github.com/repos/cli/cli | 5/5 | 331 ms | 19 KB/s |

## 2026-11-03 14:50:03 — Gha

| URL | 成功 | TTFB p50 | 速度 p50 |
|---|---|---|---|
| https://github.com/ | 5/5 | 179 ms | 2810 KB/s |
| https://raw.githubusercontent.com/octocat/Hello-World/master/README | 5/5 | 214 ms | 0 KB/s |
| https://codeload.github.com/pallets/flask/zip/refs/heads/main | 5/5 | 333 ms | 1936 KB/s |
| https://api.github.com/repos/cli/cli | 5/5 | 134 ms | 46 KB/s |
