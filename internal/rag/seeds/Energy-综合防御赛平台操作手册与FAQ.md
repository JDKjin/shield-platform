# 综合防御平台操作手册与 FAQ

> 本手册对应本项目的综合防御平台：主控面板（Panel）+ 靶机 Agent + PHP 软 WAF + 全量检测/加固 + RAG 知识库。平台用 Go 编写，面板与 Agent 均支持 Linux / Windows 全架构。所有命令以项目真实命令为准（面板二进制 `shield-panel`、Agent 二进制 `shield-agent`、面板默认端口 `:8080`）。比赛现场按本手册操作即可快速铺防御、应急与出报告。

## 平台由哪几部分组成

- **主控面板（Panel）**：跑在防守方本机或公网一台机器上，承载 Web 控制台（默认 `:8080`）、Agent 信标接收、指令下发、告警中心、RAG 知识库问答、多靶机聚合监控。所有数据落 SQLite（`panel.db`），单文件无外部数据库依赖。
- **靶机 Agent**：部署到每台靶机，本地执行全量检测、一键加固、软 WAF 部署、防御守护，并通过 WebSocket 主动回连面板上报状态、接收指令。
- **PHP 软 WAF**：部署到靶机 Web 目录的 `waf.php` + `.user.ini`（依赖 PHP-FPM/FastCGI 的 `auto_prepend_file` 机制），自动加载 80+ 条规则做请求拦截。
- **RAG 知识库**：内置 50 份安全手册种子（加固清单、应急手册、CVE 速查、取证溯源、日志分析、赛事规则与计分、Flag 防护等），支持 BM25 中文检索问答。

## 如何启动主控面板

面板无需任何外部依赖，单二进制直接运行。

1. **Linux**：
   ```bash
   ./dist/shield-panel-linux-amd64 -l :8080
   ```
2. **Windows**：双击或命令行运行 `shield-panel-windows-amd64.exe`。
3. **访问**：浏览器打开 `http://<面板IP>:8080`，登录令牌默认 `admin`（建议登录后立即在 `~/.shield-platform/panel.json` 中修改）。
4. **自定义参数**：`-l :9090` 改端口；`-token xxxx` 改令牌；`-debug` 开调试日志；`-c /path/panel.json` 指定配置文件。
5. **数据目录**：默认 `~/.shield-platform/`（含 `panel.json` 配置、`panel.db` 数据库），可用环境变量 `SHIELD_DATA_DIR` 覆盖。

## 如何部署 Agent 到靶机

在面板「设置」页可看到本机 Agent 接入说明与密钥。把对应平台的 Agent 二进制拷贝到靶机后执行：

1. **Linux 靶机**：
   ```bash
   ./shield-agent-linux-amd64 -s "ws://<面板IP>:8080/ws/agent" -k "<面板Agent密钥>" -n "靶机名称" -debug
   ```
2. **Windows 靶机**：
   ```powershell
   .\shield-agent-windows-amd64.exe -s "ws://<面板IP>:8080/ws/agent" -k "<面板Agent密钥>" -n "靶机名称"
   ```
3. **验证**：面板「靶机管理」页出现该靶机并显示 online（心跳间隔默认 3 秒，超过 30 秒未心跳标 offline）。

### 本机交叉编译 Agent

需要在面板机器上对目标平台编译 Agent 时执行：

```bash
# Linux 靶机 (amd64)
GOOS=linux GOARCH=amd64 go build -o shield-agent-linux-amd64 ./cmd/agent
# Windows 靶机
GOOS=windows GOARCH=amd64 go build -o shield-agent.exe ./cmd/agent
```

### Agent 手动配置（可选）

首次运行会自动生成 `~/.shield-platform/agent.json`，可手动编辑后重启：

```json
{
  "server": "ws://<面板IP>:8080/ws/agent",
  "name": "靶机名称",
  "secret": "与面板一致的Agent密钥",
  "interval": 3,
  "web_root": "/var/www/html",
  "auto_harden": false,
  "auto_deploy_waf": false,
  "auto_defense": false
}
```

## 靶机监控页如何看在线状态、指标和事件

1. **在线状态**：「靶机管理」/「实时监测」页显示每台靶机名称、系统、架构、IP、状态；超过 30 秒未心跳即标 offline。
2. **指标**：实时监测页选中靶机可看系统信息、监听端口、进程异常、账号安全等 14+ 项检测结果。
3. **告警中心**：所有检测产生的告警按级别（critical/high/medium/low）分类，可「展开」查看完整详情与原始数据。
4. **事件流**：`/api/events` 记录 Agent 的指令执行与回执，选中靶机可查看事件历史。

## 如何给某台靶机下发检测与加固指令

面板各页面会自动给目标靶机下发指令（指令经 WebSocket 带回复，Agent 执行后立即回传结果）：

1. **实时监测 / 全量检测**：下发 `scan`，逐项执行系统信息、进程、监听、网络后门、账号、登录审计、持久化、WebShell、SUID、SSH、防火墙、敏感文件权限、密码策略、临时文件等检测，产生告警。
2. **一键加固**：面板「一键加固」页列出 25 项加固（SSH 安全加固、高危账号处置、防火墙启用、后门清理、Web 目录加固、危险 PHP 函数禁用、Redis/MySQL 加固、日志滚动等），按需勾选或一键全部执行。
3. **远程执行**：`exec` 直接在靶机执行任意命令（如 `kill` 掉可疑进程）。
4. **WAF 部署**：`deploy_waf` 向靶机 Web 目录部署软 WAF；`disable_waf` 卸载；`get_waf_rules` 同步规则开关。
5. **网络封禁**：`ban_ip` / `unban_ip` 封禁攻击 IP；`list_ports` / `list_conns` 查看监听端口与连接。
6. **Web 备份回滚**：`backup_web` / `rollback_web` 备份与回滚 Web 目录，被篡改时快速恢复。
7. **持续防御**：`start_defense` / `stop_defense` / `defense_now` 启动/停止/立即执行防御守护（Web 目录监控、可疑进程、连接白名单、爆破阈值等）。

## WAF 拦到攻击后怎么看

1. **看拦截计数**：总览页统计卡片看拦截/告警/放行/规则命中数。
2. **看命中规则**：WAF 规则页可看到 80+ 条规则（SQL 注入、命令执行、WebShell、XSS、SSRF、文件包含、上传防护、中间件漏洞、协议攻击、工控安全、扫描器等）。
3. **看原始请求**：WAF 命中日志记录攻击 IP、URL、payload，判断是扫描器还是定向攻击，配合溯源写进报告。
4. **处置**：确认攻击来源 IP → 在面板/靶机 `ban_ip` 封禁；误拦正常业务 → 在规则页关闭对应规则或调为记录模式。

## 怎么用 RAG 知识库问答

面板「RAG 知识库」页基于内置 50 份手册做 BM25 中文检索，直接提问即可：

1. **发起问答**：输入问题（如「靶机被攻破怎么办」「CentOS 加固清单」），返回命中文档、片段与得分。
2. **API 调用**：`POST /api/kb/search` `{"query":"...","top_k":5}` 检索；`POST /api/kb/ask` 做知识问答。
3. **扩展知识**：向 `internal/rag/seeds/` 目录追加 `.md` 文件后重新编译，或通过面板知识库接口导入文档，重启后自动加载。

## 开局 30 分钟怎么用平台铺防御

前 30 分钟按「起面板 → 发 Agent → 全量检测 → 一键加固 → 部署 WAF」推进：

1. **起面板**：本机启动 `shield-panel`，确认 `http://<IP>:8080` 可登录。
2. **发 Agent**：把 Agent 二进制推到各靶机并回连，等待全部上线。
3. **全量检测**：逐台下发 `scan`，先确认无预置后门/恶意账号。
4. **一键加固**：勾选高危项执行加固（SSH、防火墙、账号、Web 目录）。
5. **部署 WAF**：对每台 Web 靶机 `deploy_waf`，curl 冒烟业务 200、注入测试被拦。
6. **建基线**：留存各靶机检测空态截图与告警基线，后续异常增量一目了然。

## 被攻破后怎么用平台应急

按「断入口 → 清驻留 → 加固 → 抢题 → 留证据」五步，全部可在面板完成：

1. **断入口**：`ban_ip` 封攻击 IP，`exec`/`kill` 清掉可疑 shell/挖矿进程。
2. **清驻留**：下发 `scan` 找 WebShell/计划任务/启动项后门，确认后 `backup_web` + `rollback_web` 恢复 Web 目录。
3. **加固**：执行「一键加固」锁空口令、清可疑计划任务、收紧目录权限、启用防火墙。
4. **抢答题**：确认题目开放后立即作答，同时保留面板告警/拦截日志作证据。
5. **写证据**：从告警中心 + 事件流 + WAF 命中记录导出攻击时间线，填入 Writeup 模板。

## 结束前怎么写报告

报告直接复用平台天然形成的证据链：

1. **时间线**：从告警中心与事件流导出「攻击时间—IP—手法—处置」表。
2. **证据与处置**：总览拦截统计、告警详情（含原始数据）、下发指令（scan/harden/deploy_waf/ban_ip）与执行回执各截 1-2 张。
3. **结论**：按「监测-研判-加固」三段组织，量化说明检测项、拦截数、加固项，提交前自查一遍。

## Agent 回连失败怎么排查

按「网络 → 密钥 → 配置 → 日志」四层排查：

1. **网络**：靶机到面板是否可达：`curl -v http://<面板IP>:8080/api/status` 或 `ping <面板IP>`；面板所在机器防火墙需放行 8080 入站。
2. **密钥**：确认 Agent `-k` 参数与面板 `~/.shield-platform/panel.json` 的 `agent_secret` 完全一致。
3. **配置**：检查靶机是否有 HTTP 代理劫持（`env | grep -i proxy`）；Agent 启动参数是否正确。
4. **日志**：靶机 Agent 加 `-debug` 看回连日志；面板加 `-debug` 看信标接收日志，按报错（401/超时/连接拒绝）对症处理。

## 故障排查：面板端口被占 / 登录不上 / 指令 pending

1. **端口被占**：`ss -tlnp | grep 8080`（Windows 用 `netstat -ano | findstr 8080`）找占用进程，换端口 `-l :9090` 启动。
2. **面板登录不上**：确认 `shield-panel` 进程在跑；令牌为 `~/.shield-platform/panel.json` 的 `token`；忘了就改配置后重启。
3. **指令一直 pending**：说明该靶机 Agent 离线或没回执——先看靶机管理页是否 online；在线仍 pending 则看 Agent 日志，用 `refresh` 指令验证通道。

## FAQ

1. **靶机失联怎么办**：先 ping/SSH 靶机确认网络，再确认 Agent 进程在（`ps -ef | grep shield-agent`），进程在则重启 Agent 回连。
2. **Agent 一直显示 offline**：超过 30 秒未心跳即 offline；查面板可达性与密钥一致性，改完重启 Agent。
3. **指令 pending 不执行**：Agent 必须在线才会拉取指令；执行失败看 Agent 日志与事件回执，`kill` 类指令权限不足时用 root/管理员启动 Agent。
4. **面板默认令牌是啥**：`admin`，在 `~/.shield-platform/panel.json` 的 `token` 修改，上线后必须改。
5. **WAF 依赖什么**：PHP-FPM/FastCGI 模式的 `.user.ini` `auto_prepend_file` 机制，纯静态/无 PHP 的靶机不适用。
6. **WAF 误拦正常业务**：在 WAF 规则页关闭对应规则或调为记录模式 → 加白名单 → 业务恢复后逐条收紧。
7. **怎么把规则同步到所有靶机**：WAF 规则页的规则变更后，对目标靶机重新 `deploy_waf` 即重新生成包含最新规则的 waf.php。
8. **如何停掉某台靶机 Agent**：面板「靶机管理」移除记录，靶机端 `kill` Agent 进程即可。
9. **Agent 重启后 ID 会变吗**：不会，ID 持久化在 `agent.json`，重启后保持不变，监控记录连续。
10. **RAG 检索不到答案**：确认问题含手册关键词（如「加固」「应急」）；语料在 `internal/rag/seeds/` 重新编译后自动加载。
11. **靶机被攻破后平台先做哪几步**：先 `ban_ip` 断入口 → `scan` 找后门 → 一键加固 → `rollback_web` 恢复 Web → 抢答题权限。
12. **比赛结束前导出什么**：拦截统计截图、告警详情（含原始数据）、事件流、指令回执，全部按时间线导出进 Writeup。
