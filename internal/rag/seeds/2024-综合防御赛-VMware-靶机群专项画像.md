# 2024 综合防御赛 VMware 靶机群专项画像

> 本手册针对 2024 能源综合防御赛 VMware 靶机群（host-only 网络 192.168.253.0/24）编写，共 5 台靶机。每台先看「总览表」，再对照「单机画像」的暴露面与优先加固项执行；各小节自包含，可直接按命令操作。

## 靶机群总览

| 靶机 | 角色 | IP | 开放服务/端口 | 攻击面优先级 |
|---|---|---|---|---|
| CentOS7_Linux | 办公机 | 192.168.253.128 | SSH 22 | 高（弱口令/爆破） |
| CentOS7_Mysql | 数据存储 | 192.168.253.129 | SSH 22 + MySQL 3306 | 高（3306 暴露） |
| Ubuntu_20.04 | 医药管理系统 | 192.168.253.130 | SSH 22 + 应用 8080 | 极高（Web 漏洞） |
| Win10-Pro_Sec | 办公端点 | 192.168.253.131 | RDP 3389 + WinRM 5985 | 中（永恒之蓝 445） |
| Windows_Server_2016 | Web 应用 | 192.168.253.132 | HTTP 80 + RDP 3389 + WinRM | 高（Web 应用） |

网段特征：host-only 纯内网，攻击入口通常为「Web 应用 → 内网横向」。统一基线：所有 SSH 允许密钥或强口令、关闭无关端口、每日/开赛即做系统快照。

## CentOS7_Linux（办公机 192.168.253.128）

角色：办公文件/跳板机，SSH 是唯一暴露面，最可能被暴力破解拿到口令后横向到数据库与 Web 机。优先加固：改 SSH 端口或限制来源（/etc/ssh/sshd_config 设 `PermitRootLogin no`、`MaxAuthTries 3`、`PasswordAuthentication no`）、开启 fail2ban sshd jail、`chage` 强制改密弱口令账号。监控重点：`grep Failed /var/log/secure` 爆破频率、`last` 登录来源、`ss -tnp` 出站外连（被当跳板先兆）。加固命令参考 07-Linux加固清单-CentOS7与Ubuntu.md。

## CentOS7_Mysql（数据存储 192.168.253.129）

角色：业务数据库，SSH 22 + MySQL 3306 双暴露。最可能被攻击：3306 端口扫描弱口令（root 空口令/常见口令）、SSH 爆破、Web 机被攻后拿数据库凭据。优先加固：`mysql_secure_installation` 锁 root、改 root 与业务库口令、`bind-address=127.0.0.1` 或防火墙仅允许应用机 IP 访问 3306（`iptables -I INPUT -p tcp --dport 3306 -s 192.168.253.130 -j ACCEPT`）。监控重点：MySQL 慢查询里异常 SQL（union/sleep）、`mysqlbinlog` 是否被回放删除、3306 非白名单来源连接。备份必须做：`mysqldump -u root -p --all-databases > /backup/all_$(date +%F).sql`，详见「MySQL 专项」。

## Ubuntu_20.04（医药管理系统 192.168.253.130）

角色：医药管理系统（Web），SSH 22 + 应用 8080（Tomcat）。整组靶标中最可能被首攻的目标，Web 层漏洞（SQLi/未授权/弱口令）是主入口。优先加固：给 Tomcat 改弱口令、禁用 manager 远程部署或设强口令、WAF 前置部署（8088→8080，见「医药管理系统专项」）、关闭不必要管理路径。监控重点：`/var/log/tomcat*/` 访问日志异常请求（`.jsp`、`/manager`、`/login` 爆破）、webapps 目录新增文件、`/var/log/auth.log` SSH 爆破。加固命令参考 07 清单与 09-数据库与中间件加固.md。

## Win10-Pro_Sec（办公端点 192.168.253.131）

角色：办公端点，RDP 3389 + WinRM 5985。最可能被攻击：RDP 弱口令爆破、445 永恒之蓝（MS17-010）类漏洞横向、WinRM 弱口令。优先加固：改 Administrator 口令并禁用 Guest、`Set-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -Enabled False` 关 445、开启账户锁定阈值（组策略→安全选项→账户锁定阈值 5 次）、RDP 改端口或用 NLA（网络级别身份验证）。监控重点：事件 ID 4625（爆破）/ 4624（登录）/ 4624 登录类型 3（网络登录横向）、`netstat -ano` 异常连接。详见 08-Windows加固清单-Server2016与Win10.md。

## Windows_Server_2016（Web应用 192.168.253.132）

角色：Web 应用服务器，HTTP 80 + RDP 3389 + WinRM。最可能被攻击：Web 应用漏洞（注入/未授权/上传）、IIS 短文件名/解析绕过、RDP 爆破。优先加固：IIS 应用池降权、关闭目录浏览、补丁更新、IIS 请求过滤限制上传类型、RDP/WinRM 仅内网白名单访问。监控重点：IIS 日志（%SystemDrive%\inetpub\logs\LogFiles）异常请求、web 目录新增可执行文件、事件 4625/4624、3389 连接来源。WAF 前置同样适用（见「Windows Web 应用专项」）。

## 医药管理系统专项（Ubuntu + Tomcat）

登录页 `/login` 与 Tomcat manager 是两大攻击面，WAF 前置是核心防线。

1. **登录页加固**：改默认账号口令、加验证码/登录失败锁定（改应用配置）、确认登录接口对 `'` `union` `sleep` 等输入有过滤或由 WAF 拦截。
2. **Tomcat manager 防护**：`conf/tomcat-users.xml` 删弱口令用户或改强口令，删除 manager-gui 角色；`webapps/manager` 目录限制本机访问：`<Valve className="org.apache.catalina.valves.RemoteAddrValve" allow="127.0.0.1,192.168.253.*"/>`。
3. **WAF 前置部署（8088→8080）**：WAF 监听 8088 反向代理到 Tomcat 8080，攻击流量只走 8088；外部 8080 用防火墙封禁：`iptables -I INPUT -p tcp --dport 8080 ! -s 127.0.0.1 -j DROP`。
4. **业务可用性验证**：`curl -i http://127.0.0.1:8088/login` 应 200 且渲染正常，`curl -I http://127.0.0.1:8088/manager/html` 应被 WAF 拦截或 403，证明 WAF 生效且业务不误杀。
5. **常见漏洞自查**：SQLi（登录参数加 `'` 触发报错）、未授权接口（/admin、/api）、弱口令（admin/admin 等），发现即修复或由 WAF 规则覆盖。

## Windows Web 应用专项（Server 2016）

IIS/Web 服务加固 + 80 端口防护 + RDP/WinRM 入口防护。

1. **IIS 加固**：应用池标识改低权账号、关闭目录浏览（请求筛选→目录浏览→禁用）、禁止上传可执行类型（请求筛选→文件扩展名→添加拒绝 .aspx/.php/.exe）、启用 HTTP 错误页防信息泄露。
2. **80 端口防护**：若前置 WAF（8088→80），用 Windows 防火墙限制 80 仅允许 WAF 机：`New-NetFirewallRule -Direction Inbound -LocalPort 80 -Action Block -RemoteAddress Any` 后加白名单规则放行 WAF IP；定期备份 `C:\inetpub\wwwroot`。
3. **RDP/WinRM 入口防护**：RDP 3389 限制来源 IP（防火墙远程地址仅内网运维网段）、启用 NLA；WinRM 5985 确认 `Set-Item WSMan:\localhost\Service\Auth\Basic $false` 并限制来源。
4. **补丁与查杀**：装 MS17-010 类补丁、关闭 SMBv1（`Set-SmbServerConfiguration -EnableSMB1Protocol $false`）、全盘查杀临时文件目录 `C:\Windows\Temp`。

## MySQL 专项

3306 暴露是数据靶机的最大风险，root 口令与备份恢复是防守关键。

1. **3306 暴露风险收敛**：`ss -tlnp | grep 3306` 确认监听；my.cnf 设 `bind-address=127.0.0.1` 或防火墙仅放行应用机：`iptables -I INPUT -p tcp --dport 3306 -s 192.168.253.130 -j ACCEPT`、其余 `-j DROP`。
2. **root 口令管理**：`mysqladmin -u root password '<新强口令>'` 或 `ALTER USER 'root'@'localhost' IDENTIFIED BY '<新强口令>'`；删除空口令用户 `DELETE FROM mysql.user WHERE authentication_string=''`，清理多余账号。
3. **数据备份**：全量 `mysqldump -u root -p --all-databases --single-transaction > /backup/all_$(date +%F_%H).sql`，备份文件立即 `chmod 600` 并同步到其它机器，避免与源同机被勒索一锅端。
4. **数据恢复演练**：`mysql -u root -p < /backup/all_xxx.sql`；验证恢复后业务能连（`mysql -u app -p -h 127.0.0.1 -e 'select 1'`）。
5. **异常监控**：`grep -iE 'drop|truncate|union|sleep' $(ls -t /var/log/mysql* | head -1)` 查异常 SQL，检查是否被回放删除数据。

## 办公机专项（CentOS7 / Win10）

办公机共性是弱口令与 445 类 SMB 漏洞，重点防爆破与横向。

1. **弱口令治理**：CentOS7 用 `awk -F: '$2==""{print $1}' /etc/shadow` 查空口令并 `passwd` 强制改密；Win10 改 Administrator 口令、禁用 Guest，开启 4625 审计。
2. **永恒之蓝类漏洞（445）**：CentOS7 `iptables -I INPUT -p tcp --dport 445 -j DROP`（SMB 非必要即封）；Win10 `Set-NetFirewallRule -DisplayGroup 'File and Printer Sharing' -Enabled False`，补 MS17-010 补丁。
3. **远程桌面防护**：CentOS7 关桌面服务或仅本机；Win10 RDP 改端口（注册表 PortNumber）、启用 NLA、限制来源 IP、设置账户锁定阈值。
4. **横向入口排查**：`arp -a` 观察异常 MAC、`netstat -ano` 看 445/3389/5985 连接、CentOS7 `ss -tnp` 看兄弟机 IP 的连接，发现即封并改全部口令。

## 开局 30 分钟防御节奏

前 30 分钟决定整场防守下限，按「连→快照→改密→关端口→上 WAF→盯监控」推进。

- **0-5 分钟**：5 台靶机全部连上（SSH/RDP），各自 `ip a` 确认 IP，给每台拍 VMware 快照（回滚保底），记录当前口令与基线文件清单。
- **6-15 分钟**：逐台改 root/Administrator/业务弱口令；关掉所有非业务端口（Linux 逐台 `firewall-cmd --add-port` 只放行所需；Windows 逐台关 445/139）。
- **16-25 分钟**：给 130 医药系统与 132 Web 应用前置 WAF（8088→8080/80），130 锁 Tomcat manager，129 MySQL `bind-address` 收紧并做 mysqldump 全备。
- **26-30 分钟**：检查 fail2ban/审计开启，`ss -tlnp` 复核各机开放端口，清点基线（`find /var/www -mmin` 快照、`crontab -l` 留存），确认 WAF 面板可达、业务 curl 冒烟通过。
