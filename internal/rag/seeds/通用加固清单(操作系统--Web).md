# 通用加固清单（操作系统 + Web）

## 账户与口令
- 修改默认/弱口令：SSH、数据库、Web 后台、工控管理口
- 禁用 root 远程 SSH：PermitRootLogin no；改 SSH 端口、仅密钥登录
- 锁定可疑账户：检查 /etc/passwd、/etc/shadow 异常 uid=0 账户；删除未知账户
- Windows：重命名 Administrator、禁用 Guest、强密码策略

## 服务与端口最小化
- 关闭非必要端口与服务（尤其是 23/telnet、21/ftp 匿名、137-139/445 非必要）
- 用 iptables / firewalld / Windows 防火墙做白名单，仅放行业务端口
- 封禁可疑外连：iptables 限制出站到未知 IP

## 文件与目录
- Web 目录禁止执行：上传目录设 php_flag engine off 或移除执行权限
- 关键目录只读挂载或降权：chmod、chattr +i 关键配置文件
- 定期文件完整性校验：记录重要文件哈希，发现新增/篡改及时处置

## 应用加固
- Web 中间件：IIS/Nginx/Apache 关闭目录遍历、限制上传类型、隐藏版本号
- 数据库：禁止远程 root、关闭危险函数、禁用 local_infile
- PHP：disable_functions 加入 exec/system/passthru/proc_open/popen/eval（按需）
- 删除测试页面、phpinfo、默认后台

## 日志与监测
- 开启并集中保存：auth.log、secure、auditd、Windows Event Log/Sysmon、Web 访问日志
- 部署 IDS/流量捕获（Suricata、Zeek、tcpdump）
- 监控反弹 shell、可疑进程、异常外连

## 加固后必须验证
- 业务可用性优先：加固不能导致服务中断（可能触发额外扣分）
- 加固动作留痕：截图、日志、配置 diff，用于人工评分材料
