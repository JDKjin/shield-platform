# Flag 与敏感文件防护手册

> 能源防御赛 flag 藏在工控数据库、Web 目录、管理后台、环境变量等多处，攻击方主要目标是拿 flag。防守要点：藏好、防读、防泄露、被抄走也能溯源。

## 一、flag 常见藏匿位置盘点

| 位置 | 说明 | 防护重点 |
|------|------|---------|
| Web 目录文件 | `flag.txt` / `flag.php` / 后台数据文件 | 目录权限、访问控制 |
| 数据库 | 表字段、配置表 | 数据库加固、防注入读库 |
| 配置文件 | `.env`、`config.php`、`application.yml` | 防文件包含/目录遍历读取 |
| 环境变量 / 启动脚本 | `export FLAG=xxx` | 防 `/proc/*/environ`、命令执行泄露 |
| 工控/后台接口 | 管理后台返回数据 | 防未授权访问、防弱口令进后台 |

## 二、文件级防护

```bash
# 1. 找本机 flag 相关文件
find / -type f \( -name '*flag*' -o -name 'flag.*' \) 2>/dev/null | grep -vE '/proc|/sys'
grep -rlE 'flag\{|^flag|FLAG=' /var/www /opt /root /home 2>/dev/null

# 2. 收紧权限：Web 目录内 flag 只读、不可被执行、不随目录列出
chmod 444 /var/www/html/flag.txt
# 目录禁止列目录（Nginx）
echo 'autoindex off;' >> /etc/nginx/nginx.conf
# 禁止直接访问 flag 文件（Apache .htaccess）
echo 'RewriteRule flag - [F,L]' >> /var/www/html/.htaccess

# 3. 排除在备份之外：备份时排除 flag 目录，防止备份文件被打包偷走
tar czf /root/backup.tar.gz --exclude='*/flag*' /var/www/html
```

## 三、Web 层防护（防注入读库、防文件读取）

- **软 WAF** 覆盖文件读取（`../`、`file://`、`php://filter`）与 SQL 注入规则，block_mode 打开。
- **危险函数禁用**：`disable_functions = system,exec,passthru,shell_exec,popen,proc_open` + `open_basedir` 限制读取范围到业务目录。
- **上传目录禁执行**：上传目录放 `uploads/` 且关 PHP 解析，`.user.ini` 或 Nginx `location` 规则排除。
- **数据库只读账号**：应用连接数据库用最小权限账号，注入也不至于读 flag 表。

## 四、反代 WAF 的响应 Flag 保护（平台能力）

对存 flag 的 Web 靶机部署**反向代理 WAF** 并开启 `flag_protect`：反代监听前置端口，上游指向原 Web 服务；命中响应中疑似 flag 的明文内容时，用假 flag 替换后再返回给请求方。

- 对外暴露端口改成反代监听端口，原 Web 端口仅允许本机访问。
- 效果：攻击方即使注入成功读库，从响应里拿到的也是被替换的假 flag。
- 配合告警：反代命中会生成 `revproxy_waf` 告警，记录攻击 IP 与规则，直接用于溯源报告。

## 五、工控/后台敏感接口防护

1. 改默认口令（admin/admin、admin/123456 在 SCADA/HMI 后台高发）。
2. 管理后台绑定本机或限制来源 IP 访问。
3. 对读 flag 的关键接口（查询、导出、报表）增加鉴权与频率限制。
4. 关键操作日志审计（谁在何时读到了 flag），配合事件日志溯源。

## 六、被抄 flag 后的溯源

1. 从数据库/应用日志找读 flag 的查询来源 IP 与时间点。
2. 与 WAF/反代拦截记录、SSH 登录记录交叉比对，锁定攻击链。
3. 封来源 IP、补上被利用的入口（注入点/弱口令/后台未授权），写入事件报告。
