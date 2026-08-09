# Web 日志分析手册（Apache / Nginx / Tomcat）

> 面向防御赛与日常应急的日志分析速查：先找"异常请求"，再定位"来源 IP 与入口"，最后还原"攻击链"。日志是溯源报告的第一证据源，比赛期间要持续保存。

## 一、日志文件位置

| 中间件 | 访问日志 | 错误日志 |
|--------|---------|---------|
| Apache | `/var/log/httpd/access_log`（CentOS）/ `/var/log/apache2/access.log`（Ubuntu） | `/var/log/httpd/error_log` 或 `/var/log/apache2/error.log` |
| Nginx | `/var/log/nginx/access.log` | `/var/log/nginx/error.log` |
| Tomcat | `tomcat/logs/localhost_access_log.*.txt` | `tomcat/logs/catalina.out`、`localhost.*.log` |
| PHP-FPM | `/var/log/php-fpm/error.log`（慢日志 `www-slow.log`） | - |

## 二、快速定位可疑请求

```bash
# 找请求体中带危险函数的访问（一句话木马特征）
grep -E 'eval|assert|base64_decode|system|passthru|\$_POST|\$_REQUEST|create_function' /var/log/nginx/access.log

# 找目录穿越 / 文件包含 / 远程包含
grep -E '\.\./|php://|phar://|data://|expect://' /var/log/nginx/access.log

# 找 SQL 注入特征
grep -E 'union|select|information_schema|sleep\(|benchmark|extractvalue|updatexml|0x' /var/log/nginx/access.log

# 找命令注入
grep -E '%3b|;cat|;id|/bin/sh|wget|curl' /var/log/nginx/access.log

# 找上传行为（POST 到可写目录）
grep -E 'POST /(upload|files|images|tmp)/' /var/log/nginx/access.log
```

## 三、按来源 IP 聚合，找攻击源

```bash
# 访问量 Top IP（刷接口/扫描）
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -20

# 404 密集 IP（目录扫描特征）
awk '$9==404{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -rn | head -10

# 该 IP 访问了哪些路径（还原其攻击路径）
grep '^<攻击IP> ' /var/log/nginx/access.log | awk '{print $7}' | sort -u
```

## 四、还原攻击时间线

```bash
# 某时间段内的请求
grep '22/Jul/2026:10:1[0-9]:' /var/log/nginx/access.log

# 攻击前后对比：先看探测（404/参数探测），再看利用（200/302），再看上传（POST 落盘）
# 配合错误日志看利用是否成功
grep -E 'error|denied|malformed|Invalid|No such file' /var/log/nginx/error.log
```

## 五、Tomcat / Java 靶机专项

```bash
# 找 JSP 内存马/WebShell 上传痕迹
grep -E '\.jsp(x)? |\.war ' tomcat/logs/localhost_access_log.*.txt

# 找反序列化/框架漏洞利用（Fastjson、Shiro、Log4j）
grep -Ei 'fastjson|JNID|rmi|ldap|Shiro|rememberMe|\\$\\{jndi|\$\{jndi' tomcat/logs/*

# 找文件包含写 shell 的 POST 落盘
grep -E 'POST /.*(\.jsp|\.jspx|\.war)' tomcat/logs/localhost_access_log.*.txt
```

## 六、日志被篡改/清空的判断

```bash
# 日志文件时间跳变、被 truncate、行数骤减
ls -l /var/log/nginx/access.log*
wc -l /var/log/nginx/access.log

# 空行堆积（常用 `echo "" >>` 洗日志特征）
awk 'NF==0' /var/log/nginx/access.log | wc -l

# 日志轮转被改 / logrotate 被删
cat /etc/logrotate.d/nginx 2>/dev/null
```

## 七、分析要点与报告输出

1. 攻击源 IP、攻击时间窗、利用的漏洞类型、是否成功（配合响应码与后续文件变更判断）三要素必须齐全。
2. 把日志中的原始请求行 `grep` 出来直接粘进 Writeup，比截图更能说明问题。
3. 比赛期间日志别清：被攻破后先 `cp -a /var/log/nginx /root/evidence/` 保全证据，再做处置。
