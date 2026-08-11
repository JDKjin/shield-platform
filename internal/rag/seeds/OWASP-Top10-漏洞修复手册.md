# OWASP Top 10 漏洞修复手册

> 从防守方视角梳理 OWASP Top 10 的高频漏洞：攻击原理、检测点、修复方案。比赛靶机与日常业务代码排查通用，修复后配合 WAF 双保险。

## 一、SQL 注入

- **原理**：未过滤用户输入拼入 SQL 查询。
- **检测**：`grep -nE 'SELECT.*\$_|WHERE.*\$_|INSERT.*\$_' /var/www/html/`。
- **修复**：参数化查询（PDO prepare）、输入校验白名单、最小数据库权限、WAF 拦截注入特征（union/information_schema/sleep）。

## 二、XSS（存储/反射/DOM）

- **原理**：用户输入未转义直接输出到页面。
- **检测**：`grep -nE 'echo.*\$_|print.*\$_' /var/www/html/` 审查输出点。
- **修复**：输出转义（htmlspecialchars/模板引擎自动转义）、CSP 头、输入长度与字符白名单、HttpOnly Cookie。

## 三、文件上传漏洞

- **原理**：上传校验不严，恶意文件落入可执行目录。
- **检测**：审查上传接口，检查 `uploads/` 目录是否可执行脚本。
- **修复**：后缀白名单+内容（MIME）校验、随机重命名、上传目录禁执行、`.htaccess`/Nginx 规则拦截脚本后缀、限制文件大小。

## 四、命令注入 / RCE

- **原理**：用户输入拼入 shell 命令（system/exec/passthru）。
- **检测**：`grep -nE 'system\(|exec\(|shell_exec|passthru|popen\(' /var/www/html/`。
- **修复**：禁用危险函数（disable_functions）、命令参数白名单、输入校验、WAF 拦截 `;|&|$()|反引号`。

## 五、文件包含（LFI/RFI）

- **原理**：include 用户可控路径。
- **检测**：`grep -nE 'include.*\$_|require.*\$_' /var/www/html/`。
- **修复**：路径白名单、过滤 `../`、禁用 `allow_url_include`、WAF 拦截 `php://`/`../`/`expect://`。

## 六、SSRF

- **原理**：服务端请求用户可控 URL。
- **检测**：审查 URL 下载/代理类接口。
- **修复**：URL 白名单（协议+域名）、禁用内网网段、`open_basedir`/出网限制、WAF 拦截内网地址特征（127.0.0.1/169.254.169.254）。

## 七、反序列化漏洞

- **原理**：反序列化不可信数据，触发 gadget 链 RCE。
- **检测**：版本比对（Fastjson/Shiro/Log4j 等 CVE）、`grep -nE 'unserialize\(|readObject|json.parse' /var/www/html/`。
- **修复**：升级修复版本、禁用危险类、序列化白名单、WAF 拦截 `JNDI|rmi|ldap|com.sun.*` 特征。

## 八、弱口令 / 默认口令

- **原理**：默认口令或弱口令直接进后台。
- **检测**：见「弱口令与账号安全排查手册」。
- **修复**：强口令策略、强制改密、登录失败锁定、WAF/限速。

## 九、敏感信息泄露

- **原理**：源码/配置/日志暴露口令、密钥、内网信息。
- **检测**：`grep -rniE 'password|secret|api.?key|token' /var/www/html/ /etc/`。
- **修复**：配置外置并加密、禁止返回堆栈/版本信息、禁止 `.git/.env` 目录访问、日志脱敏。

## 十、越权访问 / 不安全的对象引用

- **原理**：仅前端隐藏，后端未校验权限，可遍历 ID 访问他人数据。
- **检测**：审查 `id=`/`uid=` 参数接口的后端鉴权。
- **修复**：后端强制权限校验、对象属主校验、接口频率限制。

## 通用修复落地

1. 代码层修复为主（参数化/转义/白名单），WAF 兜底。
2. 修复后逐项复测：注入/上传/XSS 用代表性 payload 打一遍，确认已拦。
3. 配合「中间件 CVE 速查手册」升级组件版本，消除已知漏洞。
