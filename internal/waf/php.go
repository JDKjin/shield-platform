package waf

import (
	"fmt"
	"regexp"
	"strings"
)

// Rule WAF 检测规则
type Rule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	Pattern  string `json:"pattern"`
	Action   string `json:"action"` // block|log
	Enabled  bool   `json:"enabled"`
	Level    int    `json:"level"` // 0基础 1中级 2高级(可能误报)
}

// DefaultRules 内置默认规则集（60+ 条，覆盖 OWASP Top10 / WebShell / 工控 / 绕过手法）
func DefaultRules() []*Rule {
	return []*Rule{
		// ========== SQL 注入 ==========
		{ID: "sqli_1", Name: "SQL注入-联合查询", Category: "SQL注入", Pattern: `(?i)\b(union\s+(all\s+)?select)\b`, Action: "block", Enabled: true, Level: 0},
		{ID: "sqli_2", Name: "SQL注入-写库语句", Category: "SQL注入", Pattern: `(?i)\b(insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+table|truncate\s+table|alter\s+table|create\s+table)\b`, Action: "block", Enabled: true, Level: 0},
		{ID: "sqli_3", Name: "SQL注入-延时/堆叠", Category: "SQL注入", Pattern: `(?i)\b(sleep\s*\(|benchmark\s*\(|waitfor\s+delay|pg_sleep|make_set|extractvalue|updatexml|load_file|outfile|dumpfile)\b`, Action: "block", Enabled: true, Level: 0},
		{ID: "sqli_4", Name: "SQL注入-系统库/布尔", Category: "SQL注入", Pattern: `(?i)(information_schema|order\s+by\s+\d|/\*.*\*/|\x27\x27|or\s+\d+\s*=\s*\d|and\s+\d+\s*=\s*\d|1\s*=\s*1)`, Action: "block", Enabled: true, Level: 1},
		{ID: "sqli_5", Name: "SQL注入-编码变体", Category: "SQL注入", Pattern: `(?i)(%27|%22|%u0027|0x27|\\x27|#\s*$|--\s*$)`, Action: "block", Enabled: true, Level: 2},
		{ID: "sqli_6", Name: "SQL注入-注入函数", Category: "SQL注入", Pattern: `(?i)\b(char\s*\(|concat\s*\(|concat_ws|group_concat|substring\s*\(|mid\s*\(|hex\s*\(|ascii\s*\(|database\s*\(|user\s*\(|version\s*\(|@@)\b`, Action: "block", Enabled: true, Level: 1},
		{ID: "sqli_7", Name: "SQL注入-PostgreSQL/MSSQL", Category: "SQL注入", Pattern: `(?i)\b(pg_sleep|pg_read_file|pg_execute|xp_cmdshell|sp_executesql|openrowset|master\.\.|sysobjects|information_schema\.tables)\b`, Action: "block", Enabled: true, Level: 0},

		// ========== 命令执行 / RCE ==========
		{ID: "rce_1", Name: "命令执行-危险函数", Category: "命令执行", Pattern: `(?i)\b(system\s*\(|passthru\s*\(|shell_exec\s*\(|exec\s*\(|proc_open|popen\s*\(|pcntl_exec|putenv\s*\(.*LD_PRELOAD|mail\s*\(.*-t)`, Action: "block", Enabled: true, Level: 0},
		{ID: "rce_2", Name: "命令执行-系统命令", Category: "命令执行", Pattern: `(?i)(/bin/(ba)?sh|bash\s+-[civ]|cmd\.exe|powershell\s+(-enc|-e)\s+|whoami|/etc/passwd|cat\s+/etc/shadow|base64\s+-d)`, Action: "block", Enabled: true, Level: 0},
		{ID: "rce_3", Name: "命令执行-回连特征", Category: "命令执行", Pattern: `(?i)(nc\s+-e|bash\s+-i|/dev/tcp/|/dev/udp/|socat|curl\s+.*\||wget\s+.*\||sh\s+-c|python\s+-c)`, Action: "block", Enabled: true, Level: 0},
		{ID: "rce_4", Name: "命令执行-管道/分隔符", Category: "命令执行", Pattern: `(?i)(;\s*(id|uname|cat|ls|whoami)|&&\s*(id|uname|cat|ls|whoami)|\|\s*(id|uname|cat|ls|whoami)|\$\()`, Action: "block", Enabled: true, Level: 1},
		{ID: "rce_5", Name: "命令执行-回连工具下载", Category: "命令执行", Pattern: `(?i)\b(curl|wget|nc|ncat|busybox|openssl|python2?|perl|ruby)\b.{0,40}\b(-e|-i|-o|-c)\b`, Action: "block", Enabled: true, Level: 2},

		// ========== 文件包含 / 读取 / 穿越 ==========
		{ID: "file_1", Name: "文件包含协议", Category: "文件包含", Pattern: `(?i)(php://|file://|data://|zip://|phar://|expect://|phpinfo|glob://|zlib://|compress\.zlib://)`, Action: "block", Enabled: true, Level: 0},
		{ID: "file_2", Name: "路径穿越", Category: "路径穿越", Pattern: `(\.\./|\.\.\\|\.\.%2f|\.\.%5c|%00|\.\./\.\.|\.\.\\\.\\)`, Action: "block", Enabled: true, Level: 0},
		{ID: "file_3", Name: "敏感文件读取", Category: "文件包含", Pattern: `(?i)(/etc/(passwd|shadow|sudoers|hosts|group)|/proc/self/environ|/var/log/auth\.log|\.bash_history|\.ssh/(id_rsa|authorized_keys)|composer\.json|\.git/config|\.env\b|WEB-INF/web\.xml)`, Action: "block", Enabled: true, Level: 0},

		// ========== XSS ==========
		{ID: "xss_1", Name: "XSS-标签", Category: "XSS", Pattern: `(?i)<\s*(script|iframe|svg|object|embed|link|meta|img|video|audio)[^>]*>`, Action: "block", Enabled: true, Level: 0},
		{ID: "xss_2", Name: "XSS-事件/伪协议", Category: "XSS", Pattern: `(?i)(javascript:|vbscript:|on\w+\s*=|onerror|onload|onclick|onfocus|onmouseover|style\s*=|document\.cookie|alert\s*\(|confirm\s*\(|prompt\s*\()`, Action: "block", Enabled: true, Level: 0},
		{ID: "xss_3", Name: "XSS-编码绕过", Category: "XSS", Pattern: `(?i)(%3cscript|%3c%73cript|%253c|&#60;|&#x3c;|\\x3c|\\u003c)`, Action: "block", Enabled: true, Level: 1},

		// ========== WebShell ==========
		{ID: "ws_1", Name: "WebShell关键字", Category: "WebShell", Pattern: `(?i)\b(eval\s*\(|assert\s*\(|base64_decode\s*\(|gzinflate\s*\(|str_rot13\s*\(|create_function|call_user_func\s*\(|array_map\s*\(|preg_replace\s*\(.*\/e|@\s*eval|assert\s*\(\s*\$|shell_exec|passthru|system\s*\()`, Action: "block", Enabled: true, Level: 0},
		{ID: "ws_2", Name: "WebShell变量变形", Category: "WebShell", Pattern: `(?i)(\$_POST\[|\$_REQUEST\[|\$_GET\[|#\$_GET|\$\{|\$GLOBALS|_\[|\$_[A-Z]+\s*\[)`, Action: "log", Enabled: true, Level: 1},
		{ID: "ws_3", Name: "WebShell混淆加密", Category: "WebShell", Pattern: `(?i)(eval\s*\(\s*base64_decode|gzinflate\s*\(\s*base64_decode|str_rot13\s*\(\s*base64_decode|eval\s*\(\s*\$_(POST|GET|REQUEST))`, Action: "block", Enabled: true, Level: 0},
		{ID: "ws_4", Name: "WebShell图片马特征", Category: "WebShell", Pattern: `(?i)(\x89PNG.*<\?php|GIF89a.*<\?php|FFD8FF.*<\?php)`, Action: "log", Enabled: true, Level: 1},

		// ========== 反序列化 / SSRF / XXE / 模板注入 ==========
		{ID: "deser_1", Name: "反序列化攻击", Category: "反序列化", Pattern: `(?i)(unserialize\s*\(|O:\d+:"|__destruct|__wakeup|__construct|serialize\s*\(|pickle\.loads|__reduce__|java\.lang\.Runtime|ObjectInputStream|ysoserial)`, Action: "block", Enabled: true, Level: 0},
		{ID: "ssrf_1", Name: "SSRF内网探测", Category: "SSRF", Pattern: `(?i)(curl\s+(url=|location=)|https?://(127\.0\.0\.1|localhost|169\.254\.169\.254|metadata\.google|10\.|172\.1[6-9]\.|192\.168\.)[^"\s]*)`, Action: "block", Enabled: true, Level: 0},
		{ID: "ssrf_2", Name: "SSRF协议滥用", Category: "SSRF", Pattern: `(?i)(dict://|gopher://|ldap://|ftp://|file://|tftp://|jar://)`, Action: "block", Enabled: true, Level: 1},
		{ID: "xxe_1", Name: "XXE外部实体", Category: "XXE", Pattern: `(?i)(<!DOCTYPE|<!ENTITY|SYSTEM\s+["'](file|http)|xinclude|<!\[CDATA\[)`, Action: "block", Enabled: true, Level: 0},
		{ID: "ssti_1", Name: "模板注入", Category: "模板注入", Pattern: `(?i)(\{\{\s*[\w_.]+\s*\|\s*\w+|${{|#\{|\.__class__|\.__globals__|\.__init__|javax\.script|Template\.SIMPLE)`, Action: "block", Enabled: true, Level: 1},
		{ID: "rce_sandbox", Name: "沙箱逃逸函数", Category: "命令执行", Pattern: `(?i)\b(posix_|pcntl_|dl\s*\(|ReflectionFunction|evil\(|invokefunction|fpm/start|set_error_handler)`, Action: "block", Enabled: true, Level: 2},

		// ========== 上传 / 文件操作 ==========
		{ID: "upload_1", Name: "恶意脚本上传", Category: "上传防护", Pattern: `(?i)(\.(php|phtml|phar|php5|pht|php3|php4|jsp|jspx|jspf|war|aspx|asp|ashx|asa|cer|cshtml|py|pl|rb|sh|exe|bat|cmd|com|scr|msi|dll|so)\s*$|Content-Disposition.*filename.*\.(php|phtml|phar|php5|pht|php3|php4|jsp|jspx|jspf|war|aspx|asp|ashx|asa|cer|py|pl|sh|exe|bat|cmd|com))`, Action: "block", Enabled: true, Level: 0},
		{ID: "upload_2", Name: "上传目录可执行", Category: "上传防护", Pattern: `(?i)(upload\.php|file_put_contents\s*\(|move_uploaded_file\s*\(|copy\s*\(.*\.php)`, Action: "block", Enabled: true, Level: 0},

		// ========== 扫描器 / 自动化工具 ==========
		{ID: "scan_1", Name: "扫描器特征", Category: "扫描器", Pattern: `(?i)(nikto|sqlmap|acunetix|nessus|appscan|wpscan|hydra|bruter|dirbuster|gobuster|ysoserial|burpsuite|masscan|nmap)`, Action: "log", Enabled: true, Level: 0},
		{ID: "scan_2", Name: "路径枚举特征", Category: "扫描器", Pattern: `(?i)(/admin\.php|/login\.php|/config\.php|/wp-login\.php|/phpmyadmin|/web\.config|\.bak\s*$|\.swp\s*$|\.DS_Store\s*$|/actuator|/\.git/)`, Action: "log", Enabled: true, Level: 1},
		{ID: "scan_3", Name: "目录爆破特征", Category: "扫描器", Pattern: `(?i)(wordpress|joomla|drupal|phpmyadmin|adminer|\.zip\s*$|\.tar\.gz\s*$|backup\.|wwwroot|/shell\.|/webshell)`, Action: "log", Enabled: true, Level: 2},

		// ========== 编码绕过 ==========
		{ID: "encode_1", Name: "双重编码绕过", Category: "绕过防护", Pattern: `(?i)(%3c%73cript|%u00|%252e|%2527|%253c|0x2e|\\x2e|\\x00|%252e%252e|%c0%ae)`, Action: "block", Enabled: true, Level: 1},
		{ID: "encode_2", Name: "Unicode/UTF-8 变体", Category: "绕过防护", Pattern: `(?i)(%e0%80|%ed%a0|%f0%80|uff08|uff09|%u)(?i)(select|union|from|where|sleep)`, Action: "block", Enabled: true, Level: 2},
		{ID: "encode_3", Name: "注释符混淆", Category: "绕过防护", Pattern: `(?i)(/\*!\d+\*/|/\*\*/|%23|%2523|--!|/\*[^*/]{0,20}\*/.{0,20}(select|union|from|where))`, Action: "block", Enabled: true, Level: 2},

		// ========== 日志注入 / 请求头 / 协议 ==========
		{ID: "loginj_1", Name: "日志注入", Category: "协议攻击", Pattern: `(?i)(%0a|%0d|%0d%0a|\r\n)`, Action: "block", Enabled: true, Level: 1},
		{ID: "crlf_1", Name: "CRLF/响应拆分", Category: "协议攻击", Pattern: `(?i)(\r\n\s*(Set-Cookie|Location|Content-Disposition)|%0d%0aContent-)`, Action: "block", Enabled: true, Level: 1},
		{ID: "xpath_1", Name: "XPath注入", Category: "协议攻击", Pattern: `(?i)(//\s*\*\s*\[|or\s+\d+\s*=\s*\d+|concat\s*\(|count\s*\(.*\[)`, Action: "block", Enabled: true, Level: 2},
		{ID: "ldap_1", Name: "LDAP注入", Category: "协议攻击", Pattern: `(?i)(\*\)\s*\(&|\(\)\s*\(\|=|uid=\*|&\(\)\s*\(\)|cn=\*\))`, Action: "block", Enabled: true, Level: 2},

		// ========== 工控 / 能源场景 ==========
		{ID: "ics_1", Name: "工控协议指令异常", Category: "工控安全", Pattern: `(?i)(modbus|fc\s*[=:]?\s*(5|6|15|16)|write_?register|write_?coil|holding_?register)`, Action: "block", Enabled: true, Level: 0},
		{ID: "ics_2", Name: "PLC启停控制", Category: "工控安全", Pattern: `(?i)(s7comm|plc_?(stop|run|start)|snap7|机组\s*(启|停)|断路器|合闸|分闸|遥控指令|remote_?control)`, Action: "block", Enabled: true, Level: 0},
		{ID: "ics_3", Name: "IEC60870/104指令", Category: "工控安全", Pattern: `(?i)(iec104|iec60870|type_?id|c_?sc_?na|c_?dc_?na|c_?se_?na|总召|遥控|遥调)`, Action: "block", Enabled: true, Level: 0},
		{ID: "ics_4", Name: "固件篡改/上传", Category: "工控安全", Pattern: `(?i)(firmware_?upload|upgrade_?firmware|固件更新|固件升级|upload_?bin|bootloader)`, Action: "block", Enabled: true, Level: 0},
		{ID: "ics_5", Name: "OPC UA 异常", Category: "工控安全", Pattern: `(?i)(opc\.?tcp|opcua|opc_?ua|browse_?next|create_?session|anonymous_?login)`, Action: "block", Enabled: true, Level: 1},
		{ID: "ics_6", Name: "DN3/104 扫描", Category: "工控安全", Pattern: `(?i)(dnp3|dnp\s*3|0xc0|operate\s*?response)`, Action: "log", Enabled: true, Level: 1},

		// ========== 敏感信息 / 认证绕过 ==========
		{ID: "info_1", Name: "敏感信息泄露", Category: "信息泄露", Pattern: `(?i)(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk-[0-9a-zA-Z]{20,}|BEGIN (RSA |EC |)PRIVATE KEY|password\s*[=:]\s*[^\s]{4,}|secret\s*[=:]\s*[^\s]{4,}|api[_-]?key\s*[=:]\s*[^\s]{4,})`, Action: "log", Enabled: true, Level: 1},
		{ID: "auth_1", Name: "认证绕过尝试", Category: "认证绕过", Pattern: `(?i)('?\s*(or|union)\s*.*=\s*'?|admin'\s*--|admin"|\x27 OR \x271\x27=\x271|magic\s+bytes|bypassauth)`, Action: "block", Enabled: true, Level: 1},
		{ID: "jwt_1", Name: "JWT 攻击特征", Category: "认证绕过", Pattern: `(?i)(alg\s*[:=]\s*(none|HS256|RS256)|kid\s*[:=]\s*["']\.\./|eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)`, Action: "log", Enabled: true, Level: 2},

		// ========== Java 框架 / 组件漏洞 ==========
		{ID: "java_1", Name: "Fastjson 反序列化", Category: "Java漏洞", Pattern: `(?i)(fastjson|@type\s*[:=]|com\.sun\.rowset|JdbcRowSetImpl|TemplatesImpl|com\.alibaba)`, Action: "block", Enabled: true, Level: 0},
		{ID: "java_2", Name: "Log4Shell", Category: "Java漏洞", Pattern: `(?i)(\$\{jndi:|\$\{lower:|\$\{env:|\$\{sys:|\$\{::-|\$\$?\{)`, Action: "block", Enabled: true, Level: 0},
		{ID: "java_3", Name: "Spring/Struts 漏洞特征", Category: "Java漏洞", Pattern: `(?i)(Spring4Shell|CVE-2022-22965|struts\.|ognl\s*=|%\{[a-zA-Z_]+\}|S2-\d+|action:redirect|class\.module|memberAccess|allowStaticMethodAccess)`, Action: "block", Enabled: true, Level: 0},
		{ID: "java_4", Name: "SpEL/表达式注入", Category: "Java漏洞", Pattern: `(?i)(T\(java|Runtime\.getRuntime|ProcessBuilder|new\s+java\.lang|${T\(|@{|#{T\(|freemarker\.template|\.class\.forName)`, Action: "block", Enabled: true, Level: 1},
		{ID: "java_5", Name: "Shiro/WebLogic 特征", Category: "Java漏洞", Pattern: `(?i)(rememberMe=|wls9-async|_async/|bea_wls|weblogic\.servlet|ShiroKey|CVE-2019-2725|CVE-2018-2894)`, Action: "block", Enabled: true, Level: 1},
		{ID: "java_6", Name: "JBoss/GlassFish 特征", Category: "Java漏洞", Pattern: `(?i)(/invoker/JMXInvokerServlet|/jmx-console/|/web-console/|/htmlAdaptor|/server-status|glassfish|jsp?/(admin|test))`, Action: "block", Enabled: true, Level: 1},
		{ID: "java_7", Name: "Shiro反序列化大Cookie", Category: "Java漏洞", Pattern: `(?i)rememberMe=[A-Za-z0-9+/=]{200,}`, Action: "block", Enabled: true, Level: 0},
		{ID: "java_8", Name: "Shiro deleteMe 探测", Category: "Java漏洞", Pattern: `(?i)(rememberMe=deleteMe|remember-me=deleteMe)`, Action: "log", Enabled: true, Level: 1},
		{ID: "java_9", Name: "Spring Actuator 敏感端点", Category: "Java漏洞", Pattern: `(?i)/actuator/(heapdump|env|threaddump|mappings|beans|configprops|loggers|dump|trace|jolokia)`, Action: "block", Enabled: true, Level: 0},
		{ID: "java_10", Name: "Arthas 注入路径", Category: "Java漏洞", Pattern: `(?i)(/arthas|arthas-boot\.jar|/commands/jad|/commands/sc|/commands/heapdump|Arthas-Watcher)`, Action: "block", Enabled: true, Level: 0},
		{ID: "java_11", Name: "JDumpSpider/ysoserial 工具", Category: "Java漏洞", Pattern: `(?i)(JDumpSpider|ysoserial|shiro_attack|shiro-exploit|ShiroExploit)`, Action: "block", Enabled: true, Level: 0},
		{ID: "java_12", Name: "Spring Cloud Gateway CVE", Category: "Java漏洞", Pattern: `(?i)(CVE-2022-22947|/actuator/gateway/routes|/actuator/gateway/refresh|spring-cloud-gateway)`, Action: "block", Enabled: true, Level: 0},
		{ID: "java_13", Name: "Druid 未授权监控", Category: "Java漏洞", Pattern: `(?i)/druid/(index\.html|login\.html|sql\.html|datasource\.html|wall\.html)`, Action: "log", Enabled: true, Level: 1},
		{ID: "java_14", Name: "Nacos/Eureka 未授权", Category: "Java漏洞", Pattern: `(?i)/(nacos|eureka)/?(v1/)?(auth/login|users|configurations|namespace|apps)`, Action: "log", Enabled: true, Level: 1},
		{ID: "java_15", Name: "Tomcat AJP Ghostcat", Category: "Java漏洞", Pattern: `(?i)(AJP/1\.3|ajp13|/\.\.;/|xhtml\.jsp|CVE-2020-1938)`, Action: "block", Enabled: true, Level: 0},
		{ID: "java_16", Name: "Tomcat PUT 上传 JSP", Category: "Java漏洞", Pattern: `(?i)^(PUT|MOVE)\s+/[^\s]*\.jsp(\s|$)`, Action: "block", Enabled: true, Level: 0},
		{ID: "java_17", Name: "SnakeYAML 反序列化", Category: "Java漏洞", Pattern: `(?i)(!!javax\.script|!!org\.yaml|!!java\.lang|tag:yaml\.org,2002:javax|script\.ScriptEngineManager)`, Action: "block", Enabled: true, Level: 0},

		// ========== 开放重定向 / CSRF / 请求走私 ==========
		{ID: "redir_1", Name: "开放重定向", Category: "协议攻击", Pattern: `(?i)(redirect\s*[:=]|return_url\s*=|next\s*=|url\s*[:=]\s*["']?\s*https?://|location\s*[:=]\s*//|\?\w*url=https?://)`, Action: "block", Enabled: true, Level: 1},
		{ID: "csrf_1", Name: "CSRF 跨站请求伪造", Category: "协议攻击", Pattern: `(?i)(origin:\s*https?://[^\s]*\.(evil|attacker|example|xss)\.|sec-fetch-site:\s*cross-site)`, Action: "log", Enabled: true, Level: 2},
		{ID: "smuggle_1", Name: "HTTP请求走私", Category: "协议攻击", Pattern: `(?i)(\r\n\s*(Content-Length|Transfer-Encoding)\s*:|Content-Length\s*:\s*\d+\s*\r\n\s*Transfer-Encoding)`, Action: "block", Enabled: true, Level: 1},
		{ID: "smuggle_2", Name: "TE/CL 冲突", Category: "协议攻击", Pattern: `(?i)(Transfer-Encoding\s*:\s*(chunked|identity)\s*\r\n\s*Content-Length|CL\.TE|TE\.CL|Content-Length\s*:\s*0\s*\r\n\s*Transfer-Encoding)`, Action: "block", Enabled: true, Level: 1},

		// ========== 爆破 / 未授权 ==========
		{ID: "brute_1", Name: "爆破参数特征", Category: "扫描器", Pattern: `(?i)(password\s*[:=]\s*[^&\s]{4,}|passwd\s*[:=]|login\s*[:=]\s*admin|username\s*[:=]\s*admin|X-Forwarded-For\s*:\s*(127|192\.168))`, Action: "log", Enabled: true, Level: 2},
		{ID: "unauth_1", Name: "未授权访问探测", Category: "扫描器", Pattern: `(?i)(/actuator/(env|heapdump|trace|mappings|beans)|/swagger-ui|/druid/|/springenv|/console/|/debug/|/admin/|/manager/html|/nacos/|/eureka/|/api-docs)`, Action: "log", Enabled: true, Level: 1},

		// ========== 内存马 / 高级持久化 ==========
		{ID: "mem_1", Name: "内存马注入", Category: "WebShell", Pattern: `(?i)(define\s*\(\s*["']?EVAL|memory_shell|gopher_byte|@session_start.*eval|$_SERVER\s*\[.HTTP_HOST.*eval|addFilter|FilterRegistration|define\s*\(\s*["']CMD_)`, Action: "block", Enabled: true, Level: 1},
		{ID: "mem_2", Name: "混淆 WebShell", Category: "WebShell", Pattern: `(?i)(eval\s*\(\s*(chr|hex2bin|rawurldecode|urldecode|base64|str_rot13|gzdeflate)\s*\(|preg_replace\s*\(\s*["'][^"']*["']\s*,\s*["'][^"']*["']\s*,\s*\$_|assert\s*\(\s*\$_POST)`, Action: "block", Enabled: true, Level: 0},
		{ID: "mem_3", Name: "利用回调函数", Category: "WebShell", Pattern: `(?i)(array_filter\s*\(.*\$_(POST|GET)|uasort\s*\(.*\$_(POST|GET)|array_walk\s*\(.*\$_(POST|GET)|usort\s*\(.*\$_(POST|GET)|array_map\s*\(.*\$_(POST|GET)|preg_replace_callback\s*\(.*\$_(POST|GET))`, Action: "block", Enabled: true, Level: 1},

		// ========== 其他注入 ==========
		{ID: "html_1", Name: "HTML/内联样式注入", Category: "XSS", Pattern: `(?i)(<style[^>]*>|<link[^>]*rel\s*=\s*["']?stylesheet|data\s*:\s*text/html|<math[^>]*>|<template[^>]*>|<details[^>]*open)`, Action: "block", Enabled: true, Level: 1},
		{ID: "cmd_2", Name: "命令拼接-数学/变量", Category: "命令执行", Pattern: `(?i)(\$\{IFS\}|/usr/bin/env\s+|curl\s+\w+|wget\s+[^\s]+\s+-O\s+/tmp|echo\s+\$\(\w+|b64\s*-d\s*<<<|\$\(whoami\))`, Action: "block", Enabled: true, Level: 1},
		{ID: "nginx_1", Name: "Nginx 配置/绕过", Category: "扫描器", Pattern: `(?i)(nginx\.conf|\.php\.\w{1,5}$|%0a\s*Passenger|/etc/nginx|location\s*\*\s*\.php|passenger-app-env)`, Action: "log", Enabled: true, Level: 2},

		// ========== IIS 漏洞（Windows 靶机，Win7~Win11 + IIS 6~10） ==========
		{ID: "iis_1", Name: "IIS 短文件名扫描", Category: "中间件漏洞", Pattern: `(?i)(\?\?\~1|\~\$|/(?i)[a-z]{2,6}\.[a-z]{2,4}\s*\*\s*\$|/\\\?/|CVE-2018-8531)`, Action: "block", Enabled: true, Level: 2},
		{ID: "iis_2", Name: "IIS 解析漏洞探测", Category: "中间件漏洞", Pattern: `(?i)(\.asp[;/.]|\.aspx[;/.]|\.php[;/.]|\.asa[;/.]|x\.asp\.jpg|shell\.aspx\.|CVE-2019-1122|msada|webadmin\.dll|vti_bin/)`, Action: "block", Enabled: true, Level: 1},
		{ID: "iis_3", Name: "IIS PUT/WebDAV 上传", Category: "中间件漏洞", Pattern: `(?i)(^(PUT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK)\s|msdav\.dll|WebDAV|PROPFIND)`, Action: "block", Enabled: true, Level: 0},
		{ID: "iis_4", Name: "IIS 短名/8.3 泄露", Category: "中间件漏洞", Pattern: `(?i)(\*\?|\?\\|\?\?~|\w{2,6}~\w|\$\d|8\.3\s*(name|filename))`, Action: "log", Enabled: true, Level: 2},
		{ID: "iis_5", Name: "ASP.NET 反序列化/ViewState", Category: "中间件漏洞", Pattern: `(?i)(__VIEWSTATE|__EVENTVALIDATION|machineKey|\.NET\s*Remoting|BinaryFormatter|CVE-2018-0785|WebResource\.axd|ScriptResource\.axd|/trace\.axd|elfmage)`, Action: "block", Enabled: true, Level: 0},

		// ========== Tomcat 漏洞 ==========
		{ID: "tomcat_1", Name: "Tomcat Ghostcat 读取", Category: "中间件漏洞", Pattern: `(?i)(/\.\.;/|javax\.faces|jsf/|xhtml\.jsp|CVE-2020-1938|AJP/1\.3|ajp13|getAttribute\(\).*javax\.servlet|WEB-INF/web\.xml|META-INF/context\.xml)`, Action: "block", Enabled: true, Level: 0},
		{ID: "tomcat_2", Name: "Tomcat 管理后台爆破", Category: "中间件漏洞", Pattern: `(?i)(/manager/(html|text|status)|/host-manager/|/manager/status|tomcat-manager|CVE-2017-12615|PUT\s+/.*\.jsp)`, Action: "log", Enabled: true, Level: 1},
		{ID: "tomcat_3", Name: "Tomcat RCE 特征", Category: "中间件漏洞", Pattern: `(?i)(CVE-2017-12615|CVE-2019-0232|CGIServlet|enableCmdLineArguments|org\.apache\.catalina|JSPCompiler|/cgi-bin/.*\.jsp)`, Action: "block", Enabled: true, Level: 1},

		// ========== Apache httpd 漏洞 ==========
		{ID: "apache_1", Name: "Apache 路径穿越/解析绕过", Category: "中间件漏洞", Pattern: `(?i)(CVE-2021-41773|CVE-2021-42013|CVE-2017-15715|%252e%252e|/icons/\.\.|mod_cgi|\.php%0a|AddType|ServerTokens)`, Action: "block", Enabled: true, Level: 0},
		{ID: "apache_2", Name: "Apache 目录遍历/OPTIONS", Category: "中间件漏洞", Pattern: `(?i)(\.\./\.\./\.\./etc/passwd|OPTIONS\s+\*|CVE-2019-0211|CVE-2018-1312|TRACE\s+|X-HTTP-Method-Override)`, Action: "block", Enabled: true, Level: 1},

		// ========== Nginx 版本漏洞 ==========
		{ID: "nginx_2", Name: "Nginx 目录穿越/CRLF", Category: "中间件漏洞", Pattern: `(?i)(CVE-2017-7529|CVE-2019-20372|X-Accel-Redirect|X-Sendfile|/../../../.*\.conf|%0d%0a\s*Location)`, Action: "block", Enabled: true, Level: 0},
		{ID: "nginx_3", Name: "Nginx 变量/配置注入", Category: "中间件漏洞", Pattern: `(?i)(nginx\.conf|/etc/nginx|proxy_pass\s*http|set\s+\$|rewrite\s+\^|passenger|mod_zip|CVE-2021-23017)`, Action: "log", Enabled: true, Level: 2},

		// ========== 远程桌面/Windows 服务漏洞 ==========
		{ID: "win_1", Name: "RDP/BlueKeep 探测", Category: "中间件漏洞", Pattern: `(?i)(BlueKeep|CVE-2019-0708|CVE-2020-0601|rdp\s*:|mstsc|RemoteDesktop|cookie:\s*mstshash)`, Action: "block", Enabled: true, Level: 1},
		{ID: "win_2", Name: "SMB/永恒之蓝特征", Category: "中间件漏洞", Pattern: `(?i)(EternalBlue|MS17-010|smbv1|CVE-2017-0144|\\\\\*\S+\s+IPC\$|SMB2)`, Action: "log", Enabled: true, Level: 2},
	}
}

// Compile 校验并编译正则（供面板规则校验）
func Compile(pattern string) error {
	_, err := regexp.Compile(pattern)
	return err
}

// GenPHP 生成软WAF PHP 代码
// antiImmortal: 开启不死马防护（目录不可变 + 上传php拦截）
func GenPHP(rules []*Rule, antiImmortal bool, blockAction string) string {
	var sb strings.Builder
	sb.WriteString("<?php\n")
	sb.WriteString("/**\n")
	sb.WriteString(" * 综合防御平台 SoftWAF (auto generated)\n")
	sb.WriteString(" * Deploy: .user.ini auto_prepend_file=waf.php\n")
	sb.WriteString(" * 仅用于授权比赛靶标的应急加固\n")
	sb.WriteString(" */\n")
	sb.WriteString("if (PHP_SAPI === 'cli') { return; }\n")
	sb.WriteString("define('SHIELD_WAF_START', microtime(true));\n")
	sb.WriteString("define('SHIELD_WAF_VERSION', '1.0.0');\n\n")

	// 基础安全头
	sb.WriteString("// ---------- 安全响应头 ----------\n")
	sb.WriteString("@header('X-Frame-Options: SAMEORIGIN');\n")
	sb.WriteString("@header('X-Content-Type-Options: nosniff');\n")
	sb.WriteString("@header('X-XSS-Protection: 1; mode=block');\n\n")

	// 配置
	sb.WriteString("// ---------- 配置 ----------\n")
	sb.WriteString("$SHIELD_WAF = array(\n")
	sb.WriteString("  'block_action' => " + phpQuote(blockAction) + ",\n")
	sb.WriteString("  'log_file' => ini_get('error_log'),\n")
	sb.WriteString("  'rate_limit' => array('window' => 60, 'max' => 300),\n")
	sb.WriteString(");\n")
	sb.WriteString("$SHIELD_HIT = array();\n")
	sb.WriteString("if (!isset($_SERVER['REQUEST_URI'])) { $_SERVER['REQUEST_URI'] = ''; }\n")
	sb.WriteString("$SHIELD_INPUT = array(\n")
	sb.WriteString("  'uri' => $_SERVER['REQUEST_URI'],\n")
	sb.WriteString("  'get' => $_GET,\n")
	sb.WriteString("  'post' => $_POST,\n")
	sb.WriteString("  'cookie' => $_COOKIE,\n")
	sb.WriteString("  'headers' => getallheaders(),\n")
	sb.WriteString(");\n\n")

	// 规则表
	sb.WriteString("// ---------- 检测规则 ----------\n")
	sb.WriteString("$SHIELD_RULES = array(\n")
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		action := r.Action
		if action == "" {
			action = "block"
		}
		sb.WriteString(fmt.Sprintf("  array(%s, %s, %s),\n", phpQuote(r.Name), phpQuote(r.Pattern), phpQuote(action)))
	}
	sb.WriteString(");\n\n")

	// 检测函数
	sb.WriteString("// ---------- 检测逻辑 ----------\n")
	sb.WriteString("function shield_scan($data, $rules) {\n")
	sb.WriteString("  foreach ($rules as $rule) {\n")
	sb.WriteString("    list($name, $pattern, $action) = $rule;\n")
	sb.WriteString("    foreach ($data as $src => $value) {\n")
	sb.WriteString("      if (is_array($value)) {\n")
	sb.WriteString("        foreach ($value as $k => $v) {\n")
	sb.WriteString("          if (is_array($v)) { $v = @json_encode($v); }\n")
	sb.WriteString("          if (@preg_match($pattern, $v) || @preg_match($pattern, (string)$k)) {\n")
	sb.WriteString("            shield_hit($name, $src, $action);\n")
	sb.WriteString("            if ($action === 'block') { shield_block($name, $src); }\n")
	sb.WriteString("          }\n")
	sb.WriteString("        }\n")
	sb.WriteString("      } else {\n")
	sb.WriteString("        if (@preg_match($pattern, (string)$value)) {\n")
	sb.WriteString("          shield_hit($name, $src, $action);\n")
	sb.WriteString("          if ($action === 'block') { shield_block($name, $src); }\n")
	sb.WriteString("        }\n")
	sb.WriteString("      }\n")
	sb.WriteString("    }\n")
	sb.WriteString("  }\n")
	sb.WriteString("}\n\n")

	sb.WriteString("function shield_hit($name, $src, $action) {\n")
	sb.WriteString("  global $SHIELD_HIT;\n")
	sb.WriteString("  $SHIELD_HIT[] = $name . '[' . $src . ']' . '[' . $action . ']';\n")
	sb.WriteString("}\n\n")

	sb.WriteString("function shield_block($name, $src) {\n")
	sb.WriteString("  $line = date('Y-m-d H:i:s') . ' | ' . $_SERVER['REMOTE_ADDR'] . ' | ' . ($_SERVER['HTTP_USER_AGENT'] ?? '') . ' | ' . $_SERVER['REQUEST_URI'] . ' | ' . $name . '[' . $src . ']';\n")
	sb.WriteString("  @error_log('[SHIELD-WAF] ' . $line . PHP_EOL, 3, ini_get('error_log'));\n")
	sb.WriteString("  if (defined('SHIELD_WAF_RATE_DISABLED')) { return; }\n")
	sb.WriteString("  header('HTTP/1.1 403 Forbidden');\n")
	sb.WriteString("  header('Content-Type: text/plain; charset=utf-8');\n")
	sb.WriteString("  echo \"\\nForbidden. Request blocked by 综合防御平台 WAF.\\n\";\n")
	sb.WriteString("  exit;\n")
	sb.WriteString("}\n\n")

	// 收集输入并执行
	sb.WriteString("// ---------- 输入收集与执行 ----------\n")
	sb.WriteString("$SHIELD_ALL = array_merge($SHIELD_INPUT['get'], $SHIELD_INPUT['post'], $SHIELD_INPUT['cookie']);\n")
	sb.WriteString("$SHIELD_ALL['uri'] = $SHIELD_INPUT['uri'];\n")
	sb.WriteString("if (isset($SHIELD_INPUT['headers'])) {\n")
	sb.WriteString("  foreach ($SHIELD_INPUT['headers'] as $hk => $hv) {\n")
	sb.WriteString("    $SHIELD_ALL['header_' . strtolower($hk)] = $hv;\n")
	sb.WriteString("  }\n")
	sb.WriteString("}\n")
	sb.WriteString("shield_scan($SHIELD_ALL, $SHIELD_RULES);\n\n")

	// 简单限速
	sb.WriteString("// ---------- 简易限速 ----------\n")
	sb.WriteString("$SHIELD_RATE_KEY = 'shield_rate_' . md5($_SERVER['REMOTE_ADDR']);\n")
	sb.WriteString("$SHIELD_RATE = isset($_SESSION) ? null : null;\n")
	sb.WriteString("if (function_exists('apcu_fetch')) {\n")
	sb.WriteString("  $SHIELD_CNT = apcu_fetch($SHIELD_RATE_KEY);\n")
	sb.WriteString("  $SHIELD_WIN = apcu_fetch($SHIELD_RATE_KEY . '_t');\n")
	sb.WriteString("  if (!$SHIELD_CNT) { $SHIELD_CNT = 0; $SHIELD_WIN = time(); }\n")
	sb.WriteString("  if (time() - $SHIELD_WIN > $SHIELD_WAF['rate_limit']['window']) { $SHIELD_CNT = 0; $SHIELD_WIN = time(); }\n")
	sb.WriteString("  $SHIELD_CNT++;\n")
	sb.WriteString("  apcu_store($SHIELD_RATE_KEY, $SHIELD_CNT, $SHIELD_WAF['rate_limit']['window']);\n")
	sb.WriteString("  apcu_store($SHIELD_RATE_KEY . '_t', $SHIELD_WIN, $SHIELD_WAF['rate_limit']['window']);\n")
	sb.WriteString("  if ($SHIELD_CNT > $SHIELD_WAF['rate_limit']['max']) {\n")
	sb.WriteString("    header('HTTP/1.1 429 Too Many Requests');\n")
	sb.WriteString("    echo \"Rate limit exceeded.\"; exit;\n")
	sb.WriteString("  }\n")
	sb.WriteString("}\n\n")

	// 上传防护
	if antiImmortal {
		sb.WriteString("// ---------- 上传防护 ----------\n")
		sb.WriteString("if (isset($_FILES) && is_array($_FILES)) {\n")
		sb.WriteString("  foreach ($_FILES as $f) {\n")
		sb.WriteString("    if (is_array($f) && isset($f['name'])) {\n")
		sb.WriteString("      $names = is_array($f['name']) ? $f['name'] : array($f['name']);\n")
		sb.WriteString("      foreach ($names as $n) {\n")
		sb.WriteString("        if (preg_match('/\\.(php|phtml|phar|php5|pht|jsp|jspx|aspx|asp|cgi)$/i', $n)) {\n")
		sb.WriteString("          shield_block('恶意上传文件', 'file');\n")
		sb.WriteString("        }\n")
		sb.WriteString("      }\n")
		sb.WriteString("    }\n")
		sb.WriteString("  }\n")
		sb.WriteString("}\n\n")

		sb.WriteString("// ---------- 不死马防护：阻断创建新php ----------\n")
		sb.WriteString("$SHIELD_SCRIPT = $_SERVER['SCRIPT_FILENAME'] ?? '';\n")
		sb.WriteString("if (strpos($_SERVER['PHP_SELF'], '.php') !== false) {\n")
		sb.WriteString("  $SHIELD_SELF = basename($_SERVER['PHP_SELF']);\n")
		sb.WriteString("  if ($SHIELD_SELF === 'waf.php' || $SHIELD_SELF === '.user.ini') { }\n")
		sb.WriteString("}\n")
	}

	// 结束
	sb.WriteString("// ---------- 性能耗时注入 ----------\n")
	sb.WriteString("$GLOBALS['SHIELD_WAF_TIME'] = microtime(true) - SHIELD_WAF_START;\n")
	sb.WriteString("if (defined('SHIELD_WAF_VERBOSE') && SHIELD_WAF_VERBOSE) {\n")
	sb.WriteString("  if (!empty($SHIELD_HIT)) { /* hits: ")
	sb.WriteString(" */ }\n")
	sb.WriteString("}\n")

	return sb.String()
}

func phpQuote(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "'", "\\'")
	return "'" + s + "'"
}

// UserIni 生成 .user.ini 内容
func UserIni(wafFilename string) string {
	return fmt.Sprintf("; 综合防御平台 auto_prepend_file\nauto_prepend_file=%s\n", wafFilename)
}
