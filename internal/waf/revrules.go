package waf

import "regexp"

// compileRVBasic 基础 Web 攻击规则（scope=request）
func compileRVBasic() []rvRule {
	return []rvRule{
		{ID: "special_chars", Name: "危险特殊字符", Action: "block", Severity: "medium", Side: "request", Patterns: mustRe(
			`(\.\./){2,}`, `%2e%2e%2f`, `\\x00`, `<%\s*(script|iframe|object)`)},
		{ID: "sqli", Name: "SQL 注入防护", Action: "block", Severity: "high", Side: "request", Patterns: mustRe(
			`(?i)(\bunion\b.{0,40}\bselect\b)`,
			`(?i)\bselect\b.+\bfrom\b`,
			`(?i)\bor\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+`,
			`(?i)\band\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+`,
			`(?i)\bsleep\s*\(\s*\d+\s*\)`,
			`(?i)\bbenchmark\s*\(\s*\d+`,
			`(?i)\bupdatexml\s*\(`,
			`(?i)\bextractvalue\s*\(`,
			`(?i)information_schema`,
			`(?i)\bload_file\s*\(`,
			`(?i)\binto\s+outfile\b`,
			`--\s*$|#\s*$|/\*.*\*/`)},
		{ID: "rce", Name: "命令执行防护", Action: "block", Severity: "high", Side: "request", Patterns: mustRe(
			`(?i)(\bcat\b|\bwhoami\b|\bid\b|\buname\b|\bls\b|\bifconfig\b|\bipconfig\b)\b.{0,20}\|`,
			`(?i)(\||;|&{1,2}|\$\(|`+"`"+`)\s*(?:bash|sh|cmd|powershell|python|perl|nc|ncat)`,
			`(?i)\b(base64|certutil|wget|curl)\b.{0,30}\|\s*(?:sh|bash)`,
			`(?i)/bin/(?:sh|bash)`,
			`(?i)\beval\s*\(`,
			`(?i)\bexec\s*\(`,
			`(?i)\bsystem\s*\(`,
			`(?i)\bpassthru\s*\(`,
			`(?i)\bpopen\s*\(`,
			`(?i)\bproc_open\s*\(`)},
		{ID: "lfi", Name: "文件包含/读取防护", Action: "block", Severity: "high", Side: "request", Patterns: mustRe(
			`(?i)(\.\./){1,}`,
			`(?i)/(etc|proc|var)/`,
			`(?i)\bphp://`,
			`(?i)\bfile://`,
			`(?i)\bdata://`,
			`(?i)\bexpect://`,
			`(?i)\bphar://`,
			`(?i)\bzip://`)},
		{ID: "upload", Name: "危险文件上传防护", Action: "block", Severity: "high", Side: "request", Patterns: mustRe(
			`(?i)filename\s*=\s*["'].*\.(php|php3|php4|php5|phtml|pht|jsp|jspx|war|asp|aspx|asa|cer|py|pl|sh|cgi)\b`,
			`(?i)content-type\s*:\s*application/(x-php|octet-stream)`)},
		{ID: "unserialize", Name: "反序列化防护", Action: "block", Severity: "high", Side: "request", Patterns: mustRe(
			`(?i)\bunserialize\s*\(`,
			`(?i)\bO:\d+:"`,
			`\xac\xed\x00\x05`,
			`(?i)\bpickle\.loads?\s*\(`,
			`(?i)\b__reduce__\s*\(`)},
		{ID: "webshell", Name: "WebShell 特征", Action: "block", Severity: "critical", Side: "request", Patterns: mustRe(
			`(?i)\beval\s*\(`,
			`(?i)\bassert\s*\(`,
			`(?i)\bbase64_decode\s*\(`,
			`(?i)\bgzinflate\s*\(`,
			`(?i)\bstr_rot13\s*\(`,
			`(?i)\bcreate_function\s*\(`,
			`(?i)\bcall_user_func\s*\(`,
			`(?i)\barray_map\s*\(`)},
	}
}

// compileRVICS 能源工控场景规则（scope=request，告警级避免误伤业务）
func compileRVICS() []rvRule {
	return []rvRule{
		{ID: "energy_ics", Name: "能源工控协议异常/危险操作", Action: "alert", Severity: "critical", Side: "request", Patterns: mustRe(
			`(?i)(modbus|fc\s*[=:]?\s*(5|6|15|16)|write_?register|write_?coil|holding_?register)`,
			`(?i)(0x0[56]|0x1[0f]|function\s*code\s*[=:]?\s*(5|6|15|16))`,
			`(?i)(iec\s*?104|iec104|iec60870|type_?id|c_?sc_?na|c_?dc_?na|c_?se_?na|c_?ic_?na|总召|遥控|遥调)`,
			`(?i)(dnp3|dnp\s*3|0xc0|operate\s*?response)`,
			`(?i)(opc\.?tcp|opcua|opc_?ua|browse_?next|create_?session|anonymous_?login)`,
			`(?i)(snap7|s7.?1200|s7.?1500|s7comm|plc_?(stop|run|start)|plc\s*启停|机组\s*(启|停))`,
			`(?i)(断路器|合闸|分闸|开关[分合]|阀门|定值|固件|firmware|remote_?control|遥控指令)`,
			`(?i)(firmware_?upload|upgrade_?firmware|固件更新|固件升级|upload_?bin)`)},
		{ID: "flag_protect", Name: "Flag 泄露保护", Action: "alert", Severity: "critical", Side: "response", Patterns: mustRe(
			`flag\{[^}]*\}`,
			`flag\s*[:=]\s*[A-Za-z0-9_\-]{4,}`,
			`(?i)ctf\{[^}]*\}`)},
	}
}

// mustRe 编译正则（内置规则确保合法）
func mustRe(pats ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(pats))
	for _, p := range pats {
		out = append(out, regexp.MustCompile(p))
	}
	return out
}
