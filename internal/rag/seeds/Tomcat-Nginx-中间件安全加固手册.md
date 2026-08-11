# Tomcat / Nginx 中间件安全加固手册

> 中间件是 Web 靶机的咽喉：Tomcat 管理后台与反序列化、Nginx 配置错误与解析漏洞，都是高频打点。本手册覆盖两类中间件的核查、加固与应急。

## 一、Tomcat 核查

```bash
# 1. 版本与已知漏洞（对应 CVE 速查手册）
catalina.sh version 2>/dev/null || cat /usr/share/tomcat/RELEASE-NOTES | head -5
# 2. 管理后台是否开放
ss -tlnp | grep 8080
curl -sI http://127.0.0.1:8080/manager/html | head -3
# 3. 默认口令与账号
grep -E '<user|<role' conf/tomcat-users.xml
# 4. 目录与权限
ls -la webapps/
find webapps -name '*.war' -mmin -180
```

## 二、Tomcat 加固

```xml
<!-- 1. tomcat-users.xml：删除默认/弱口令用户，只留最小必要 -->
<user username="admin" password="强随机口令" roles="manager-gui,admin-gui"/>
<!-- 2. 禁用不用的 Connector：如 AJP（CVE-2020-1938 Ghostcat 高危）-->
<!-- conf/server.xml 中注释掉 <Connector port="8009" protocol="AJP/1.3"> -->
```

```bash
# 3. 管理后台绑定内网/限制来源
# conf/server.xml 的 manager Host 配 <Valve> 按来源 IP 限制
# 4. 最小权限运行（非 root）
useradd -r tomcat && chown -R tomcat:tomcat /usr/share/tomcat
# 5. 关闭 war 自动部署（防上传 war 即执行）
# conf/server.xml: unpackWARs="false" autoDeploy="false"
# 6. 反序列化入口收敛：删除不需要的 lib、升级到修复版本
# 7. 目录权限
chmod 750 webapps/ && chown tomcat:tomcat webapps/
```

## 三、Nginx 核查

```bash
nginx -V 2>&1 | grep -iE 'version|prefix'   # 版本
nginx -t                                    # 配置语法检查
grep -rE 'autoindex|alias|root|fastcgi_pass' /etc/nginx/nginx.conf /etc/nginx/conf.d/* /etc/nginx/sites-enabled/* 2>/dev/null
ss -tlnp | grep -E ':80 |:443 '
```

## 四、Nginx 常见配置漏洞与修复

| 漏洞/风险 | 特征配置 | 修复 |
|----------|---------|------|
| 目录穿越 | `alias` 与 `location` 拼接未加 `/` | alias 后加 `/`；禁用 `alias` 拼接用户输入 |
| 目录列举 | `autoindex on` | 改 `off` |
| 解析漏洞（php 不解析） | `.php` 未配 fastcgi | 配置 `location ~ \.php$` 完整解析链 |
| 上传目录可执行 | uploads 在 php location 内 | `location ~* ^/uploads/.*\.php$ { deny all; }` |
| 任意文件读取 | `location / { root /var/www/html/; }` + 通配 | 收窄 root/alias，禁用多级 alias |
| 空字节/畸形文件名 | 未过滤 | 开启 `location ~ [^\-]\.[^/]{2,5}$` 兜底 |

```nginx
# 安全示例：上传目录禁执行 + 目录穿越兜底
location ~* ^/(upload|files|images|tmp)/.*\.(php|php5|phtml|jsp|asp)$ {
    deny all;
}
```

## 五、应急处置

1. **发现管理后台被进**：改 `tomcat-users.xml` 口令 → 删异常 war/应用 → 重启 tomcat。
2. **发现 Nginx 被改配置/加后门**：`nginx -t` 校验 → 比对基线恢复配置 → `systemctl reload nginx`。
3. **定位中间件后门**：`find webapps -name '*.war' -mmin -180`、`grep -rlE 'eval\(|\$_POST' webapps/`，可疑文件移取证目录。
4. **回滚**：面板 `backup_web` / `rollback_web` 恢复 webapps 干净快照，重启中间件验证业务。
