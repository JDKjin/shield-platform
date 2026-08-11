# 多因素认证 MFA 与权限控制手册

> 培训内容深化整理：MFA 原理、Tomcat/SSH/Web 多因素强化、最小权限原则。
> 适用场景：综合防御竞赛靶机账号体系加固、防爆破、防越权。

## 一、MFA 基本原理

### 1.1 什么是 MFA

多因素认证（Multi Factor Authentication）：在用户名密码之外，再增加一层安全保护。

**两层安全要素**：
1. **第一层**：用户名 + 密码（你知道的）
2. **第二层**：
   - 虚拟 MFA 设备生成的验证码（Google Authenticator）
   - 通行密钥（Passkey / FIDO2）
   - 安全手机短信验证码
   - 安全邮箱验证码
   - 硬件 Key（U2F / YubiKey）

### 1.2 MFA 不影响的场景

> 培训 PDF 原文：**不影响通过 AccessKey 的 API 调用**

即：MFA 只对**控制台登录**和**敏感操作**生效，对程序化 API 调用（AccessKey）不生效。这要求：
- AccessKey 必须妥善保管（环境变量、密钥管理服务）
- AccessKey 权限最小化
- AccessKey 定期轮换

## 二、Tomcat Manager 的多因素强化

### 2.1 现状问题

Tomcat Manager 默认只支持单一密码认证，容易被 msf 爆破：

```bash
msf > use auxiliary/scanner/http/tomcat_mgr_login
msf > set rhosts 192.168.1.131
msf > set rport 8080
msf > run
```

### 2.2 强化方案 1：IP 白名单 + 强密码

`$CATALINA_HOME/webapps/manager/META-INF/context.xml`：

```xml
<Context antiResourceLocking="false" privileged="true">
    <Valve className="org.apache.catalina.valves.RemoteAddrValve"
           allow="127\.\d+\.\d+\.\d+|10\.10\.10\.\d+|::1"/>
</Context>
```

配合 `tomcat-users.xml` SHA-256 加密密码（见 Tomcat 账户加固手册）。

### 2.3 强化方案 2：Nginx 反代 + Basic Auth 二次验证

```nginx
location /manager/ {
    auth_basic "Tomcat Manager Restricted";
    auth_basic_user_file /etc/nginx/.htpasswd;

    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}

location /host-manager/ {
    auth_basic "Tomcat Host-Manager Restricted";
    auth_basic_user_file /etc/nginx/.htpasswd;

    proxy_pass http://127.0.0.1:8080;
}
```

生成 htpasswd：
```bash
htpasswd -c /etc/nginx/.htpasswd deploy_admin
chmod 644 /etc/nginx/.htpasswd
```

### 2.4 强化方案 3：直接下架（推荐）

如果业务不需要 Manager：
```bash
cd $CATALINA_HOME/webapps
mv manager manager.disabled
mv host-manager host-manager.disabled
```

## 三、SSH 多因素强化

### 3.1 密钥 + 密码双因素

`/etc/ssh/sshd_config`：

```sshconfig
# 启用密钥认证
PubkeyAuthentication yes

# 禁用密码单独登录（关键）
PasswordAuthentication no

# 但保留键盘交互（用于双因素 PAM）
KbdInteractiveAuthentication yes
ChallengeResponseAuthentication yes

# 限制登录用户
AllowUsers deploy@10.0.0.0/8

# 限制来源
Match Address 10.0.0.0/8
    PasswordAuthentication no
    PubkeyAuthentication yes
```

### 3.2 密钥 + Google Authenticator（TOTP）

```bash
apt install libpam-google-authenticator -y

# 用户执行
google-authenticator
# 扫描二维码，保存应急备份码

# 配置 PAM
echo "auth required pam_google_authenticator.so" >> /etc/pam.d/sshd

# sshd 配置
sed -i 's/^#ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config

systemctl restart sshd
```

登录时需：SSH 密钥 + TOTP 6 位验证码。

### 3.3 SSH 加固清单

| 配置项 | 推荐值 | 说明 |
|---|---|---|
| `PermitRootLogin` | `no` | 禁止 root 直接登录 |
| `PasswordAuthentication` | `no` | 禁用密码登录 |
| `PubkeyAuthentication` | `yes` | 启用密钥 |
| `MaxAuthTries` | `4` | 最大重试 |
| `LoginGraceTime` | `60` | 登录宽限期 |
| `ClientAliveInterval` | `300` | 空闲超时 |
| `ClientAliveCountMax` | `2` | 超时次数 |
| `AllowTcpForwarding` | `no` | 禁用转发 |
| `X11Forwarding` | `no` | 禁用 X11 |
| `Protocol` | `2` | 仅协议 v2 |

## 四、Web 应用多因素强化

### 4.1 登录页防护

**WAF 规则（已有）**：
- `brute_1`：爆破参数特征
- `pam_lockout`：PAM 失败锁定

**应用层强化**：
```nginx
# 限制登录接口速率
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

server {
    location /login {
        limit_req zone=login burst=3 nodelay;
        limit_req_status 429;

        proxy_pass http://backend;
    }
}
```

### 4.2 关键操作二次验证

敏感操作（修改密码、删除用户、部署应用）应要求二次验证：
- 重新输入密码
- TOTP 验证码
- 短信/邮件验证码

### 4.3 Session 加固

```nginx
# Session Cookie 安全属性
proxy_cookie_path / "/; HTTPOnly; Secure; SameSite=Strict";

# 强制 HTTPS
if ($scheme = http) {
    return 301 https://$host$request_uri;
}
```

## 五、最小权限原则（PoLP）

### 5.1 账号最小权限

| 角色 | 权限 | 原则 |
|---|---|---|
| 普通用户 | 只读 + 自有目录写 | 最小必要 |
| 运维账号 | sudo 限定命令 | 不用 ALL |
| 应用账号 | 仅应用目录 | 禁 shell |
| 数据库账号 | 仅业务库 | 禁 root |

### 5.2 sudo 权限示例

```bash
# 错误：给全部权限
deploy ALL=(ALL) NOPASSWD:ALL

# 正确：只给必要命令
deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart app
deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl status app
deploy ALL=(ALL) NOPASSWD: /usr/bin/journalctl -u app
```

### 5.3 文件权限基线

| 文件 | 权限 | 说明 |
|---|---|---|
| `/etc/passwd` | `644` | 所有人可读 |
| `/etc/shadow` | `640` 或 `000` | 仅 root 可读 |
| `/etc/sudoers` | `440` | 仅 root 可读写 |
| `~/.ssh/` | `700` | 仅所有者 |
| `~/.ssh/authorized_keys` | `600` | 仅所有者 |
| `/var/www/html/` | `755` | 目录 |
| `/var/www/html/upload/` | `555` | 上传目录不可写执行 |

## 六、AccessKey / API 凭证管理

### 6.1 不要写入代码或配置

**错误**：
```properties
# application.properties
aliyun.access-key=LTAI5tXXXXXXXXXXXX
aliyun.secret=YYYYYYYYYYYYYYYY
```

**正确**：通过环境变量或密钥管理服务

```bash
# systemd 服务
[Service]
Environment="ALIYUN_ACCESS_KEY=LTAI5tXXXXXXXXXXXX"
Environment="ALIYUN_SECRET=YYYYYYYYYYYYYYYY"
EnvironmentFile=/etc/secrets/app.env
```

`/etc/secrets/app.env` 权限 `600`，属主应用账号。

### 6.2 检查泄漏

```bash
# 在代码仓库中搜索
grep -rE 'AKIA[0-9A-Z]{16}|LTAI[0-9A-Za-z]+|sk-[0-9a-zA-Z]{20,}' /opt /srv /home /app

# 在配置文件中搜索
find /opt /srv /home -name "*.properties" -o -name "*.yml" | \
  xargs grep -lE 'access.?key|secret' 2>/dev/null

# 在 heapdump 中（如果泄漏）
java -jar JDumpSpider-1.1-SNAPSHOT-full.jar heapdump.hprof | grep -iE 'AKIA|LTAI|secret'
```

### 6.3 轮换策略

- AccessKey 90 天轮换
- 数据库密码 30 天轮换
- SSH 密钥 180 天轮换
- TLS 证书 365 天轮换

## 七、培训案例：Tomcat Manager 防爆破

### 7.1 加固前

```bash
# msf 直接爆破
msf > use auxiliary/scanner/http/tomcat_mgr_login
msf > set rhosts 192.168.1.131
msf > set rport 8080
msf > run
# [+] 192.168.1.131 - SUCCESS: tomcat:tomcat
```

### 7.2 加固后

**方案 A：下架 Manager**
```bash
mv $CATALINA_HOME/webapps/manager $CATALINA_HOME/webapps/manager.disabled
mv $CATALINA_HOME/webapps/host-manager $CATALINA_HOME/webapps/host-manager.disabled
```

**方案 B：IP 白名单 + 强密码 + Nginx 二次认证**

`server.xml` 移除默认账号，`context.xml` 加 IP 限制，Nginx 加 Basic Auth。

```bash
# msf 再次爆破
msf > run
# [-] 192.168.1.131 - FAILED: tomcat:tomcat
# [-] 192.168.1.131 - FAILED: admin:admin
# 全部失败
```

## 八、相关加固项

| 加固项 ID | 作用 |
|---|---|
| `ssh_harden` | SSH 加固 |
| `ssh_session` | SSH 会话加固（超时、最大重试） |
| `pam_lockout` | PAM 失败锁定 |
| `passwd_policy` | 密码策略强化 |
| `sudo_restrict` | sudo 权限收紧 |
| `tomcat_user_harden` | Tomcat 账户加固 |
| `tomcat_mgr_remove` | Manager 应用下架 |
| `pubkey_check` | SSH 公钥审查 |

## 九、参考

- 培训 PDF：应急响应.pdf（多因素认证 MFA 与权限控制章节）
- 阿里云 RAM MFA：https://help.aliyun.com/document_detail/28635.html
- Google Authenticator PAM：https://github.com/google/google-authenticator-libpam
