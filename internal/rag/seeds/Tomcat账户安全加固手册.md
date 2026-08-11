# Tomcat 账户安全加固手册

> 培训内容深化整理：tomcat-users.xml 加固、密码加密、Manager 应用下架、msf 爆破检测。
> 适用场景：综合防御竞赛靶机 Tomcat 中间件加固、Manager 后台爆破防御。

## 一、Tomcat 账户体系

### 1.1 配置文件位置

```
$CATALINA_HOME/conf/tomcat-users.xml
```

常见路径：
- `/etc/tomcat9/tomcat-users.xml`（Ubuntu/Debian 包安装）
- `/usr/share/tomcat/conf/tomcat-users.xml`（RHEL/CentOS）
- `/opt/tomcat/conf/tomcat-users.xml`（手动解压）
- `/usr/local/tomcat/conf/tomcat-users.xml`

### 1.2 默认账号（必须清理）

| 用户名 | 默认密码 | 角色 | 风险 |
|---|---|---|---|
| `tomcat` | `tomcat` | manager-gui, manager-script | Manager 后台 |
| `role1` | `tomcat` | role1 | 角色 1 |
| `both` | `tomcat` | tomcat, role1 | 双角色 |
| `admin` | `admin` | admin-gui, manager-gui | Host Manager |

### 1.3 角色权限说明

| 角色 | 权限 | 风险等级 |
|---|---|---|
| `manager-gui` | Manager Web 界面（部署 WAR） | 高 |
| `manager-script` | Manager 脚本接口（curl 部署） | 高 |
| `manager-jmx` | JMX 接口 | 高 |
| `manager-status` | 服务器状态 | 中 |
| `admin-gui` | Host Manager（虚拟主机） | 高 |
| `admin-script` | Host Manager 脚本 | 高 |

## 二、msf 暴力破解（攻击视角）

### 2.1 msf 模块

```bash
msfconsole
use auxiliary/scanner/http/tomcat_mgr_login
set rhosts 192.168.1.131
set rport 8080
set stop_on_success true
set user_file /usr/share/wordlists/tomcat_users.txt
set pass_file /usr/share/wordlists/tomcat_pass.txt
run
```

### 2.2 防御策略

1. **关闭 Manager 应用**（推荐，见下文）
2. **强密码 + 加密存储**
3. **IP 白名单**（只允许 127.0.0.1 访问 Manager）
4. **WAF 拦截爆破**：见 WAF 规则 `tomcat_2`、`brute_1`

## 三、密码加密加固

### 3.1 生成加密密码

```bash
# Linux
$CATALINA_HOME/bin/digest.sh -a SHA-256 your_password

# Windows
%CATALINA_HOME%\bin\digest.bat -a SHA-256 your_password
```

输出示例：
```
your_password:5e884898da28047151d0e56f8dc6292773603d0d6aabbddc...
```

只取冒号后的部分。

### 3.2 修改 tomcat-users.xml

**修改前**（明文）：
```xml
<user username="admin" password="admin@123" roles="manager-gui,admin-gui"/>
```

**修改后**（SHA-256 加密）：
```xml
<user username="admin"
      password="6cc196d2137ff44691d21c0294ed56bc6585c0b1cc6c14c79190cc7ea8429bee$1$b4026248dcaf16e47075558f20f0bb59939e349eaa90ea6d5d4bcc0fc7f9d268"
      roles="manager-gui,admin-gui"/>
```

> 注意：SHA-256 加密存储与明文存储可并存，Tomcat 会自动识别。但加密后即使泄漏 `tomcat-users.xml` 也无法直接拿到明文。

### 3.3 配置 Realm（Tomcat 8.5+ 必须）

**Tomcat 8.5 之前**：
```xml
<!-- server.xml -->
<Realm className="org.apache.catalina.realm.UserDatabaseRealm"
       resourceName="UserDatabase"
       digest="SHA-256"/>
```

**Tomcat 8.5+ 之后**（必须用 CredentialHandler）：
```xml
<Realm className="org.apache.catalina.realm.UserDatabaseRealm"
       resourceName="UserDatabase">
    <CredentialHandler
        className="org.apache.catalina.realm.MessageDigestCredentialHandler"
        algorithm="SHA-256"/>
</Realm>
```

### 3.4 重启验证

```bash
systemctl restart tomcat
# 或
$CATALINA_HOME/bin/shutdown.sh
$CATALINA_HOME/bin/startup.sh

# 访问 Manager 验证（仍用明文密码登录，Tomcat 后台加密比对）
curl -u admin:your_password http://localhost:8080/manager/html
```

## 四、Manager 应用下架（推荐）

如果业务不需要 Tomcat Manager，直接下架最安全。

```bash
cd $CATALINA_HOME/webapps
mv manager manager.disabled
mv host-manager host-manager.disabled
mv docs docs.disabled
mv examples examples.disabled

# 重启
systemctl restart tomcat
```

**验证**：
```bash
curl -u admin:password http://localhost:8080/manager/html
# 应返回 404
```

## 五、最小权限原则（PoLP）

如果必须保留 Manager，遵循最小权限：

### 5.1 只授必要角色

```xml
<!-- 错误：给所有角色 -->
<user username="admin" password="xxx" roles="manager-gui,manager-script,manager-jmx,manager-status,admin-gui"/>

<!-- 正确：只给 GUI（移除 script/jmx 高危接口） -->
<user username="deploy" password="xxx" roles="manager-gui"/>
```

### 5.2 限制访问来源

`$CATALINA_HOME/webapps/manager/META-INF/context.xml`：

```xml
<!-- 默认只允许 127.0.0.1 -->
<Context antiResourceLocking="false" privileged="true">
    <Valve className="org.apache.catalina.valves.RemoteAddrValve"
           allow="127\.\d+\.\d+\.\d+|::1|0:0:0:0:0:0:0:1"/>
</Context>

<!-- 加白名单（如运维网段） -->
<Context antiResourceLocking="false" privileged="true">
    <Valve className="org.apache.catalina.valves.RemoteAddrValve"
           allow="127\.\d+\.\d+\.\d+|10\.10\.10\.\d+"/>
</Context>
```

### 5.3 强密码策略

- 最小长度 12 位
- 包含大小写、数字、特殊字符
- 不含 tomcat、admin、manager 等关键词
- 90 天轮换

## 六、server.xml 审计要点

### 6.1 关闭危险 Connector

```xml
<!-- AJP Connector（Ghostcat CVE-2020-1938 风险） -->
<!-- 非必须则注释 -->
<!--
<Connector port="8009" protocol="AJP/1.3" redirectPort="8443"/>
-->

<!-- 如必须开启，加 secret 与 address 限制 -->
<Connector port="8009" protocol="AJP/1.3" redirectPort="8443"
           address="127.0.0.1"
           secret="<强随机字符串>"
           requiredSecret="true"/>
```

### 6.2 隐藏版本号

`$CATALINA_HOME/conf/server.xml`：
```xml
<Connector port="8080" protocol="HTTP/1.1"
           server="Apache"
           xpoweredBy="false"/>
```

### 6.3 禁用自动部署

```xml
<Host name="localhost" appBase="webapps"
      unpackWARs="true"
      autoDeploy="false">   <!-- 改为 false -->
```

## 七、培训案例加固示例

### 7.1 加固前

```bash
cat $CATALINA_HOME/conf/tomcat-users.xml
```

```xml
<tomcat-users>
    <user username="tomcat" password="tomcat" roles="tomcat,manager-gui"/>
    <user username="admin" password="admin" roles="manager-gui,manager-script,admin-gui"/>
</tomcat-users>
```

**问题**：
1. 默认账号 tomcat/tomcat、admin/admin 仍在
2. 明文密码
3. admin 拥有所有高危角色

### 7.2 加固后

```xml
<tomcat-users>
    <!-- 注释默认账号 -->
    <!-- <user username="tomcat" password="tomcat" roles="tomcat,manager-gui"/> -->
    <!-- <user username="admin" password="admin" roles="manager-gui,manager-script,admin-gui"/> -->

    <!-- 新建最小权限账号 + SHA-256 加密 -->
    <user username="deploy"
          password="6cc196d2137ff44691d21c0294ed56bc6585c0b1cc6c14c79190cc7ea8429bee$1$b4026248dcaf16e47075558f20f0bb59939e349eaa90ea6d5d4bcc0fc7f9d268"
          roles="manager-gui"/>
</tomcat-users>
```

server.xml 添加 CredentialHandler：
```xml
<Realm className="org.apache.catalina.realm.UserDatabaseRealm"
       resourceName="UserDatabase">
    <CredentialHandler
        className="org.apache.catalina.realm.MessageDigestCredentialHandler"
        algorithm="SHA-256"/>
</Realm>
```

### 7.3 验证

```bash
# 默认账号应失败
curl -u tomcat:tomcat http://localhost:8080/manager/html  # 401
curl -u admin:admin http://localhost:8080/manager/html    # 401

# 新账号应成功
curl -u deploy:your_password http://localhost:8080/manager/html  # 200

# msf 爆破应失败
msf > use auxiliary/scanner/http/tomcat_mgr_login
msf > run  # 全部失败
```

## 八、相关加固项

| 加固项 ID | 作用 |
|---|---|
| `tomcat_user_harden` | 默认账号清理 + 密码加密提示 |
| `tomcat_mgr_remove` | Manager/Host-Manager 应用下架 |
| `web_server` | 隐藏服务器版本号 |

## 九、参考

- 培训 PDF：应急响应.pdf（Tomcat 账户安全检查、Tomcat 账号/密码策略加固章节）
- Tomcat 官方文档：https://tomcat.apache.org/tomcat-9.0-doc/realm-howto.html
- Ghostcat CVE-2020-1938：https://tomcat.apache.org/security-9.html
