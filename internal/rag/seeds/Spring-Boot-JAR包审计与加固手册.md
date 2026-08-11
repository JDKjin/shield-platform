# Spring Boot JAR 包审计与加固手册

> 培训内容深化整理：JAR 包结构、配置审计、漏洞依赖识别、解包加固流程。
> 适用场景：综合防御竞赛靶机 Java 应用审计、Shiro/Actuator 漏洞应急。

## 一、JAR 包核心结构

Spring Boot 可执行 JAR 包内部分三层：

| 目录 | 作用 | 审计优先级 |
|---|---|---|
| `META-INF/MANIFEST.MF` | 启动信息（Main-Class / Start-Class） | 高 |
| `org/springframework/boot/loader` | Spring Boot 启动器代码（非业务） | 低 |
| `BOOT-INF/classes` | 项目自身代码与配置 | **最高** |
| `BOOT-INF/lib` | 第三方依赖 JAR | **高** |

### 关键文件清单（必看）

```
BOOT-INF/classes/application.properties   # 端口、上传、下载、Actuator 暴露
BOOT-INF/classes/com/<pkg>/controller/    # 接收用户请求，漏洞入口
BOOT-INF/classes/com/<pkg>/shiro/         # 认证配置（Shiro key）
BOOT-INF/classes/templates/               # HTML 模板（XSS/模板注入面）
BOOT-INF/lib/shiro-*.jar                  # 反序列化漏洞版本
BOOT-INF/lib/fastjson-*.jar               # autoType 反序列化
BOOT-INF/lib/log4j-core-*.jar             # Log4Shell
BOOT-INF/lib/commons-collections-*.jar    # 反序列化链
```

## 二、MANIFEST.MF 字段识别

```manifest
Main-Class: org.springframework.boot.loader.JarLauncher   # Spring Boot 启动器
Start-Class: com.example.doctoolkit.DocToolkitApplication  # 业务启动类
Implementation-Version: 0.0.1-SNAPSHOT
```

- `Main-Class` 永远是 `JarLauncher`（Spring Boot 提供，无需审计）
- `Start-Class` 是业务入口，决定审计起点

## 三、application.properties 审计清单

### 高危配置示例

```properties
server.port=8080                                          # 端口
spring.servlet.multipart.max-file-size=50MB               # 上传大小（>10MB 需关注）
file.staticAccessPath=/download/**                        # 下载路径（任意文件下载？）
management.endpoints.web.exposure.include=*               # ★ Actuator 全暴露
management.endpoints.web.exposure.exclude=                # ★ 排除项为空
```

### 审计要点

| 配置项 | 风险 | 加固建议 |
|---|---|---|
| `exposure.include=*` | heapdump/env 泄漏 | 改 `health,info` |
| `exposure.exclude` 为空 | 全端点可访问 | 加 `env,heapdump,threaddump` |
| `multipart.max-file-size` > 50MB | DoS、上传大马 | 限制到 5MB |
| `staticAccessPath=/download/**` | 任意文件下载 | 校验路径白名单 |
| 出现 `shiro.key` / `rememberMe` | 默认 key 风险 | 轮换 key |
| `database.password` 明文 | 凭证泄漏 | 走环境变量 |

## 四、第三方依赖漏洞速查

| 依赖 | 漏洞版本 | CVE / 风险 |
|---|---|---|
| shiro-core | < 1.7.1 | CVE-2016-4437 反序列化 RCE |
| shiro-core | < 1.11.0 | CVE-2022-32532 路径绕过 |
| fastjson | < 1.2.83 | autoType RCE |
| fastjson | < 1.2.68 | 多个 gadget 链 |
| log4j-core | < 2.17.1 | CVE-2021-44228 Log4Shell |
| commons-collections | <= 3.2.1 | InvokerTransformer 链 |
| snakeyaml | < 1.31 | 反序列化 RCE |
| spring-cloud-gateway | < 3.1.1 | CVE-2022-22947 |
| spring-cloud-function | < 3.2.3 | CVE-2022-22963 SpEL |

## 五、JAR 解包 / 修改 / 重封流程（核心加固技能）

```bash
# 1. 解包（保留 manifest 顺序）
mkdir app_unpack
cd app_unpack
unzip -o ../app.jar

# 2. 审计配置
cat BOOT-INF/classes/application.properties
ls BOOT-INF/lib/ | grep -iE 'shiro|fastjson|log4j'

# 3. 修改配置（以 Actuator 为例）
sed -i 's/management.endpoints.web.exposure.include=\*/management.endpoints.web.exposure.include=health,info/' \
  BOOT-INF/classes/application.properties
echo 'management.endpoints.web.exposure.exclude=env,heapdump,threaddump,mappings,beans,configprops,loggers' \
  >> BOOT-INF/classes/application.properties

# 4. Shiro key 轮换（用 jd-gui 审计定位）
#    jd-gui 打开 JAR，搜索 setCipherKey / rememberMeManager
#    替换为 16 字节随机 Base64
java -cp . org.apache.shiro.codec.Base64 < /dev/urandom | head -c 24

# 5. 重封（注意 c0fm 的 0 = 不压缩，避免 Spring Boot Loader 报错）
jar c0fm ./app_new.jar META-INF/MANIFEST.MF -C . .

# 6. 部署替换
mv app.jar app.jar.bak
mv app_new.jar app.jar
systemctl restart <app-service>
```

## 六、jd-gui 代码审计要点

启动：`java -jar jd-gui-1.6.6.jar`

### 搜索关键词（高优先级）

| 关键词 | 漏洞类型 |
|---|---|
| `setCipherKey(` / `setRememberMeManager` | Shiro 默认 key |
| `@RequestMapping("/upload")` + `MultipartFile` | 文件上传 |
| `new File(` + 请求参数 | 任意文件读写 |
| `Runtime.getRuntime().exec(` | 命令执行 |
| `ObjectInputStream` / `readObject` | 反序列化 |
| `process(` / `ScriptEngine.eval` | 表达式注入 |
| `@PreAuthorize` 缺失 | 越权 |
| `SpringApplication.run` 上下文 | Actuator 端点 |

### 无 GUI 替代（CLI 反编译，适合服务器/容器）

jd-gui 是 GUI 弹窗工具，无头环境（SSH 远程、容器、最小化安装）无法使用。以下 CLI 工具功能等价：

#### CFR（推荐，纯 Java，无需安装）

```bash
# 下载 CFR
wget https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar -O /tmp/cfr.jar

# 反编译整个 JAR 到目录
java -jar /tmp/cfr.jar app.jar --outputdir /tmp/app_src/

# 反编译后用 grep 搜索关键漏洞点
grep -rn "setCipherKey\|setRememberMeManager" /tmp/app_src/
grep -rn "Runtime.getRuntime().exec" /tmp/app_src/
grep -rn "@RequestMapping.*upload\|MultipartFile" /tmp/app_src/
grep -rn "ObjectInputStream\|readObject" /tmp/app_src/
```

#### procyon（备选）

```bash
# 下载 procyon
wget https://github.com/mstrobel/procyon/releases/download/v0.6.0/procyon-decompiler-0.6.0.jar -O /tmp/procyon.jar

# 反编译
java -jar /tmp/procyon.jar -jar app.jar -o /tmp/app_src/
```

#### jad（老牌，速度快但兼容性差）

```bash
# Ubuntu 安装
sudo apt install jad -y

# 反编译单个 class
jad -d /tmp/app_src -s .java com/example/Service.class

# 反编译整个 JAR（先解包）
unzip app.jar -d app_unpack/
find app_unpack -name "*.class" | while read f; do
  jad -d /tmp/app_src -s .java "$f" 2>/dev/null
done
```

**新手提示**：CFR 是最推荐的 CLI 反编译工具，对 Java 8+ 语法（lambda、Stream）支持最好，且单个 jar 文件即可运行。

## 七、典型靶机案例（DocToolkit）

PDF 中提到的 DocToolkit-0.0.1-SNAPSHOT.jar 结构：

```
com.example.doctoolkit/
├── controller/
│   ├── user/IndexController        # 首页
│   ├── user/ImageController        # 图片上传/EXIF 解析
│   ├── user/PDFController          # PDF 上传/解析
│   ├── admin/AdminController       # 后台
│   └── test/TestController         # ★ 测试留存（可能未鉴权）
├── parser/{PDFParser, ExifParser}
├── shiro/{ShiroConfig, UserRealm}  # ★ Shiro key 与认证
└── utils/{Crypt, ZipUtils}
```

**风险点**：
1. `controller/test/` 测试接口常未鉴权，可能直接命令执行
2. `shiro/ShiroConfig` 中 `setCipherKey` 若为硬编码默认值 → 反序列化 RCE
3. `application.properties` 中 `exposure.include=*` → heapdump 泄漏 shiro key
4. 图片/PDF 上传接口若未校验文件类型 → 上传 JSP/WebShell

## 八、加固验收

加固后必须验证：
1. `curl http://target:8080/actuator/heapdump` → 应 404
2. `curl http://target:8080/actuator/env` → 应 404
3. `curl http://target:8080/actuator/health` → 正常返回
4. 旧 Shiro payload 失效（rememberMe 反序列化不再触发）
5. 业务功能（上传/下载/登录）正常

## 九、相关加固项

| 加固项 ID | 作用 |
|---|---|
| `java_jar_audit` | 自动扫描 JAR 配置与依赖 |
| `java_actuator_off` | 关闭 Actuator 敏感端点 |
| `java_shiro_key` | Shiro 默认 key 检查 |
| `java_heapdump_clean` | 清理 heapdump 文件 |
| `tomcat_user_harden` | Tomcat 账户加固 |

## 十、参考

- 培训 PDF：jar包(1).pdf
- OWASP: A06 Vulnerable and Outdated Components
- Spring Boot Actuator 官方文档：https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html
