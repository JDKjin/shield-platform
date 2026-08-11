# PHP WebShell 与内存马防御手册

> PHP 靶机是 AWD 主战场，WebShell 是红队与自动化脚本的标配。本手册覆盖一句话木马、不死马、内存马的识别、查杀与源头防护。配合「WebShell 检测」「Web 日志分析」手册使用。

## 一、一句话木马识别

常见加密/混淆载荷特征（扫描关键字）：

```bash
# 高危函数与参数
grep -rlE 'eval\(|assert\(|base64_decode|gzinflate|str_rot13|create_function|\$_POST|\$_REQUEST|\$_GET|\$_COOKIE|system\(|exec\(|passthru|shell_exec|popen\(' /var/www/html/

# 免杀马常用变形
grep -rlE 'gzuncompress|gzdecode|pack\("H|\.\.\.chr\(|\\x[0-9a-f]{2}\\x' /var/www/html/

# 隐藏马（文件名伪装）
find /var/www/html -type f \( -name '*.php*' -o -name '.*' \) -mmin -120
find /var/www/html -type f -name '*.php' -size -2k -exec ls -la {} \;
```

## 二、不死马（常驻内存马）

不死马原理：把 PHP 代码注入到内存中常驻进程，文件可被删但请求即重生。特征：

```bash
# 1. 进程里常驻的 php 子进程（php-fpm 每请求重生）
ps -ef | grep -E 'php|php-fpm' | grep -v grep

# 2. 源文件常是短暂文件：requests 请求后文件即删
# 3. 常配合 crontab/startup 拉起
crontab -l | grep -E 'php|curl|wget'

# 4. 检测不死马常用手段：发一个请求触发后立刻查
curl -s http://127.0.0.1/xxx.php >/dev/null; ps -ef | grep php
```

处置不死马：

1. 断源：先清 crontab / 启动项，阻止拉起。
2. 重启承载进程：`systemctl restart php-fpm` 或 `pkill -9 php-fpm`（内存马随 fpm 进程消亡而消失）。
3. 删除入口文件（如果存在）并锁定：`chattr +i`。
4. 立即全目录复扫，确认无残留文件与定时任务。

## 三、Java 内存马（Filter/Servlet/Listener 型）

Tomcat 场景，不落盘、重启失效，日志和文件系统看不到：

- 特征：`curl -sI http://127.0.0.1:8080/` 后 `jmap` 无法直接看；管理接口被新增的 Filter。
- 排查手段（进阶）：`jps` 定位 Java 进程 → 用 arthas 等查看已注册的 Filter/Servlet 类名（对比基线）。
- 防御优先级：**防落入口**——关闭 Tomcat manager 未授权、防反序列化/上传 war，比事后发现更有效。

## 四、批量查杀流程（比赛场景）

```bash
# 1. 全目录高危函数扫描
grep -rlE 'eval\(|assert\(|base64_decode|gzinflate|\$_POST' /var/www/html/

# 2. 短文件名 / 近期新增文件交叉核对
find /var/www/html -type f -name '*.php' -mmin -180 -ls

# 3. 逐一确认：高危文件先 diff 开局基线，未见过的标记为可疑
# 4. 可疑文件先 cp 到取证目录再移除 Web 可访问权限（chmod 000 或移出）
# 5. 清理后重启 php-fpm，防不死马残留
systemctl restart php-fpm
```

> 平台面板「实时监测」的 WebShell 检测与「防御作战」的 Web 目录监控可自动发现大多数文件型马，配合 `rollback_web` 一键回滚干净快照。

## 五、源头防护（治本）

1. **上传目录禁执行**：Nginx `location ~* \.php$` 排除 `uploads/`，Apache `<FilesMatch>` 拒绝 php 在 uploads 下解析。
2. **危险函数禁用**：`disable_functions = system,exec,passthru,shell_exec,popen,proc_open`（/etc/php.ini）。
3. **短文件上传拦截**：WAF 规则覆盖图片马（文件头校验、`.php5/.phtml/.htaccess` 后缀）。
4. **只读 Web 根目录**：非上传目录 `chmod 555`，`chattr +i` 关键入口文件。
5. **代码层**：上传校验后缀+内容、文件名白名单重命名，禁止用户可控内容进入可执行目录。
