# WebShell 检测与清除指南

## 一、WebShell 常见类型
1. **一句话木马**：`<?php @eval($_POST['cmd']);?>`、`<?php @assert($_REQUEST['x']);?>`
2. **菜刀/蚁剑马**：通常含 `@$_POST`、`eval`、`assert`、`base64_decode`
3. **图片马**：文件头为图片（jpg/png/gif），文件尾或中间夹杂 PHP 代码
4. **加密马**：使用 `eval(gzinflate(base64_decode(...)))` 多层嵌套
5. **内存马**：不落地文件，注入到运行的 PHP/Python/Java 进程中

## 二、静态检测
- PHP 特征命令：
```
grep -r -l -E '(eval|assert|system|shell_exec|exec|passthru)\s*\(' /var/www/html/
grep -r -l -E 'base64_decode|gzinflate|str_rot13|pack\(' /var/www/html/
grep -r -l -E '\$_(POST|GET|REQUEST|COOKIE)\[' /var/www/html/ | xargs grep -l -E 'eval|assert'
```
- 查找近 7 天内新增 PHP 文件：
```
find /var/www/html -name "*.php" -mtime -7 -type f
```
- 查找非标准文件头：`file <文件名>` 检查实际类型
- 查找隐藏文件：`find /var/www/html -name ".*" -type f`
- 查找权限异常文件：`find /var/www/html -perm -002 -type f`（组/其他可写）

## 三、动态检测
- 访问日志特征：
```
grep -iE 'eval|assert|base64|cmd|whoami|id;' /var/log/apache2/access.log
grep -iE 'toolbar|chopper|antSword|caidao' /var/log/nginx/access.log
```
- 检查高频率访问的单文件（蚁剑/冰蝎连接特征）
- 异常 UA：中国菜刀、antSword、ladybug

## 四、清除步骤
1. 记录木马文件路径与内容备份
2. 使用 `mv` 而非 `rm` 移走木马（便于溯源）
3. 检查同目录近期文件，防止多枚马
4. 检查 .user.ini / .htaccess 是否被插入 `auto_prepend_file`
5. 检查 index.php 等入口文件是否被修改
6. 修改所有被攻破的账号密码
7. 排查连接来源 IP 并在防火墙封禁

## 五、防御建议
- 上传目录禁止执行 PHP：Nginx 配置 `location ~* \.(php)$ { deny all; }`
- 使用软 WAF 拦截 eval/assert 等危险函数
- 文件权限收紧：web 目录 755，文件 644，禁止 777
- 定期扫描与日志审计
