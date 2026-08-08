# 数据库与中间件加固（MySQL + Tomcat + Nginx/Apache + Redis）

> 覆盖 CentOS7_Mysql 靶机的 MySQL 与常见中间件。先备份配置再修改，改完必须重启并验证业务可用。

## MySQL root 远程访问限制（只允许本地登录）

- 查看 root 来源：`mysql -uroot -p -e "SELECT user,host FROM mysql.user WHERE user='root';"`
- 只允许本机：`mysql -uroot -p -e "UPDATE mysql.user SET host='localhost' WHERE user='root'; FLUSH PRIVILEGES;"`
- 业务需要远程则建专用账号：`GRANT SELECT,INSERT,UPDATE,DELETE ON 库名.* TO 'app'@'192.168.%' IDENTIFIED BY '强密码';`

## MySQL 删除匿名账户与空口令
- 查匿名/空口令：`SELECT user,host,authentication_string FROM mysql.user;`（user='' 或密码为空即异常）
- 删除匿名账户：`DELETE FROM mysql.user WHERE user=''; FLUSH PRIVILEGES;`
- 全账号强制改密：`ALTER USER 'user'@'host' IDENTIFIED BY '强密码';`

## MySQL 修改默认端口与弱口令
- 改端口：/etc/my.cnf `[mysqld]` 段加 `port=33066`，`systemctl restart mysqld`
- 修改弱口令：`ALTER USER 'root'@'localhost' IDENTIFIED BY '强密码'; FLUSH PRIVILEGES;`
- 验证监听：`ss -antp | grep mysql`

## MySQL 关闭 local_infile
- 临时关闭：`SET GLOBAL local_infile=0;`
- 永久关闭：/etc/my.cnf `[mysqld]` 段加 `local-infile=0` 后重启
- 验证：`SHOW VARIABLES LIKE 'local_infile';`（应返回 OFF）

## MySQL 权限最小化与 GRANT 复查
- 查看全部用户：`SELECT user,host FROM mysql.user;`
- 查看指定用户权限：`SHOW GRANTS FOR 'user'@'host';`
- 撤销多余权限：`REVOKE ALL ON 库名.* FROM 'user'@'host';`；删除无用账号：`DROP USER 'user'@'host';`；原则：不授 FILE/SUPER/PROCESS，业务库只给增删改查

## MySQL my.cnf 关键配置
- 完全禁止网络（本机专用）：`skip-networking`
- 绑定内网：`bind-address=127.0.0.1`（或业务网段 IP）
- 安全项：`symbolic-links=0`、`local-infile=0`；修改后重启并验证：`SHOW VARIABLES LIKE 'skip_networking';`

## MySQL 日志开启
- 错误日志：`log-error=/var/log/mysqld.log`；慢查询：`slow_query_log=1`、`slow_query_log_file=/var/log/mysql-slow.log`、`long_query_time=2`
- 关闭通用日志：`general_log=0`
- 验证：`SHOW VARIABLES LIKE 'slow_query_log';`

## MySQL 补丁升级与备份恢复
- 升级：`yum update mysql mysql-server`；版本：`mysql -V`；升级后 `mysql_upgrade -uroot -p`
- 全库备份：`mysqldump -uroot -p --all-databases --single-transaction --routines --triggers > /backup/all_$(date +%F).sql`
- 恢复：`mysql -uroot -p < /backup/all_xxx.sql`；加固前先做全量备份，备份文件 `chmod 600`

## Tomcat manager 后台弱口令加固
- 修改 /conf/tomcat-users.xml，删除默认账号并设强密码：`<user username="admin" password="强密码" roles="manager-gui,admin-gui"/>`
- 不需要管理后台则删除 manager / host-manager 应用目录
- 重启后立即用默认口令（tomcat/tomcat 等）测试是否已失效

## Tomcat 关闭默认示例应用
- 删除示例应用：`rm -rf webapps/examples webapps/docs webapps/manager webapps/host-manager`（或改名 .bak）
- 查看已部署应用：`ls webapps/`
- 重启后访问示例路径应 404

## Tomcat AJP 8009 端口加固
- 检查监听：`ss -antp | grep 8009`
- 默认注释 /conf/server.xml 中 `<Connector port="8009" protocol="AJP/1.3"/>`
- 若需要 AJP，仅监听本机并加密钥：`address="127.0.0.1" secretRequired="true"`
- 重启后用 `ss` 确认 8009 不再对外暴露

## Tomcat server.xml 加固
- 改默认 Shutdown 口令：`<Server port="8005" shutdown="SHUTDOWN">` 改为复杂随机串
- 连接器限流：`maxThreads="200" acceptCount="100" connectionTimeout="20000"`
- 关闭 TRACE：Connector 加 `allowTrace="false"`；校验：`bin/configtest.sh`

## Tomcat 禁止目录列表与版本隐藏
- /conf/web.xml 中 default servlet 的 `listings` 参数设为 `false`
- 隐藏版本：覆盖 lib/catalina.jar 内 ServerInfo.properties 的 server.info（或升级到最新版）
- 验证：`curl -I http://IP:8080/` 看 Server 头不带完整版本

## Tomcat HTTPS 配置要点
- 生成密钥库：`keytool -genkeypair -alias tomcat -keyalg RSA -keystore conf/keystore.jks -storepass 强密码`
- server.xml 增加 HTTPS Connector：`<Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol" SSLEnabled="true" keystoreFile="conf/keystore.jks" keystorePass="强密码"/>`
- 放行 8443 并验证：`curl -k https://IP:8443/`

## Nginx 隐藏版本与禁止目录遍历
- 隐藏版本：http 段加 `server_tokens off;`
- 禁止目录列表：`autoindex off;`（location 或 server 段）
- 限制上传：`client_max_body_size 10m;`；校验重载：`nginx -t && systemctl reload nginx`

## Nginx 危险配置与日志
- 限制请求方法：`limit_except GET POST { deny all; }`
- 日志开启：`access_log /var/log/nginx/access.log;` 与 `error_log /var/log/nginx/error.log warn;`
- 上传目录禁止执行：location 中禁用 php 执行或移出 web 根

## Apache 隐藏版本与目录遍历
- 隐藏版本：`ServerTokens Prod`、`ServerSignature Off`
- 禁止目录列表：`<Directory "/var/www/html"> Options -Indexes </Directory>`
- 重载验证：`apachectl -t && systemctl reload httpd`

## Apache 日志与危险模块
- 日志：`CustomLog /var/log/httpd/access_log combined`、`ErrorLog /var/log/httpd/error_log`
- 关闭暴露模块：注释 LoadModule 中 mod_info、mod_status（RHEL）或 `a2dismod status`（Debian）
- php 危险函数：php.ini 设 `disable_functions=exec,system,passthru,shell_exec,proc_open,popen`

## Redis 绑定地址与密码（防未授权入侵）
- 编辑 redis.conf：`bind 127.0.0.1`、`requirepass 强密码`、`protected-mode yes`
- 重启：`systemctl restart redis`
- 验证：`redis-cli -a 强密码 ping` 返回 PONG；无密码访问应报 NOAUTH

## Redis 危险命令禁用重命名
- redis.conf 重命名/禁用危险命令：
  `rename-command CONFIG ""`、`rename-command FLUSHALL ""`、`rename-command FLUSHDB ""`、`rename-command KEYS ""`
- 或改为复杂名：`rename-command CONFIG "c0nfig_x99"`
- 重启后验证：`redis-cli config get dir` 报 unknown command

## Redis 保护模式与日志
- 确认 `daemonize yes`、`protected-mode yes`，仅内网可达
- 开启日志：`logfile /var/log/redis/redis-server.log`、`loglevel notice`
- 排查攻击痕迹：`grep -iE "denied|attack" /var/log/redis/redis-server.log`

## MySQL 忘记 root 密码重置（skip-grant-tables）
- 适用于靶机 MySQL root 密码被改/遗忘、被攻击者篡改后需要恢复控制权
- 步骤：
  1. 停服务：`systemctl stop mysqld`（或 `service mysql stop`）
  2. 免认证启动：`mysqld_safe --skip-grant-tables &`（或改 /etc/my.cnf 临时加 `skip-grant-tables`）
  3. 重置密码：`mysql -uroot -e "FLUSH PRIVILEGES; ALTER USER 'root'@'localhost' IDENTIFIED BY '新强密码';"`
  4. 停掉免认证模式：kill mysqld 进程，删除 my.cnf 中临时项，`systemctl start mysqld`
  5. 验证：`mysql -uroot -p新密码 -e "SELECT 1;"`
- 注意：重置后立即同步修改应用配置中的数据库口令，并检查是否还有其他被篡改的账号/授权
