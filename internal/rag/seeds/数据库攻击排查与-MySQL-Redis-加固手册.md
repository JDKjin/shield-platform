# 数据库攻击排查与加固手册（MySQL / Redis）

> 能源防御赛靶机数据库常被打点：MySQL 弱口令与 UDF 提权、Redis 未授权写公钥/计划任务是两大高频入口。本手册覆盖排查、加固与取证。

## 一、MySQL 排查

```bash
# 1. 登录方式审计：本地 socket 还是远程 TCP
netstat -tlnp | grep 3306   # 只留 127.0.0.1 更安全
ss -tlnp | grep 3306

# 2. 空口令 / 弱口令账号
mysql -uroot
SELECT user, host, authentication_string FROM mysql.user WHERE authentication_string='' OR authentication_string IS NULL;
# 已知 hash 比对弱口令：password() 生成的 41 位 hash 可离线爆破

# 3. 异常权限（UDF 提权前置）
SHOW VARIABLES LIKE 'plugin_dir';
SELECT * FROM mysql.func;                -- 查自定义函数（sys_exec/lib_mysqludf_sys 特征）
SELECT user,host,Super_priv,File_priv FROM mysql.user;  -- File_priv=Y 可读文件写 webshell

# 4. 日志里找注入/爆破
grep -E 'Access denied|using password' /var/log/mysql/error.log
mysql -uroot -e "SHOW VARIABLES LIKE 'general_log%';"    # 开 general_log 记录全部 SQL
```

## 二、MySQL 加固

```sql
-- 改 root 强口令（先确认自己有权限，别锁死）
ALTER USER 'root'@'localhost' IDENTIFIED BY '强随机口令';
-- 删除匿名/远程空口令账号
DELETE FROM mysql.user WHERE user='' OR (host<>'localhost' AND authentication_string='');
-- 删除风险用户（演示账号）
DROP USER 'test'@'%';
-- 收紧远程访问：仅允许本机
RENAME USER 'root'@'%' TO 'root'@'localhost';
-- 应用权限
FLUSH PRIVILEGES;
```

```bash
# 配置层：仅监听本机 + 关闭 general_log（降低被翻日志风险）
sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' /etc/my.cnf
systemctl restart mysqld
# 禁用危险函数 / 收紧 UDF（用 secure_file_priv 限制读写目录）
echo 'secure-file-priv=/tmp' >> /etc/my.cnf.d/mysql.cnf
```

## 三、Redis 排查

```bash
# 1. 是否暴露在网口（默认 6379 未授权可连）
ss -tlnp | grep 6379
redis-cli -h <本机IP> -p 6379 ping    # 返回 PONG = 未授权

# 2. 查看配置是否开了保护模式
redis-cli config get protected-mode
redis-cli config get requirepass        # 密码是否为空

# 3. 检查被写入的计划任务 / 公钥（Redis 写文件攻击痕迹）
ls -la /var/spool/cron/ /root/.ssh/authorized_keys
# 检查 Redis 数据中的恶意 key（dir/dbfilename 被改）
redis-cli config get dir
redis-cli config get dbfilename
```

## 四、Redis 加固

```bash
# 1. 设强口令
redis-cli config set requirepass '强随机口令'
# 持久化到配置文件
echo 'requirepass 强随机口令' >> /etc/redis.conf

# 2. 关闭危险命令（重命名 config/命令防止被利用）
# /etc/redis.conf 中追加：
# rename-command CONFIG ""
# rename-command EVAL ""

# 3. 禁外部访问 + 开保护模式
echo 'bind 127.0.0.1' >> /etc/redis.conf
echo 'protected-mode yes' >> /etc/redis.conf
systemctl restart redis

# 4. 清被写入的计划任务/公钥后，清除 Redis 中残留恶意数据
redis-cli -a '口令' --scan | while read k; do redis-cli -a '口令' del "$k"; done
```

## 五、数据库攻击后的取证要点

1. **定位写入路径**：被 Redis 写入的 crontab/authorized_keys 先 `cp` 到 `/root/evidence/`，记录文件 mtime。
2. **查来源 IP**：`grep 3306 /var/log/secure`、`ss -tnp` 连接记录、数据库 error log 中的连接来源。
3. **还原时间线**：`ls -l /etc/redis.conf /var/spool/cron/` 等文件 mtime 与日志比对，锁定攻击窗口。
4. **清理后重扫**：加固完成后再次 `redis-cli ping`、`mysql -u root` 空口令测试，确认入口已关。
