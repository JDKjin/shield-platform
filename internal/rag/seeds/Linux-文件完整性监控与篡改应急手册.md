# Linux 文件完整性监控与篡改应急手册

> Web 目录/配置文件被篡改是防御赛最常见的丢分点。监控思路：开局建基线（hash 快照），轮询比对发现变更立即告警，配合备份回滚恢复业务。

## 一、开局建基线（黄金时间做）

```bash
# 1. Web 目录文件清单与 hash 基线
find /var/www/html -type f -exec md5sum {} \; | sort -k2 > /root/baseline-web.md5
# 2. 关键配置文件基线
for f in /etc/passwd /etc/shadow /etc/crontab /etc/ssh/sshd_config; do md5sum "$f"; done > /root/baseline-etc.md5
# 3. 监听端口与进程基线（对照用）
ss -tlnp > /root/baseline-ports.txt
ps -ef > /root/baseline-procs.txt
# 4. 定时任务基线
crontab -l > /root/baseline-cron.txt 2>/dev/null
```

## 二、定期比对（发现篡改）

```bash
# 与基线比对：输出新增/删除/变更文件
find /var/www/html -type f -exec md5sum {} \; | sort -k2 | diff /root/baseline-web.md5 -
# 只看最近被改的文件（绕过基线）
find /var/www/html -type f -mmin -30
# 校验系统包文件完整性（CentOS）
rpm -Va 2>/dev/null | head -30
# Ubuntu 校验
debsums 2>/dev/null | grep -v OK | head
```

> 面板平台的「防御作战」模块内置 Web 目录监控与告警，命中文件变更即上报，可在面板直接看到，无需手工轮询。

## 三、发现篡改后的处置（先取证后恢复）

```bash
# 1. 取证：被改文件复制到隔离目录，记录时间戳
mkdir -p /root/evidence
cp -a /var/www/html/<被改文件> /root/evidence/
stat /var/www/html/<被改文件>

# 2. 定位来源：日志里找写该文件的请求
grep '<被改文件名>' /var/log/nginx/access.log /var/log/apache2/access.log 2>/dev/null

# 3. 回滚：用开局备份恢复
tar xzf /root/backup.tar.gz -C /  # 或按文件恢复
cp /root/evidence/正常版本.conf /etc/xxx.conf

# 4. 清理被注入的代码：回滚后再 grep 一遍确认无残留
grep -rlE 'eval\(|base64_decode|system\(' /var/www/html/
```

## 四、防止被篡改的纵深手段

1. **目录只读**：Web 目录 `chmod 555`，仅上传目录可写且禁执行。
2. **文件防篡改**：关键文件设 `chattr +i` 不可变属性（防删除/改写，`lsattr` 查看）。
   ```bash
   chattr +i /var/www/html/index.php
   lsattr /var/www/html/
   ```
3. **写文件被拦截**：配合 WAF 拦截上传写 Web 根目录的请求。
4. **自动回滚**：防御作战开启 Web 目录监控后，配合 `backup_web` / `rollback_web` 指令在面板一键恢复。

## 五、收尾验证

1. 回滚后 `curl -I` 业务 200 正常。
2. 重新生成基线快照（被恶意改的文件若被误当正常，先确认内容干净）。
3. 确认篡改来源已封（来源 IP、漏洞入口），否则下轮还会被改。
