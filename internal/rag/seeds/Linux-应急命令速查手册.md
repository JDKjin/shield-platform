# Linux 应急命令速查手册

> 应急响应高频命令的一页速查，按「系统 → 进程 → 网络 → 账号 → 文件 → 日志 → 防火墙」组织。全部命令直接可执行，比赛与日常通用。

## 一、系统信息

```bash
uname -a                      # 内核与系统
cat /etc/os-release          # 发行版
uptime                       # 运行时间/负载
free -h                      # 内存
df -h                        # 磁盘
ls -l /proc/1/exe            # init 是否被替换
```

## 二、进程排查

```bash
ps -ef                       # 全进程
ps -eo pid,ppid,user,%cpu,etime,args --sort=-%cpu | head -20   # CPU 排序
top -bn1 | head -20          # 瞬时快照
ls -l /proc/*/exe            # 定位进程真实二进制
cat /proc/<pid>/cwd          # 进程工作目录
cat /proc/<pid>/environ      # 进程环境变量（可疑泄露）
ls /proc/<pid>/fd            # 打开的文件描述符
```

## 三、网络排查

```bash
ss -tlnp                     # 监听端口
ss -tnp                      # 已建立连接
ss -tn state established | wc -l   # 连接数
netstat -antlp 2>/dev/null   # 备用
lsof -i :8080                # 指定端口占用
ip a / ip route              # 网卡与路由
arp -a                       # ARP 表（横向扫描痕迹）
```

## 四、账号与登录

```bash
cat /etc/passwd              # 用户
awk -F: '$3==0{print}' /etc/passwd   # UID 0
awk -F: '($2==""){print}' /etc/shadow  # 空口令
last / lastlog               # 登录记录
grep 'Accepted' /var/log/secure      # 成功登录
grep 'Failed' /var/log/secure | tail -50  # 爆破
```

## 五、文件与完整性

```bash
find /var/www -type f -mmin -180 -ls   # 近期新增/修改
find / -perm -4000 -ls 2>/dev/null     # SUID 文件
find /tmp /var/tmp /dev/shm -type f -exec ls -la {} \;  # 临时目录
md5sum <文件>                   # 哈希比对基线
chattr +i /var/www/html/index.php      # 加不可变
lsattr /var/www/html/           # 查看属性
```

## 六、日志与历史

```bash
ls -la /var/log/                 # 日志目录
tail -n 100 /var/log/secure      # 认证日志
tail -n 100 /var/log/messages    # 系统日志
grep -iE 'error|denied' /var/log/nginx/error.log | tail -50
history                         # 当前用户历史（攻击者可能已清）
cat /root/.bash_history 2>/dev/null
```

## 七、计划任务与启动项

```bash
crontab -l; ls -la /var/spool/cron/
cat /etc/crontab /etc/cron.d/*
ls -la /etc/cron.daily/ /etc/cron.hourly/
systemctl list-timers --all
systemctl list-unit-files | grep -iE 'service' | grep -vE '^proc|^sys|^dev'
cat /etc/rc.d/rc.local /etc/rc.local
grep -nE 'wget|curl|/dev/tcp|base64' /etc/profile /etc/profile.d/*.sh ~/.bashrc
```

## 八、防火墙操作

```bash
iptables -L -n --line-numbers     # 查看
iptables -I INPUT -s <IP> -j DROP # 封 IP
iptables -I INPUT -p tcp --dport <端口> -j DROP  # 封端口
iptables -I OUTPUT -d <IP> -j DROP  # 封出站（断回连）
iptables -F                        # 清空（慎用，会放行所有）
systemctl status firewalld / ufw status
```

## 九、取证与打包

```bash
mkdir -p /root/evidence
cp -a <可疑文件> /root/evidence/
stat <文件>                       # 时间戳
# 打包关键日志与证据
tar czf /root/evidence.tar.gz /root/evidence /var/log/secure /var/log/nginx
sha256sum /root/evidence.tar.gz
```
