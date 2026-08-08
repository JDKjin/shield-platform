# Linux 应急响应手册

## 一、排查思路
1. 先断网/隔离，防止横向扩散
2. 按 进程 -> 网络 -> 文件 -> 登录 -> 计划任务 -> 自启动 的顺序排查
3. 所有排查结果留档，避免重复排查

## 二、进程排查
- 查看异常进程：`ps aux --sort=-%cpu | head -20`
- 查看网络连接：`netstat -antp` 或 `ss -antp`
- 重点看：CPU 占用高、名字伪装（systemd 带空格/特殊字符）、PPID 为 1 的孤儿进程
- 查看进程打开的文件：`ls -l /proc/<pid>/exe`、`ls -l /proc/<pid>/cwd`
- 查看进程命令行：`cat /proc/<pid>/cmdline | tr '\0' ' '`

## 三、网络后门排查
- 外连可疑端口：4444、5555、6666、7777、8888、9999、31337、12345
- `lsof -i` 查看所有网络连接
- 反向 shell 特征：bash、sh、nc、python 进程带 `-c` 且连接外网
- 检查 `ss -antp | grep -v LISTEN | grep -v 127.0.0.1` 找出外部连接

## 四、持久化排查
- crontab：`crontab -l`、`ls -la /etc/cron.d/ /var/spool/cron/`
- 开机自启：`ls -la /etc/init.d/ /etc/rc.d/`、检查 rc.local
- systemd：`ls -la /etc/systemd/system/`、`systemctl list-units --type=service --state=running | grep -v systemd`
- 环境变量：`cat /etc/ld.so.preload`、检查 `/etc/ld.so.conf.d/`
- bash 后门：检查 `/etc/profile`、`~/.bashrc`、`~/.bash_profile`、`/root/.ssh/authorized_keys`
- SSH 后门：检查 `authorized_keys` 是否被添加、`sshd_config` 是否被修改
- 内核模块：`lsmod | grep -i -E 'backdoor|shell|rootkit'`

## 五、WebShell 排查
- 特征：eval、assert、base64_decode、system、shell_exec、exec、passthru、$_POST、$_REQUEST
- 常见位置：web 目录下含图片马（文件头 jpg 尾 PHP）、.php 后缀的图片文件
- 查找命令：`grep -r -l -E 'eval|assert|base64_decode|shell_exec' /var/www/html/`
- 按时间查找近期文件：`find /var/www/html -name "*.php" -mtime -7`

## 六、账号排查
- UID=0 的非 root 用户：`awk -F: '$3==0 {print $1}' /etc/passwd`
- 空密码用户：`awk -F: '($2=="") {print $1}' /etc/shadow`
- 最近登录：`last`、`lastlog`
- 登录失败记录：`grep "Failed password" /var/log/auth.log | tail -20`
- 查看 sudoers：`cat /etc/sudoers`

## 七、文件排查
- 近期修改的可疑文件：`find / -mtime -3 -type f \( -name "*.so" -o -name "*.sh" -o -name "*.py" \) 2>/dev/null`
- SUID 文件：`find / -perm -4000 -type f 2>/dev/null`
- 隐藏目录：`ls -la /tmp /var/tmp /dev/shm`
- 检查 /tmp 下近期文件：`find /tmp -mtime -1`

## 八、日志分析
- auth.log：`grep -iE 'accepted|failed|session opened' /var/log/auth.log`
- 系统日志：`journalctl -u sshd --since today`
- 检查历史命令：`cat ~/.bash_history | tail -50`、`cat /root/.bash_history`
