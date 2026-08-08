# 加固操作速查清单

## 一、SSH 安全
```
# 备份配置
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# 禁用 root 远程登录
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config

# 禁用密码登录（保留密钥）
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config

# 禁用空密码
sed -i 's/^#\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config

# 重启服务
systemctl restart sshd || service ssh restart
```

## 二、账号安全
```
# 锁定异常账号
usermod -L <username>

# 查看 UID=0 用户
awk -F: '$3==0 {print $1}' /etc/passwd

# 修改密码
passwd <username>

# 删除空密码用户
awk -F: '($2=="") {print $1}' /etc/shadow | while read u; do passwd -l $u; done
```

## 三、防火墙
```
# 安装/启动
systemctl start firewalld || ufw enable || service iptables start

# 仅允许必要端口（示例）
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```

## 四、Web 目录权限
```
# 目录 755，文件 644
find /var/www/html -type d -exec chmod 755 {} \;
find /var/www/html -type f -exec chmod 644 {} \;

# 移除写权限
chmod -R a-w /var/www/html
```

## 五、cron 清理
```
# 查看所有 cron
crontab -l
ls -la /etc/cron.d/ /var/spool/cron/

# 清理可疑任务
crontab -r   # 清空当前用户 crontab
```

## 六、临时目录清理
```
# 清理 /tmp /var/tmp /dev/shm 近期可执行文件
find /tmp /var/tmp /dev/shm -type f -mmin -60 -exec rm -f {} \; 2>/dev/null
```

## 七、危险函数禁用（php.ini）
```
# 编辑 php.ini 添加
disable_functions = exec,shell_exec,system,passthru,proc_open,popen,pcntl_exec
```

## 八、关键文件保护（chattr）
```
# 防篡改 .user.ini 和 waf.php
chattr +i /var/www/html/.user.ini
chattr +i /var/www/html/waf.php
```
