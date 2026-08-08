# 容器与 Docker 安全手册

> 手册目标：AWD 场景中靶机可能是"容器里的 Web"，也可能是"Docker 宿主机"。先判断你在哪一层，再决定加固与排查手段。命令面向 CentOS7/Ubuntu 的 Docker Engine。

## 先判断：容器内还是宿主机

```bash
# 容器内特征
ls -la /.dockerenv                # 存在 => 容器内
cat /proc/1/cgroup | grep docker  # 有 docker 字样 => 容器内
hostname                          # 容器内 hostname 通常是短哈希
cat /proc/self/mountinfo | grep overlay
# 宿主机特征：/.dockerenv 不存在；可看到 systemd (PID 1) 为 /sbin/init
ps aux | grep -E "dockerd|containerd|kubelet"
```
- **判断意义**：容器内被入侵 → 优先**隔离容器**；宿主机被入侵 → 全部容器都要排查。两者加固手段完全不同。

## docker.sock 未授权访问

- **概述**：容器把宿主机 `/var/run/docker.sock` 挂载进容器（`-v /var/run/docker.sock:/var/run/docker.sock`），容器内即可调用 Docker API 控制宿主机（挂载宿主根目录提权）。
- **检测特征**：容器内 `ls -l /var/run/docker.sock` 存在；容器内 curl 到 `unix:///var/run/docker.sock/version` 有返回。
- **利用验证（容器内）**：
```bash
# 挂载宿主 / 到新容器并 chroot 提权
docker -H unix:///var/run/docker.sock run -it -v /:/host ubuntu chroot /host
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock exec <host_容器名> id
```
- **加固命令**：
```bash
# 1) 不要把 socket 挂进容器；审查 compose 里所有 -v /var/run/docker.sock
grep -r "docker.sock" /opt/*/docker-compose.yml 2>/dev/null
# 2) 若确需管理，用 tls + 鉴权：docker run -v /var/run/docker.sock ... --privileged 换为
#    最小授权：仅对受信容器挂载，并开启 tlsverify（DOCKER_TLS_VERIFY=1）
# 3) 系统级：为 socket 设置文件权限
chmod 660 /var/run/docker.sock
```

## 容器逃逸：privileged / cap_sys_admin / CVE-2019-5736

### --privileged 逃逸（最常见）
- **检测特征**：容器内 `cat /proc/self/status | grep CapEff` 值为 `0000003fffffffff`（全 1）；`mount` 能挂载宿主设备。
- **利用路径**：`fdisk -l` 找到宿主盘 → `mkdir /tmp/x && mount /dev/sda1 /tmp/x` → 写宿主 `/etc/passwd` 或 `.ssh/authorized_keys` 留后门 → 后续 ssh 登录宿主。
- **加固命令**：
```bash
# 禁止 privileged 容器（Docker daemon.json 或 Kubernetes 准入）
grep -r "privileged: true" /opt /etc 2>/dev/null
# 运行容器时禁用：去掉 --privileged 参数，改用 --cap-drop=ALL --cap-add=NET_BIND_SERVICE
docker run -it --cap-drop=ALL --cap-add=NET_BIND_SERVICE --security-opt no-new-privileges <img>
```

### cap_sys_admin + CVE-2022-0492 / 内核漏洞逃逸
- **检测特征**：`cat /proc/self/status | grep CapEff` 含 `00000000` 中 `cap_sys_admin`（bit 21，十六进制位第 6 位为 1）；`unshare` 可用。
- **利用思路**：`unshare -UrmC` 新命名空间后挂载 cgroup 释放宿主写权限。
- **加固命令**：
```bash
# 默认 drop ALL 后按需 add（见上）
# daemon.json 全局配置：
cat /etc/docker/daemon.json
# { "default-ulimits": {...}, "capabilities": ["NET_BIND_SERVICE"] }
# 升级内核 + 升级 Docker；开启 user namespace 隔离
```

### CVE-2019-5736（runc 逃逸）
- **概述**：恶意镜像或可写容器内，利用 runc 执行宿主二进制（`docker exec` 触发）。
- **检测特征**：容器内 `/proc/self/exe` 指向 runc 相关路径被改写；镜像构建层存在恶意脚本。
- **加固命令**：升级 Docker ≥ 19.03.0 / runc ≥ 1.0.0-rc6；`docker version` 核对版本。

## 镜像投毒检测

- **概述**：基础镜像被替换或构建层藏后门（`/etc/cron.d`、`/root/.ssh/authorized_keys`、启动命令）。
- **排查命令**：
```bash
# 列出镜像与大小异常的层
docker images
docker history --no-trunc <image> | head -30   # 看每层 RUN 命令
# 导出并静态分析（不启动）
docker save <image> -o /tmp/img.tar && tar -xvf /tmp/img.tar
# 检查镜像内关键文件
docker run --rm -it <image> bash -c 'cat /etc/cron.d/*; ls -la /root/.ssh/ 2>/dev/null; cat /root/.ssh/authorized_keys 2>/dev/null'
```
- **加固**：只拉官方/受信仓库镜像（`docker pull` 校验 digest）；构建后做 `docker scan`/`trivy image`；禁止宿主目录整体挂载。

## docker cp 植入后门与容器内 Web 目录加固

- **攻击手法**：攻击者通过 `docker cp host 文件 容器:/路径` 把 Webshell/工具拷入容器，或反之把容器文件窃出。
- **排查**：`docker events` 与 auditd 监控 `docker cp`（audit 规则 `-w /var/lib/docker -k docker`）；容器内 Web 目录 mtime 突变文件。
- **容器内 Web 目录加固（重点）**：
```bash
# 进入容器
docker exec -it <cid> bash
# Web 根只读化（php 程序目录 chmod -R 555 + 写目录单独授权）
chmod -R 555 /var/www/html
chmod -R 755 /var/www/html/uploads   # 仅上传目录可写
chown -R www-data:www-data /var/www/html/uploads
# 删除备份/源码泄露文件
find /var/www/html -name "*.bak" -o -name "*.swp" -o -name "*~" -delete
# 扫描新增 webshell（近期 mtime）
find /var/www/html -mmin -120 -type f \( -name "*.php" -o -name "*.jsp" \)
```

## 容器内 vs 宿主排查步骤

### 容器内排查（先从最可疑容器开始）
```bash
docker ps -a                                # 列出所有容器（含停止的）
docker top <cid>                            # 容器内进程
docker exec <cid> ps aux
docker exec <cid> netstat -tunlp            # 容器内监听与外连
docker logs --tail 200 <cid>                # 应用日志
docker exec <cid> cat /proc/1/cmdline       # 主进程命令
docker inspect --format '{{.Config.Cmd}}' <cid>
```

### 宿主排查（容器逃逸后必查）
```bash
ss -antp | grep -v docker                   # 宿主监听端口
ps aux --sort=-%cpu | head -30              # 异常进程（容器进程带 [kworker] 前缀区分）
docker ps -a --no-trunc | awk '{print $1}'  # 找出可写宿主盘的容器
# 检查主机 .ssh / crontab / 新建系统用户
grep -E "docker|nobody" /etc/passwd | tail
find / -maxdepth 3 -newermt "2026-08-08 00:00" -type f 2>/dev/null | grep -vE "proc|sys"
```

## docker inspect / exec 取证命令

```bash
# 取证信息三件套
docker inspect <cid>                        # 完整配置：挂载、端口、CapEff、Env
docker inspect --format='{{.HostConfig.Privileged}}' <cid>
docker inspect --format='{{.HostConfig.Binds}}' <cid>    # 挂载了宿主哪些目录
docker inspect --format='{{.NetworkSettings.IPAddress}} {{.Config.Image}}' $(docker ps -q)
# 导出容器文件系统（不改动证据）
docker export <cid> -o /evidence/container.tar
# 暂停而非停止（保留进程状态）
docker pause <cid>
# 查镜像与容器创建时间（对时间线）
docker ps -a --format "table {{.Names}}\t{{.CreatedAt}}\t{{.Image}}"
```

## 容器网络隔离加固

- **问题**：默认 bridge 网络下所有容器可互 ping；攻击者横向移动容易。
- **加固命令**：
```bash
# 1) 按服务划分自定义网络（服务间默认隔离）
docker network create -d bridge app-net
docker network create -d bridge db-net
docker run --network app-net --name web ...
docker run --network db-net --name mysql ...
# 2) 仅暴露必要端口到宿主
#    避免 -p 0.0.0.0:3306:3306，改绑回环：
docker run -p 127.0.0.1:3306:3306 mysql
# 3) 默认 bridge 禁止容器间互通
sysctl -w net.bridge.bridge-nf-call-iptables=1
# 通过 iptables 阻断 container 网段间互访
# 4) 容器内禁用不必要的网络能力（如 NET_RAW 丢 raw socket）
docker run --cap-drop=NET_RAW ...
# 5) 出站限制：只允许业务端口出网（iptables -A FORWARD -s <container-net> -o eth0 -j DROP 后按需放行）
```

## 容器安全快速 Checklist

- [ ] 确认当前处于容器内还是宿主机（`.dockerenv` / `/proc/1/cgroup`）
- [ ] 排查 `/var/run/docker.sock` 是否被挂载进容器
- [ ] 检查容器 `CapEff` 是否含 `cap_sys_admin` 或全 1（privileged）
- [ ] 检查所有镜像来源与 `docker history` 各层命令
- [ ] Web 容器内目录 `chmod -R 555` 只读化，上传目录单独授权
- [ ] 检查 docker daemon.json 全局 `capabilities` 与 `userns-remap`
- [ ] 记录每台容器的镜像、创建时间、开放端口，输出到溯源报告
