# CTF 工控流量分析实战手册 - Wireshark 与 CLI

> 培训内容深化整理：S7comm、Modbus/TCP 协议分析、数据提取、flag 还原。
> 适用场景：CTF 工控流量题、综合防御平台工控告警取证。
> **每条命令均区分图形化（Wireshark GUI）与无头服务器（tshark/CLI）两种环境**。

## 一、工控流量通用分析流程

```
1. 识别端口 → 2. 锁定会话 → 3. 看协议字段 → 4. 找读写操作 → 5. 提取数据 → 6. 还原 flag
```

| 步骤 | GUI（Wireshark） | CLI（tshark） |
|---|---|---|
| 1. 识别端口 | Statistics → Conversations | `tshark -r file.pcap -q -z conv,tcp` |
| 2. 锁定会话 | 显示过滤器 `tcp.port == 102` | `tshark -r file.pcap -Y "tcp.port==102"` |
| 3. 看协议字段 | Packet Details 展开 | `tshark -r file.pcap -Y "s7comm" -T fields -e s7comm.param.func` |
| 4. 找读写操作 | 过滤 `s7comm.param.func == 4` | `tshark -r file.pcap -Y "s7comm.param.func==4"` |
| 5. 提取数据 | 选中字段 → Copy → As Hex | `tshark -r file.pcap -Y "s7comm" -T fields -e s7comm.data` |
| 6. 还原 flag | CyberChef Hex → ASCII | `python3 -c "import binascii; print(binascii.unhexlify('hex_here').decode())"` |

## 二、工具安装

### 2.1 图形化（GUI）- 本地桌面环境

```bash
# Windows / macOS / Linux Desktop
# 下载：https://www.wireshark.org/
# 安装时勾选 Npcap（Windows）或 libpcap（Linux）

# Ubuntu Desktop
sudo apt install wireshark -y
sudo usermod -aG wireshark $USER
# 注销重登
```

### 2.2 CLI（无头服务器）

```bash
# Ubuntu/Debian Server
sudo apt install tshark -y

# CentOS/RHEL
sudo yum install wireshark-cli -y

# 验证
tshark --version
tshark -r test.pcap -c 5    # 读前 5 包
```

**为什么无头环境用 tshark**：Wireshark 是 GUI 工具，SSH 远程或容器内无法弹窗；tshark 是同一套引擎的命令行版本，所有过滤语法完全兼容。

## 三、S7comm 协议分析（Siemens PLC，TCP 102）

### 3.1 协议分层

```
Ethernet / IP
  ↓
TCP (端口 102)            ← ISO-on-TCP
  ↓
TPKT                     ← 封装 ISO Transport
  ↓
COTP                     ← ISO 传输层连接
  ↓
S7comm                   ← 应用层（PLC 读写控制）
```

### 3.2 关键字段速查

| 字段 | 值 | 含义 |
|---|---|---|
| Protocol ID | 0x32 | 确认是 S7comm |
| ROSCTR | 0x01 / 0x03 / 0x07 | Job 请求 / Ack_Data 响应 / Userdata |
| PDU Reference | 数字 | 请求-响应配对编号 |
| Function | 4 / 5 / 0x28 | Read Var / Write Var / Setup Communication |

### 3.3 Read Var 读操作分析

**重点看响应包**：请求包告诉你读哪里，响应包才有数据。

#### GUI（Wireshark）

1. 过滤 `s7comm.param.func == 4`
2. 找到 Job 请求包，记录 DB Number、Area、Address、Length
3. 找到对应 Ack_Data 响应包（同 PDU Reference）
4. 展开 S7comm → Data，右键 → Copy → ...As Hex

#### CLI（tshark）

```bash
# 列出所有 Read Var 请求
tshark -r file.pcap -Y "s7comm.param.func==4" \
  -T fields -e frame.number -e s7comm.param.userdata.dbnum \
              -e s7comm.param.userdata.address

# 列出所有 Ack_Data 响应（包含数据）
tshark -r file.pcap -Y "s7comm.header.rosctr==3 && s7comm.data" \
  -T fields -e frame.number -e s7comm.data

# 导出所有 S7comm 数据到文件
tshark -r file.pcap -Y "s7comm.data" -T fields -e s7comm.data > s7_data.txt
```

### 3.4 Write Var 写操作分析

**写入值在请求包里**（与读操作相反）。

#### GUI

1. 过滤 `s7comm.param.func == 5`
2. 展开 S7comm → Data → 复制十六进制
3. 尝试 ASCII / Base64 / XOR 解码

#### CLI

```bash
# 提取所有 Write Var 的写入数据
tshark -r file.pcap -Y "s7comm.param.func==5" \
  -T fields -e frame.number -e s7comm.data > write_data.txt

# hex 转 ASCII
python3 -c "
with open('write_data.txt') as f:
    for line in f:
        parts = line.strip().split('\t')
        if len(parts) >= 2:
            hex_str = parts[1].replace(':', '')
            try:
                print(f'Frame {parts[0]}: {bytes.fromhex(hex_str).decode(\"latin1\")}')
            except:
                print(f'Frame {parts[0]}: {hex_str}')
"
```

### 3.5 S7 地址换算（必懂）

| 写法 | 含义 | 提取方法 |
|---|---|---|
| `DB1.DBX10.2` | DB1 第 10 字节第 2 位 | 位级布尔 |
| `DB1.DBB10` | DB1 第 10 字节 | 1 字节 |
| `DB1.DBW10` | DB1 第 10 字节起 2 字节 | 注意大小端 |
| `DB1.DBD10` | DB1 第 10 字节起 4 字节 | 整数或浮点 |

**新手提示**：CTF 中最常见的是 DBB（字节）连续读取，拼成 hex 后转 ASCII。

## 四、Modbus/TCP 协议分析（TCP 502）

### 4.1 报文结构

```
MBAP Header (7 字节)
  ├─ Transaction ID (2B)  ← 请求-响应配对
  ├─ Protocol ID (2B)     ← 通常 0x0000
  ├─ Length (2B)          ← 后续字节数
  └─ Unit ID (1B)         ← 从站编号
PDU
  ├─ Function Code (1B)   ← 决定数据含义
  └─ Data                 ← 地址/数量/值
```

### 4.2 功能码速查

| 功能码 | 名称 | CTF 含义 |
|---|---|---|
| 0x01 | Read Coils | bit 串隐藏 |
| 0x02 | Read Discrete Inputs | 状态序列 |
| 0x03 | Read Holding Registers | **最常见，ASCII flag** |
| 0x04 | Read Input Registers | 输入寄存器 |
| 0x05 | Write Single Coil | 单点写入 |
| 0x06 | Write Single Register | 单寄存器写入 |
| 0x0F | Write Multiple Coils | 批量 bit 写入 |
| 0x10 | Write Multiple Registers | **批量写，最适合藏 flag** |

### 4.3 Read Holding Registers (0x03) 提取

#### GUI

1. 过滤 `modbus.func_code == 3`
2. 找响应包，查看 Byte Count 和 Register Values
3. 每个 16-bit 寄存器拼成 hex

#### CLI

```bash
# 提取所有 Read Holding Registers 响应的寄存器值
tshark -r file.pcap -Y "modbus.func_code==3 && modbus.type==0" \
  -T fields -e frame.number -e modbus.regval_uint16 \
  > modbus_regs.txt

# 拼接所有寄存器值并转 ASCII
python3 << 'EOF'
with open('modbus_regs.txt') as f:
    hex_all = ''
    for line in f:
        parts = line.strip().split('\t')
        if len(parts) >= 2:
            for reg in parts[1].split(','):
                hex_all += f'{int(reg):04x}'   # 每个 16-bit 转 4 位 hex
    try:
        print(bytes.fromhex(hex_all).decode('latin1'))
    except:
        print(hex_all)
EOF
```

### 4.4 Write Multiple Registers (0x10) 提取

**写入值在请求包**。

```bash
# 提取批量写入的寄存器值
tshark -r file.pcap -Y "modbus.func_code==16" \
  -T fields -e frame.number -e modbus.regval_uint16 \
  > write_regs.txt

# 同上拼接转 ASCII
```

### 4.5 寄存器还原尝试顺序

```
1. 大端拼接 → hex → ASCII
2. 小端拼接（每 2 字节反转）→ hex → ASCII
3. 整数解释 → 可能是字符 ASCII 码
4. 浮点解释（4 字节 IEEE 754）
5. Base64 / XOR / RC4 解密
```

**新手提示**：例 `0x666c 0x6167 0x7b31 0x3233 0x7d` → 大端拼接 `666c61677b3132337d` → ASCII `flag{123}`。

## 五、Wireshark / tshark 显示过滤器速查

| 目标 | 过滤器 |
|---|---|
| S7comm 流量 | `s7comm` 或 `tcp.port == 102` |
| Modbus/TCP 流量 | `modbus` 或 `tcp.port == 502` |
| 指定通信双方 | `ip.addr == 192.168.1.10 && ip.addr == 192.168.1.20` |
| 只看某 TCP 会话 | `tcp.stream == N` |
| S7 读操作 | `s7comm.param.func == 4` |
| S7 写操作 | `s7comm.param.func == 5` |
| Modbus 读寄存器 | `modbus.func_code == 3` |
| Modbus 批量写 | `modbus.func_code == 16` |
| 查可疑字符串 | Edit → Find Packet → Packet bytes / String |

## 六、实战案例 A：S7comm 提取 DB 数据

**目标**：从 Read Var 响应中还原字符串。

### GUI 步骤

1. 过滤 `s7comm`
2. 找 Function = Read Var 的请求包，记录 DB Number、Area、Address、Length
3. 跳到对应 Ack_Data 响应包（同 PDU Reference）
4. 复制 Data 字节
5. hex → ASCII

### CLI 步骤

```bash
# 一步到位：提取所有响应数据并转 ASCII
tshark -r s7.pcap -Y "s7comm.header.rosctr==3 && s7comm.data" \
  -T fields -e frame.number -e s7comm.data | \
  python3 -c "
import sys
for line in sys.stdin:
    parts = line.strip().split('\t')
    if len(parts) >= 2:
        h = parts[1].replace(':', '')
        try:
            print(f'Frame {parts[0]}: {bytes.fromhex(h).decode(\"latin1\")}')
        except:
            print(f'Frame {parts[0]}: {h}')
"
```

## 七、实战案例 B：Modbus 寄存器转字符串

### CLI 一键脚本

```bash
#!/bin/bash
# 用法：./modbus_extract.sh file.pcap
PCAP=$1

tshark -r "$PCAP" -Y "modbus.func_code==3 && modbus.type==0" \
  -T fields -e modbus.regval_uint16 | \
python3 -c "
import sys
hex_all = ''
for line in sys.stdin:
    for reg in line.strip().split(','):
        reg = reg.strip()
        if reg:
            hex_all += f'{int(reg):04x}'
# 尝试大端
try:
    print('大端:', bytes.fromhex(hex_all).decode('latin1'))
except: pass
# 尝试小端（每 2 字节反转）
small = ''
for i in range(0, len(hex_all), 4):
    small += hex_all[i+2:i+4] + hex_all[i:i+2]
try:
    print('小端:', bytes.fromhex(small).decode('latin1'))
except: pass
"
```

## 八、混合协议题（S7 给 key，Modbus 给密文）

### 解题流程

```bash
# 1. 从 S7comm Write Var 提取 key（hex）
tshark -r mixed.pcap -Y "s7comm.param.func==5" -T fields -e s7comm.data > key.hex

# 2. 从 Modbus 批量写提取密文（hex）
tshark -r mixed.pcap -Y "modbus.func_code==16" -T fields -e modbus.regval_uint16 > ct.hex

# 3. Python 解密（假设 XOR）
python3 << 'EOF'
key = bytes.fromhex(open('key.hex').read().strip().replace(':', ''))
ct = bytes.fromhex(open('ct.hex').read().strip().replace(':', ''))
pt = bytes(c ^ key[i % len(key)] for i, c in enumerate(ct))
print(pt.decode('latin1'))
EOF
```

## 九、排错清单

| 问题 | 检查点 |
|---|---|
| 看到数据但不是 flag | 尝试 ASCII、hex、Base64、大小端、XOR |
| 顺序不对 | 按时间、地址、Transaction ID / PDU Reference 排序 |
| 寄存器偏移差 1 | Modbus 文档地址与协议地址可能有 0/1 基差异 |
| 重复数据多 | 去掉 TCP 重传、重复读取、心跳包 |
| 只找到请求没数据 | 数据在响应包；写入值在请求包 |
| tshark 找不到字段 | `tshark -r file.pcap -Y "modbus" -T pdml > out.xml` 看完整字段名 |

## 十、工控协议端口速查

| 协议 | 端口 | 过滤器 |
|---|---|---|
| S7comm | TCP 102 | `s7comm` |
| Modbus/TCP | TCP 502 | `modbus` |
| DNP3 | TCP 20000 | `dnp3` |
| IEC 60870-5-104 | TCP 2404 | `iec60870_104` |
| BACnet | UDP 47808 | `bacnet` |
| EtherCAT | UDP 34980 | `ecat` |
| OPC UA | TCP 4840 | `opc.ua` |

## 十一、相关加固项

| 加固项 ID | 作用 |
|---|---|
| `firewall_on` | 封禁 502/102/2404 等工控端口对外 |
| `kernel_harden` | 内核网络加固 |

## 十二、参考

- 培训 PDF：CTF_工控流量.pdf
- Wireshark 显示过滤器：https://www.wireshark.org/docs/dfref/
- tshark 手册：`man tshark`
- Modbus 规范：https://modbus.org/specs.php
