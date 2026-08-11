# CTF MISC 题目实战手册

> 培训内容深化整理：文件识别、编码链、隐写、Office 文档、流量取证全流程命令。
> 适用场景：CTF MISC 分类题目、综合防御平台取证分析。
> **每条命令均区分图形化（GUI）与无头服务器（CLI）两种环境**。

## 一、MISC 通用解题流程

```
1. 识别载体 → 2. 提取线索 → 3. 判断算法 → 4. 解码 → 5. 验证 flag
   file/010      binwalk         特征串        CyberChef    格式语义
   strings       Wireshark       文件头        John/zsteg
```

**核心原则**：每一步都要回答"我为什么认为这个工具适合当前证据"。

## 二、工具安装

### 2.1 图形化（GUI）- 桌面环境

| 工具 | 用途 | 下载 |
|---|---|---|
| 010 Editor | 二进制查看与模板解析 | https://www.sweetscape.com/ |
| StegSolve | 图片 LSB/位平面分析 | CTF 常用 Java 工具 |
| CyberChef | 编码链式处理 | https://gchq.github.io/CyberChef/ |
| Wireshark | 流量分析 | https://www.wireshark.org/ |
| ARCHPR | ZIP 密码爆破 | Windows GUI 工具 |

### 2.2 CLI（无头服务器必备）

```bash
# Ubuntu/Debian Server 一键安装
sudo apt install -y file binwalk strings foremost xxd hexdump \
                    steghide zsteg exiftool imagemagick \
                    john zip unzip p7zip-full \
                    tshark tcpdump

# Python 库
pip install pillow stegano -i https://pypi.tuna.tsinghua.edu.cn/simple

# 验证
file --version
binwalk --version
strings --version
```

**为什么无头环境装这些**：CTF 靶机通常是最小化 Ubuntu Server，只装 CLI 工具即可覆盖 90% MISC 题。

## 三、文件识别

### 3.1 file 命令（识别文件类型）

```bash
# 基础用法
file unknown_file
# 输出示例：unknown_file: PNG image data, 1920 x 1080, 8-bit/color RGBA, non-interlaced

# 扩展名被改的情况（最常见）
mv flag.png flag.txt
file flag.txt
# 输出：flag.txt: PNG image data, ... → 说明实际是 PNG
```

**新手提示**：`file` 通过文件头（magic bytes）判断真实类型，不看扩展名。这是 MISC 第一步必做。

### 3.2 文件头速查

| 文件头（Hex） | 类型 | 扩展名 |
|---|---|---|
| `89504E47` | PNG | .png |
| `FFD8FF` | JPEG | .jpg |
| `47494638` | GIF | .gif |
| `504B0304` | ZIP | .zip/.docx/.xlsx/.jar |
| `52617221` | RAR | .rar |
| `25504446` | PDF | .pdf |
| `7F454C46` | ELF | 二进制可执行 |
| `4D5A` | PE | .exe |
| `49492A00` / `4D4D002A` | TIFF | .tif |
| `424D` | BMP | .bmp |

### 3.3 010 Editor（GUI）vs xxd（CLI）

#### GUI（010 Editor）

1. 打开文件
2. 自动应用模板（PNG/ZIP/PE 等）
3. 查看结构化字段

#### CLI（xxd，所有 Linux 自带）

```bash
# 查看前 64 字节 hex
xxd unknown_file | head -4

# 查看文件头
xxd -l 16 unknown_file
# 00000000: 8950 4e47 0d0a 1a0a 0000 000d 4948 4452  .PNG........IHDR

# hex 转 ASCII
echo "89504E47" | xxd -r -p

# 整个文件转 hex（用于 CyberChef 反查）
xxd -p file.png > file.hex
```

## 四、strings 字符串提取

### 4.1 基础用法

```bash
# 提取所有可打印字符串（默认 ≥4 字符）
strings file.pcap > strings.txt

# 提取 ASCII + Unicode
strings -a -e l file.docx > unicode_strings.txt   # little-endian Unicode
strings -a -e b file.docx > unicode_strings.txt   # big-endian Unicode

# 最小长度 6
strings -n 6 file.pcap
```

### 4.2 配合 grep 定位 flag

```bash
# 常用 grep 模式
strings file.pcap | grep -i "flag"           # 直接搜 flag
strings file.pcap | grep "Zmx"               # Base64 编码的 flag{
strings file.pcap | grep -i "user\|pass"     # 账号密码
strings file.pcap | grep -i "mysql"          # 数据库痕迹
strings file.pcap | grep -iE "flag\{|ctf\{|key"  # 多关键字

# 上下文（前后 2 行）
strings file.pcap | grep -B2 -A2 "flag"

# 提取 Base64 候选（特征：A-Za-z0-9+/ 长度 4 倍数 + =）
strings file.pcap | grep -E '^[A-Za-z0-9+/]{20,}={0,2}$'
```

**原理**：pcap 保存的是数据包字节流，若载荷没加密，明文和编码文本会以连续字符串形式出现。

## 五、binwalk 文件提取

### 5.1 识别嵌入文件

```bash
# 扫描文件中隐藏的其他文件
binwalk image.png
# 输出示例：
# DECIMAL       HEXADECIMAL     DESCRIPTION
# 0             0x0             PNG image, 1920 x 1080
# 1234567       0x12D687        Zip archive data

# 详细签名扫描
binwalk -B image.png    # 等同 --signature
```

### 5.2 自动提取

```bash
# 提取所有嵌入文件（创建 _image.png.extracted 目录）
binwalk -e image.png

# 指定输出目录
binwalk -e -C /tmp/extracted image.png

# 递归提取（提取出的文件继续扫描）
binwalk -eM image.png

# 手动指定提取（按偏移）
dd if=image.png of=hidden.zip bs=1 skip=1234567
```

### 5.3 foremost（binwalk 失败时的备选）

```bash
# 按文件类型强制提取
foremost -t zip,png,jpg -i image.png -o /tmp/foremost_out

# 类型代码：jpg, png, gif, bmp, zip, rar, html, doc, xls, pdf
foremost -t all -i disk.dd -o /tmp/foremost_out
```

## 六、图片隐写

### 6.1 StegSolve（GUI，Java）

**用途**：查看 RGB/Alpha 位平面，定位 LSB 隐藏。

```bash
# 启动（需 Java）
java -jar StegSolve.jar
# 打开图片 → Analyse → Frame Browser / Data Extract / Format Checker
```

**无 GUI 替代**：用 Python pillow + stegano 库。

### 6.2 zsteg（CLI，PNG/BMP LSB 自动枚举）

```bash
# 安装（Ruby）
sudo apt install ruby ruby-dev
sudo gem install zsteg

# 一键枚举所有 LSB 通道
zsteg image.png

# 指定通道
zsteg -a image.png              # 全部尝试
zsteg -e 'b1,rgb,lsb,xy' image.png    # 指定位/通道/顺序

# 提取到文件
zsteg -e 'b1,rgb,lsb,xy' image.png > out.bin
```

### 6.3 steghide（CLI，JPEG/通用）

```bash
# 查看是否有嵌入信息
steghide info image.jpg

# 提取（需密码）
steghide extract -sf image.jpg -p "password"
steghide extract -sf image.jpg -p ""        # 空密码

# 嵌入（出题用）
steghide embed -cf cover.jpg -ef secret.txt -p "password"
```

### 6.4 exiftool（元数据，CLI）

```bash
# 查看所有元数据
exiftool image.jpg

# 查看特定字段
exiftool -XPSubject -XPComment -UserComment image.jpg

# 提取 GPS（可能有线索）
exiftool -gps* image.jpg

# 递归目录
exiftool -r /tmp/images/
```

### 6.5 LSB 原理与 Python 实现

**原理**：每个像素的 RGB 最低位（bit 0）改动对人眼不可见，可隐藏 3 bit/像素。

```bash
python3 << 'EOF'
from PIL import Image

img = Image.open('suspicious.png')
pixels = list(img.getdata())

# 提取每个像素 RGB 通道的最低位
bits = ''
for pixel in pixels:
    for channel in pixel[:3]:   # R, G, B
        bits += str(channel & 1)

# 每 8 位转 ASCII
result = ''
for i in range(0, len(bits), 8):
    byte = bits[i:i+8]
    if len(byte) == 8:
        char = chr(int(byte, 2))
        result += char
        if result.endswith('}'):
            break
print(result)
EOF
```

## 七、Office 文档（本质是 ZIP）

### 7.1 改扩展名 + 解压（最常用）

**原理**：xlsx/docx/pptx 是 OOXML 格式，本质是 ZIP 包，内部是 XML 文件。

```bash
# 方法 1：直接改扩展名解压
cp hidden.docx hidden.zip
unzip hidden.zip -d hidden_doc/

# 方法 2：unzip 直接读（不改名）
unzip hidden.docx -d hidden_doc/

# 关键文件
# Word: word/document.xml        ← 正文
# Excel: xl/sharedStrings.xml    ← 共享字符串
# PPT: ppt/slides/slide1.xml     ← 幻灯片
```

### 7.2 查找隐藏白字

```bash
# 搜索白色字体（隐藏文字）
grep -r 'w:color.*FFFFFF' hidden_doc/

# 搜索 flag 关键字
grep -ri "flag" hidden_doc/

# 搜索 Base64
grep -rE '[A-Za-z0-9+/]{20,}={0,2}' hidden_doc/
```

### 7.3 嵌入对象提取

```bash
# 查找嵌入文件
find hidden_doc/ -name "*.bin" -o -name "*.ole"

# binwalk 扫描嵌入对象
binwalk hidden_doc/word/embeddings/oleObject1.bin
```

## 八、压缩包密码爆破

### 8.1 zip2john + john（CLI）

```bash
# 1. 提取密码哈希
zip2john encrypted.zip > hash.txt

# 2. 查看哈希格式
head hash.txt

# 3. 字典爆破
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# 4. 查看结果
john --show hash.txt

# 5. 暴力模式（无字典）
john --incremental hash.txt
```

### 8.2 ARCHPR（Windows GUI）

```bash
# 仅 Windows GUI
# 1. 打开 ARCHPR
# 2. 打开 encrypted.zip
# 3. 选"字典攻击"或"暴力"
# 4. 字典：rockyou.txt
# 5. 开始
```

### 8.3 fcrackzip（CLI 备选）

```bash
# 字典爆破
fcrackzip -D -p /usr/share/wordlists/rockyou.txt -u encrypted.zip

# 暴力（数字 1-6 位）
fcrackzip -b -c1 -l1-6 -u encrypted.zip
```

## 九、流量取证（pcap）

### 9.1 strings 快速定位

```bash
# 优先用 strings 找明文线索
strings capture.pcap | grep -iE "flag|ctf|key|pass|user"
strings capture.pcap | grep "Zmx"   # Base64 flag{
```

### 9.2 tshark 提取 HTTP 内容

```bash
# 列出所有 HTTP 请求
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri

# 导出所有 HTTP 对象（图片/文件）
tshark -r capture.pcap --export-objects "http,/tmp/http_objects"

# 提取 POST 数据
tshark -r capture.pcap -Y "http.request.method==POST" \
  -T fields -e http.file_data
```

### 9.3 Wireshark Follow TCP Stream（GUI）

1. 选中任意包 → Analyze → Follow → TCP Stream
2. 查看完整会话内容
3. 数据可能直接含 flag

#### CLI 等价

```bash
# 导出指定 TCP Stream
tshark -r capture.pcap -q -z follow,tcp,ascii,0    # stream 0
tshark -r capture.pcap -q -z follow,tcp,ascii,1    # stream 1

# 导出所有 stream（循环）
for i in $(seq 0 20); do
  tshark -r capture.pcap -q -z follow,tcp,ascii,$i 2>/dev/null | grep -i "flag" && echo "Found in stream $i"
done
```

### 9.4 提取 FTP 明文密码

```bash
tshark -r capture.pcap -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg

# 或
strings capture.pcap | grep -iE "USER |PASS "
```

## 十、实战案例（培训 PDF 原题）

### 10.1 5GC AMF 名称题（Base64 提取）

**WP 关键证据**：pcap 中出现 `Zmxh...` 字符串。

```bash
# 1. strings 提取
strings 5gc-amfname.pcap | grep "Zmx"

# 2. CyberChef 或 CLI 解码
echo "ZmxhZ3thbWZuYW1lLXVqcnIxMTIzfQ==" | base64 -d
# 输出: flag{amfname-ujrr1123}
```

**教学点**：Base64 前缀不是结论，只是候选；结论来自解码后格式和语义同时成立。

### 10.2 签到题（exe strings）

```bash
# 1. 提取字符串
strings 签到题.exe | grep -iE "flag|ctf"
# 输出: flag{9280c6a3-15f7-64b2-a39d-47285e10f63d}
```

### 10.3 草甸方阵（古典密码）

```bash
# 1. strings 得到编码串
strings 草甸方阵的密语 > encoded.txt
# 内容: mPsBhFnA{MTKRZVHSNW}

# 2. 识别为方阵换位（大小写分组）
# 用随波逐流 GUI 或 Python 脚本枚举列数
python3 -c "
s = 'mPsBhFnA{MTKRZVHSNW}'
# 观察规律：mPsBhFnA{ + MTKRZVHSNW + }
# 大写部分单独取出做栅栏/方阵
import itertools
upper = 'MTKRZVHSNW'
for cols in range(2, 10):
    rows = (len(upper) + cols - 1) // cols
    out = [''] * len(upper)
    idx = 0
    for c in range(cols):
        for r in range(rows):
            if idx < len(upper):
                out[r * cols + c] = upper[idx]
                idx += 1
    s2 = ''.join(out)
    print(f'cols={cols}: {s2}')
"
```

### 10.4 光隙中的寄生密钥（图片内嵌 ZIP）

```bash
# 1. binwalk 发现内嵌 ZIP
binwalk image.png
# 1234567       0x12D687        Zip archive data

# 2. 提取
binwalk -e image.png
cd _image.png.extracted/

# 3. 爆破 ZIP 密码
zip2john 12D687.zip > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --show hash.txt
# 输出: 12D687.zip:password:flag.txt::12D687.zip

# 4. 解压
unzip -P password 12D687.zip
cat flag.txt
# flag{9Lm\$Zb5@rT4#cN7j}
```

### 10.5 ez_xor（异或爆破）

```bash
# 1. 从 xls 提取 hex
strings flag.xls | grep -oE '[0-9a-fA-F]{20,}' > hex.txt

# 2. 异或爆破
python3 << 'EOF'
hex_str = open('hex.txt').read().strip()
data = bytes.fromhex(hex_str)

# 尝试单字节 XOR
for key in range(256):
    pt = bytes(b ^ key for b in data)
    if b'flag{' in pt or b'CTF' in pt:
        print(f'key=0x{key:02x}: {pt}')
        break

# 尝试多字节 key（如 'flag'）
for klen in range(1, 10):
    for start in range(256):
        key = bytes([(start + i) % 256 for i in range(klen)])
        pt = bytes(data[i] ^ key[i % klen] for i in range(len(data)))
        if b'flag{' in pt:
            print(f'key={key}: {pt}')
            break
EOF
```

### 10.6 ez_picture1（LSB + 元数据双路线）

```bash
# 路线 A：LSB
zsteg image.png | grep -i "flag"

# 路线 B：爆破密码 + EXIF
# 假设图片有密码保护（如 steghide）
for pw in $(seq 999999999 999999999); do
  steghide extract -sf image.png -p "$pw" -f 2>/dev/null && echo "Password: $pw" && break
done

# 查看 EXIF 元数据
exiftool -XPSubject image.png | base64 -d
# flag{HNCTFyaBPfaBW1E1}
```

### 10.7 套娃题（Office → ZIP → XML）

```bash
# 1. xlsx 改 zip
cp challenge.xlsx challenge.zip
unzip challenge.zip -d challenge/

# 2. 搜索白色字体
grep -r 'w:color w:val="FFFFFF"' challenge/
# word/document.xml: <w:color w:val="FFFFFF"/>

# 3. 提取白色文字内容
python3 -c "
import re
with open('challenge/word/document.xml') as f:
    content = f.read()
# 找所有白色字体后的文本
matches = re.findall(r'w:color w:val=\"FFFFFF\"[^>]*>.*?<w:t[^>]*>([^<]+)</w:t>', content)
print(''.join(matches))
"
# flag{HNCTFNNlWGNX5}
```

## 十一、MISC 工具速查表

| 现象 | GUI 工具 | CLI 替代 |
|---|---|---|
| 未知文件 | 010 Editor | `file` + `xxd` |
| 嵌入文件 | 010 Editor | `binwalk -e` |
| 字符串 | - | `strings` + `grep` |
| 图片 LSB | StegSolve | `zsteg` / Python pillow |
| JPEG 隐写 | StegSolve | `steghide` |
| 元数据 | 右键属性 | `exiftool` |
| ZIP 爆破 | ARCHPR | `john` / `fcrackzip` |
| Office 隐藏 | Office 打开 | `unzip` + `grep` |
| 流量分析 | Wireshark | `tshark` + `strings` |
| 编码链 | CyberChef | Python base64/hex |

## 十二、MISC 解题决策树

```
拿到文件
  ↓
file 识别类型
  ├─ 图片 → zsteg / steghide / exiftool / binwalk
  ├─ 压缩包 → 是否加密？
  │   ├─ 是 → zip2john + john
  │   └─ 否 → unzip，看内容
  ├─ Office → unzip，搜 document.xml/sharedStrings.xml
  ├─ pcap → strings + tshark
  ├─ exe/elf → strings + binwalk
  └─ 未知 → binwalk -e 递归提取
  ↓
拿到字符串
  ├─ 看 flag{} 格式 → 成功
  ├─ Base64 特征 → base64 -d
  ├─ hex 特征 → xxd -r -p
  ├─ 古典密码 → CyberChef / Python 枚举
  └─ 仍乱码 → 多层解码 / XOR 爆破
```

## 十三、参考

- 培训 PDF：misc题目课件.pdf
- HelloCTF MISC：https://hello-ctf.com/hc-misc/file/
- CyberChef：https://gchq.github.io/CyberChef/
- binwalk 文档：https://github.com/ReFirmLabs/binwalk
- zsteg 文档：https://github.com/zed-0xff/zsteg
