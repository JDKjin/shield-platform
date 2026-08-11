# CTF Crypto 密码学实战手册

> 培训内容深化整理：CyberChef、随波逐流、古典密码、AES、RC4、RSA 全流程命令。
> 适用场景：CTF 比赛 Crypto 分类题目、综合防御平台知识库检索。
> **每条命令均区分图形化（GUI）与无头服务器（CLI）两种环境**。

## 一、必备工具与安装

### 1.1 在线工具（图形化，浏览器即可）

| 工具 | 网址 | 用途 |
|---|---|---|
| CyberChef | https://gchq.github.io/CyberChef/ | 编码/解码/异或链式处理 |
| 随波逐流 | 搜索"随波逐流在线" | 古典密码、栅栏、换位枚举 |
| factordb | https://factordb.com/ | 大数分解查询 |
| sojson AES | https://www.sojson.com/encrypt_aes.html | AES 在线加解密 |
| wqtool | https://www.wqtool.com/basecode | 多种 Base 编码互转 |

### 1.2 本地 CLI 工具（无 GUI 服务器必备）

#### Python 库（必须）

```bash
# 一键安装全部密码学库
pip install pycryptodome libnum gmpy2 -i https://pypi.tuna.tsinghua.edu.cn/simple

# 验证
python -c "from Crypto.Util.number import *; print('pycryptodome OK')"
python -c "import gmpy2; print('gmpy2 OK')"
python -c "import libnum; print('libnum OK')"
```

**为什么用清华源**：默认 PyPI 在国内访问慢甚至超时，`-i` 指定镜像加速。

#### yafu（大数分解 CLI 工具）

```bash
# 下载（Windows）
# https://sourceforge.net/projects/yafu/
# 解压后 yafu.exe / yafu-Win32.exe

# Linux（需自行编译或下载预编译版）
wget https://sourceforge.net/projects/yafu/files/latest/download -O yafu.zip
unzip yafu.zip -d yafu
chmod +x yafu/yafu
./yafu/yafu
```

#### 轩禹 CTF_RSA 工具（仅 Windows GUI）

```bash
# 仅 Windows GUI，下载后双击运行
# 适合共模攻击、Wiener 攻击、小 e 攻击等
# 无 GUI 替代：用 Python + gmpy2 脚本（见下文各章节）
```

## 二、古典密码

### 2.1 凯撒密码（Caesar）

**原理**：明文每个字母按字母表向后（或向前）移动固定数目。

#### 图形化解法（GUI）

1. 打开 CyberChef
2. Recipe 添加 `ROT13`（仅偏移 13）或 `ROT47`
3. 若偏移未知，添加 `Find / Replace` + 多次试 `Add`
4. 输入密文 `wcrx{ir1c_wvetv_15_x00u}`，观察输出

#### CLI 解法（无 GUI）

```bash
# 方法 1：Python 脚本暴力枚举 25 种偏移
python3 -c "
c = 'wcrx{ir1c_wvetv_15_x00u}'
for shift in range(26):
    out = ''.join(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')) if ch.islower() else
                  chr((ord(ch) - ord('A') + shift) % 26 + ord('A')) if ch.isupper() else ch
                  for ch in c)
    print(f'{shift:2d}: {out}')
"

# 方法 2：识别 flag{} 格式自动找偏移
python3 -c "
c = 'wcrx{ir1c_wvetv_15_x00u}'
# 已知 flag{ 对应 wcrx{，求偏移：f(102) - w(119) = -17 = 9 (mod 26)
for shift in range(26):
    out = ''.join(chr((ord(ch) - ord('a') + shift) % 26 + ord('a')) if ch.islower() else ch for ch in c)
    if 'flag{' in out:
        print(f'偏移={shift}, 明文={out}')
        break
"
```

### 2.2 ROT13 / ROT47

#### GUI（CyberChef）

- ROT13：Recipe 添加 `ROT13`
- ROT47：Recipe 添加 `ROT47`

#### CLI（无 GUI）

```bash
# ROT13（标准 tr 命令，所有 Linux 自带）
echo "Hello World" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# ROT47（ASCII 33-126 位移 47）
python3 -c "
s = 'afZ_r9VYfScOeO_UL^RWUc'
print(''.join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in s))
"
```

### 2.3 埃特巴什码（Atbash）

**原理**：字母表中第一个字母用最后一个代替（A↔Z, B↔Y, ...）。

```bash
# CLI
python3 -c "
s = 'ABCDEFG'
print(''.join(chr(ord('A') + 25 - (ord(c) - ord('A'))) if c.isupper() else
             chr(ord('a') + 25 - (ord(c) - ord('a'))) if c.islower() else c for c in s))
"
```

### 2.4 维吉尼亚密码（Vigenere）

**原理**：多表代换，密钥循环使用。明文 `come greatwall` + 密钥 `crypto` → 密文 `efkt zferrltzn`。

#### GUI（CyberChef）

1. Recipe 添加 `Vigenère Decode`
2. Key 填 `crypto`
3. 输入密文

#### CLI（无 GUI）

```bash
# 已知密钥解密
python3 -c "
def vigenere_decrypt(ct, key):
    out = []
    ki = 0
    for c in ct:
        if c.isalpha():
            shift = ord(key[ki % len(key)].lower()) - ord('a')
            base = ord('A') if c.isupper() else ord('a')
            out.append(chr((ord(c) - base - shift) % 26 + base))
            ki += 1
        else:
            out.append(c)
    return ''.join(out)

ct = 'efkt zferrltzn'
key = 'crypto'
print(vigenere_decrypt(ct, key))
# 输出: come greatwall
"

# 未知密钥：用 Kasiski 测试求密钥长度（高阶，可借助在线工具）
# https://www.wqtool.com/vigenere-cipher
```

### 2.5 培根密码（Bacon）

**特征**：只有 A、B 两种字符，每段长度 5。可能用大小写或字体区分。

```bash
# CLI 解码
python3 -c "
bacon = 'ABAAAABABAABBABBAABBAABAAAAAABAAAAAAAABAABBABABBAABAAABAAABAABAAAABBBAAABBBAABAABAAAA'
table = {'A':0,'B':1}
# 标准 Bacon 表（24 字母，I=J, U=V）
for i in range(0, len(bacon), 5):
    val = 0
    for j in range(5):
        val = val * 2 + table[bacon[i+j]]
    print(chr(val + ord('A')), end='')
')
"
```

### 2.6 栅栏密码（Rail Fence）

**原理**：明文分 N 组，取每组第 1 个字连起来。明文 `flag{ra1l_fence_15_g00d}` → 密文 `fl}adg0{0rga_15l1__feecn`。

#### GUI

- CyberChef：`Rail Fence Cipher Decode`，调 Rails 数量

#### CLI（无 GUI）

```bash
# 暴力枚举栏数
python3 -c "
ct = 'fl}adg0{0rga_15l1__feecn'
for rails in range(2, 20):
    # 简单栅栏（按栏数分组重排）
    n = len(ct)
    cols = (n + rails - 1) // rails
    out = [''] * n
    idx = 0
    for c in range(cols):
        for r in range(rails):
            if idx < n:
                out[r * cols + c] = ct[idx]
                idx += 1
    s = ''.join(out)
    if 'flag{' in s:
        print(f'栏数={rails}, 明文={s}')
"
```

### 2.7 JSFUCK / Brainfuck

#### CLI（无 GUI）

```bash
# Brainfuck 解释器
python3 -c "
code = '++++++++++[>+++++++>++++++++++>+++>+<<<<-]>++.>+.+++++++..+++.>++.<<+++++++++++++++.>.+++.------.--------.>+.>.'
tape = [0]*30000
ptr = 0
pc = 0
stack = []
out = []
while pc < len(code):
    c = code[pc]
    if c == '+': tape[ptr] = (tape[ptr]+1) % 256
    elif c == '-': tape[ptr] = (tape[ptr]-1) % 256
    elif c == '>': ptr += 1
    elif c == '<': ptr -= 1
    elif c == '.': out.append(chr(tape[ptr]))
    elif c == '[':
        if tape[ptr] == 0:
            depth = 1
            while depth:
                pc += 1
                if code[pc] == '[': depth += 1
                elif code[pc] == ']': depth -= 1
    elif c == ']':
        if tape[ptr] != 0:
            depth = 1
            while depth:
                pc -= 1
                if code[pc] == ']': depth += 1
                elif code[pc] == '[': depth -= 1
    pc += 1
print(''.join(out))
"
```

## 三、编码家族（Base 系列）

### 3.1 识别特征

| 编码 | 特征 | 示例 |
|---|---|---|
| Base16 | 仅 0-9A-F，无等号 | `61646D696E` |
| Base32 | A-Z + 2-7，等号多 | `GEZDGNBVGY3TQOJQGE======` |
| Base64 | A-Za-z0-9+/，等号少 | `ZmxhZ3tCYXNlXzY0fQ==` |
| Base85 | 不含 v-z | `Ao(mgHX\chAi)1qAM#Sp2E39F2` |
| Base91 | 含 v-z | `@iH<,{DTwJ$/KC1jut>xwntX%2ux` |
| Base100 | emoji 表情 | 🎸🦴🦴...'
| Base45 | 0-9A-Z + $%*+-./: | `U.C5EC-QFFL6J-C646QZCD46K` |

### 3.2 CLI 一键转换（无 GUI）

```bash
# Base 全家族互转（Python 脚本）
python3 << 'EOF'
import base64

data = b"flag{base_test}"
print("Base16:", base64.b16encode(data).decode())
print("Base32:", base64.b32encode(data).decode())
print("Base64:", base64.b64encode(data).decode())
print("Base85:", base64.b85encode(data).decode())        # RFC 1924
print("Ascii85:", base64.a85encode(data).decode())       # Adobe

# 解码
b64 = "ZmxhZ3tCYXNlXzY0fQ=="
print("\nBase64 解码:", base64.b64decode(b64).decode())
EOF

# 命令行直接用
echo "ZmxhZ3tCYXNlXzY0fQ==" | base64 -d
echo "61646D696E" | xxd -r -p
```

### 3.3 难识别编码实战

培训 PDF 案例：

```
chgdchg5clctclcxclc5cdc9chcdcdc9chctchglcdc9chclclcdclcpchchchgdchg5...
```

这是 base62 的一种形式（10 数字+26 大写+26 小写），需用专用工具：

```bash
# 在线（GUI）：https://www.wqtool.com/basecode
# CLI 替代：pip install pybase62
pip install pybase62
python3 -c "
import base62
s = 'chgdchg5clctclcxclc5cdc9chcdcdc9chctchglcdc9'
# 注意：原串可能需先按某种映射转回标准 base62 字符
# 这里只演示标准 base62 解码
try:
    decoded = base62.decodebytes(s)
    print(decoded)
except Exception as e:
    print(f'需人工映射: {e}')
"
```

## 四、AES 对称加密

### 4.1 五种工作模式

| 模式 | 是否需填充 | 是否需 IV | 特点 |
|---|---|---|---|
| ECB | 是（PKCS#7） | 否 | 不安全（相同明文→相同密文） |
| CBC | 是（PKCS#7） | 是 | 常用 |
| CTR | 否 | 是（Nonce） | 流式 |
| GCM | 否 | 是（Nonce） | 带 AEAD Tag |
| CFB | 否 | 是 | 流式 |

### 4.2 AES-ECB 解密（CLI，无 GUI）

```bash
python3 << 'EOF'
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii, base64

key = bytes.fromhex('00112233445566778899aabbccddeeff')
ct_hex = '60477dcaea2db1e192ce590bed527bf789db72d896d6eb6e9949222690eb5009'
ct = bytes.fromhex(ct_hex)

cipher = AES.new(key, AES.MODE_ECB)
pt = unpad(cipher.decrypt(ct), AES.block_size)
print(pt.decode())
# 输出: flag{this_is_flag}
EOF
```

### 4.3 AES-CBC 解密（CLI）

```bash
python3 << 'EOF'
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = bytes.fromhex('00112233445566778899aabbccddeeff')
iv = bytes.fromhex('11223344556677889900aabbccddeeff')
ct = bytes.fromhex('8cbb3b779787207daa7bb30d36ffea400036c67edd80388eac66f6aba7c14e76')

cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(ct), AES.block_size)
print(pt.decode())
# 输出: flag{this_is_flag}
EOF
```

### 4.4 AES-GCM 解密（带 Tag，CLI）

```bash
python3 << 'EOF'
from Crypto.Cipher import AES

key = bytes.fromhex('00112233445566778899aabbccddeeff')
nonce = bytes.fromhex('000102030405060708090a0b')
ct = bytes.fromhex('4db956a3d5e3e709ec6740ec4feb2d8c6a62')
tag = bytes.fromhex('4e4cc3c50bcb3e87aaaed0bb3929a142')

cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
pt = cipher.decrypt_and_verify(ct, tag)
print(pt.decode())
# 输出: flag{this_is_flag}
EOF
```

### 4.5 实战：识别 OpenSSL Salted 封装

培训 PDF 案例：

```
密文2: U2FsdGVkX18+HJOxvzO7qoZxyVz5UGU771XiV2HbvqrvbETnSq2W7VKtWjV4TtPvkLO/UvUADkNSQw3nWdWVsA==
key2: admin123
```

**特征识别**：`U2FsdGVkX1` 开头 = `Salted__` 的 Base64，说明是 OpenSSL 风格密码派生。

#### GUI（在线 sojson）

1. 打开 https://www.sojson.com/encrypt_aes.html
2. 密文粘贴，密码填 `admin123`
3. 选 AES，模式自动识别

#### CLI（无 GUI，pycryptodome 模拟 OpenSSL EVP）

```bash
python3 << 'EOF'
import base64, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# OpenSSL enc -aes-256-cbc 默认 KDF：EVP_BytesToKey(md5, salt, password, 1)
b64 = "U2FsdGVkX18+HJOxvzO7qoZxyVz5UGU771XiV2HbvqrvbETnSq2W7VKtWjV4TtPvkLO/UvUADkNSQw3nWdWVsA=="
raw = base64.b64decode(b64)
assert raw[:8] == b'Salted__', "非 Salted 封装"
salt = raw[8:16]
ct = raw[16:]

password = b'admin123'

def evp(password, salt, klen=32, ilen=16):
    d = b''
    prev = b''
    while len(d) < klen + ilen:
        prev = hashlib.md5(prev + password + salt).digest()
        d += prev
    return d[:klen], d[klen:klen+ilen]

key, iv = evp(password, salt)
cipher = AES.new(key, AES.MODE_CBC, iv)
pt = unpad(cipher.decrypt(ct), AES.block_size)
print(pt.decode())
EOF
```

## 五、RC4 流密码

### 5.1 Raw RC4 vs Password-based RC4

| 对比项 | Raw RC4（无 Salt） | Password-based（有 Salt） |
|---|---|---|
| Key 含义 | 直接进 KSA | 密码+salt→KDF→key |
| 随机性 | 相同输入相同输出 | 每次不同 |
| 输出前缀 | Hex/Base64 原始密文 | `U2FsdGVkX1...` |
| 典型工具 | CyberChef RC4 | OpenSSL / CryptoJS |

### 5.2 Raw RC4 解密（CLI）

```bash
python3 << 'EOF'
from Crypto.Cipher import ARC4
import base64

# 培训案例题目1
ct_b64 = "bQBVil/9GH4XInskcCh8k/YJ"
key = b'key'

cipher = ARC4.new(key)
pt = cipher.decrypt(base64.b64decode(ct_b64))
print(pt.decode())
# 输出: flag{rc4_is_funny}
EOF
```

### 5.3 有 Salt RC4 解密（CLI）

```bash
python3 << 'EOF'
import base64, hashlib
from Crypto.Cipher import ARC4

b64 = "ydxQMxtVKOadauk19ZwSPL"   # 培训案例题目2（实际需验证）
# 如果以 U2FsdGVkX1 开头，走 OpenSSL EVP 流程
# 如果是普通 Base64，直接 Raw RC4
raw = base64.b64decode(b64)
if raw[:8] == b'Salted__':
    salt = raw[8:16]; ct = raw[16:]
    # OpenSSL EVP_BytesToKey(md5, salt, 'key', 1) → 16 字节 RC4 key
    d = b''; prev = b''
    while len(d) < 16:
        prev = hashlib.md5(prev + b'key' + salt).digest()
        d += prev
    rc4_key = d[:16]
    cipher = ARC4.new(rc4_key)
    print(cipher.decrypt(ct).decode())
else:
    cipher = ARC4.new(b'key')
    print(cipher.decrypt(raw).decode())
EOF
```

### 5.4 排错清单

| 问题 | 检查点 |
|---|---|
| 解出来乱码 | Base64 字符串不要直接当字节，先 base64.b64decode |
| key 混淆 | UTF-8 `key` vs Hex `6b6579`，不可混用 |
| 看到 U2FsdGVkX1 | 是 Salted 封装，不是 RC4 独有，需提取 salt |
| 网站结果不一致 | 一个是 Raw，一个是 Password-based，参数不同 |

## 六、RSA

### 6.1 RSA 基础公式

```
密钥生成：n = p * q，phi = (p-1)*(q-1)，d = inverse(e, phi)
加密：c = pow(m, e, n)
解密：m = pow(c, d, n)
明文还原：long_to_bytes(m)
```

### 6.2 已知 p、q、e、c（基础题，CLI）

```bash
python3 << 'EOF'
from Crypto.Util.number import long_to_bytes, inverse

p = 105549155105463785131400744596580866446566541449053378094169760664147716478369509416164415058972073978349287815118636991533499798682451297889979721668885951
q = 8246403321715011123191410826902524505032643184038566851264109473851746507405534573077909160292816825514872584170252311902322051822644609979417178306809223
e = 65537
c = 40005881669517895877352756665523238535105922590962714344556374248977905431683140065629966778249773228248201807844489945346731806741025157651474530811920115794270396320935022110691338083709019538562205165553541077855422953438117902279834449006455379382431883650004540282758907332683496655914597029545677184720

n = p * q
phi = (p - 1) * (q - 1)
d = inverse(e, phi)
m = pow(c, d, n)
print(long_to_bytes(m))
EOF
```

### 6.3 未知 p、q，仅知 n（factordb 在线分解）

#### GUI（浏览器）

1. 打开 https://factordb.com/
2. 粘贴 n
3. 查看分解结果，记录 p、q

#### CLI（无 GUI，调 factordb API）

```bash
python3 << 'EOF'
import requests

n = 7382582015733895208810490097582153009797420348201515356767397357174775587237553842395468027650317457503579404097373070312978350435795210286224491315941881
url = f"http://factordb.com/api?query={n}"
r = requests.get(url).json()
print(r)
# {"status":"FF","factors":[["70538125404512947763739093348083497980212021962975762144416432920656660487657",1],["104660876276442216612517835199819767034152013287345576481899196023866133215633",1]]}
if r['status'] == 'FF':
    p = int(r['factors'][0][0])
    q = int(r['factors'][1][0])
    print(f'p = {p}')
    print(f'q = {q}')
EOF
```

### 6.4 yafu 本地分解（CLI，无 GUI）

```bash
# 适合 factordb 查不到的中等大小素数
# Windows
yafu-Win32.exe "factor(7382582015733895208810490097582153009797420348201515356767397357174775587237553842395468027650317457503579404097373070312978350435795210286224491315941881)"

# 输出示例：
# P39 = 70538125404512947763739093348083497980212021962975762144416432920656660487657
# P39 = 104660876276442216612517835199819767034152013287345576481899196023866133215633
```

### 6.5 共模攻击（Common Modulus）

**特征**：两组 (c1, e1) 和 (c2, e2) 使用同一个 n。

#### GUI（轩禹工具）

下载轩禹CTF_RSA工具3.6.1，选择"共模攻击"，填 n、e1、c1、e2、c2。

#### CLI（无 GUI）

```bash
python3 << 'EOF'
from Crypto.Util.number import long_to_bytes
from gmpy2 import gcd, invert

# 假设已知：n, e1, c1, e2, c2
n = 0   # 题目给
e1 = 0; c1 = 0
e2 = 0; c2 = 0

g, s, t = gcd(e1, e2)        # 扩展欧几里得
if g == 1:
    # m = c1^s * c2^t mod n
    s = int(s); t = int(t)
    if s < 0:
        c1 = invert(c1, n); s = -s
    if t < 0:
        c2 = invert(c2, n); t = -t
    m = (pow(c1, s, n) * pow(c2, t, n)) % n
    print(long_to_bytes(m))
EOF
```

### 6.6 Wiener 攻击（e 过大）

**特征**：私钥 d 较小（e 很大）。

```bash
pip install owiener
python3 << 'EOF'
import owiener
from Crypto.Util.number import long_to_bytes

e = 0    # 题目给的大 e
n = 0
c = 0

d = owiener.attack(e, n)
if d:
    m = pow(c, d, n)
    print(long_to_bytes(m))
else:
    print("Wiener 攻击失败，d 不够小")
EOF
```

### 6.7 小 e 攻击（e=3，m^3 < n）

```bash
python3 << 'EOF'
from Crypto.Util.number import long_to_bytes
import gmpy2

e = 3
n = 0    # 题目给
c = 0

# 若 m^3 < n，直接开立方
m, exact = gmpy2.iroot(c, 3)
if exact:
    print(long_to_bytes(int(m)))
else:
    # 可能有填充，尝试 c + k*n 多次开立方
    for k in range(10000):
        m, exact = gmpy2.iroot(c + k * n, 3)
        if exact:
            print(long_to_bytes(int(m)))
            break
EOF
```

### 6.8 共享素数（N 不互素）

**特征**：两道题给 n1、n2，且 gcd(n1, n2) > 1。

```bash
python3 << 'EOF'
from Crypto.Util.number import long_to_bytes, inverse
from gmpy2 import gcd

n1 = 0; c1 = 0; e1 = 65537
n2 = 0; c2 = 0; e2 = 65537

p = int(gcd(n1, n2))   # 共享的素数
assert p > 1, "无共享素数"

q1 = n1 // p
q2 = n2 // p

phi1 = (p - 1) * (q1 - 1)
d1 = inverse(e1, phi1)
m1 = pow(c1, d1, n1)
print(long_to_bytes(m1))
EOF
```

### 6.9 RSA 工具速查

| 工具 | 类型 | 场景 |
|---|---|---|
| factordb | 在线 GUI | 查询 n 是否已分解 |
| yafu | 本地 CLI | 中等素数分解 |
| pycryptodome | Python 库 | RSA 标准运算 |
| gmpy2 | Python 库 | 大数运算、iroot |
| libnum | Python 库 | n2s/s2n 转换 |
| owiener | Python 库 | Wiener 攻击 |
| 轩禹CTF_RSA | Windows GUI | 共模/Wiener/小 e 综合 |

## 七、零宽隐写（Zero-Width Steganography）

**特征**：同一段 txt 看起来一样，但字节长度不同（隐藏零宽字符）。

### 在线工具（GUI）

- http://330k.github.io/misc_tools/unicode_steganography.html
- https://offdev.net/demos/zwsp-steg-js
- https://yuanfux.github.io/zero-width-web/

### CLI（无 GUI）

```bash
python3 << 'EOF'
# 零宽字符：U+200B U+200C U+200D U+FEFF U+2060
zero_chars = ['\u200b', '\u200c', '\u200d', '\ufeff', '\u2060']

with open('suspicious.txt', 'r', encoding='utf-8') as f:
    content = f.read()

# 提取所有零宽字符
hidden = ''.join(c for c in content if c in zero_chars)
print(f"隐藏字符数: {len(hidden)}")
print(f"原始: {hidden!r}")

# 常见编码：每个零宽字符代表 0/1（如 U+200B=0, U+200C=1）
binary = ''
for c in hidden:
    if c == '\u200b': binary += '0'
    elif c == '\u200c': binary += '1'
    elif c == '\u200d': binary += ' '   # 分隔符

# 每 8 位转 ASCII
result = ''
for i in range(0, len(binary.replace(' ', '')), 8):
    byte = binary.replace(' ', '')[i:i+8]
    if len(byte) == 8:
        result += chr(int(byte, 2))
print(f"解码: {result}")
EOF
```

## 八、CTF Crypto 解题决策树

```
拿到密文
  ↓
特征识别
  ├─ 仅 A-Z + 2-7 + =    → Base32
  ├─ A-Za-z0-9+/ + =     → Base64
  ├─ 仅 0-9A-F            → Base16/Hex
  ├─ emoji 表情           → Base100
  ├─ U2FsdGVkX1 开头      → OpenSSL Salted（AES/DES/RC4）
  ├─ 仅 A/B 长度 5 倍     → Bacon
  ├─ 看起来像字母但无意义  → 凯撒/Vigenere/Atbash
  ├─ 数字很大 + e/n/c     → RSA
  ├─ hex 长度 16 倍数 + key/iv → AES
  └─ txt 看起来一样但字节不同 → 零宽隐写
  ↓
选工具
  ├─ 在线（GUI）→ CyberChef / factordb / sojson
  └─ 本地（CLI）→ Python + pycryptodome + gmpy2
  ↓
解码验证
  ├─ 含 flag{...} → 成功
  └─ 仍乱码 → 检查编码层级（Base64→hex→XOR）
```

## 九、参考

- 培训 PDF：Crypto密码学(1).pdf
- CyberChef：https://gchq.github.io/CyberChef/
- pycryptodome 文档：https://pycryptodome.readthedocs.io/
- factordb：https://factordb.com/
