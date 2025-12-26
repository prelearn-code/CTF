import base64
from Crypto.Util.number import long_to_bytes, inverse

# 1. 题目给出的数据
p = 177077389675257695042507998165006460849
n = 37421829509887796274897162249367329400988647145613325367337968063341372726061
# 题目给出的加密字符串
c_str_reversed = "==gMzYDNzIjMxUTNyIzNzIjMyYTM4MDM0gTMwEjNzgTM2UTN4cjNwIjN2QzM5ADMwIDNyMTO4UzM2cTM5kDN2MTOyUTO5YDM0czM3MjM"

# 2. 计算 q 和 phi
q = n // p
phi = (p - 1) * (q - 1)

# 3. 还原密文 c (整数)
# 第一步：字符串逆序
c_str_b64 = c_str_reversed[::-1]
# 第二步：Base64 解码 (注意题目虽然叫 b32encode 但实际是 imports b64encode)

c_int_str = base64.b64decode(c_str_b64)
# 第三步：转为整数
c = int(c_int_str)

print(f"[*] Recovered c: {c}")

# 4. 爆破 e 并解密
print("[*] Brute forcing e...")

# e 的范围在 50000 到 70000 之间
for e_guess in range(50000, 70001):
    # e 必须与 phi 互质
    if e_guess % 2 == 0: # 简单的优化，phi通常是偶数，e通常是奇数
        continue
        
    try:
        # 尝试计算私钥 d
        # 如果 e_guess 和 phi 不互质，inverse 会报错，所以用 try-except
        d = inverse(e_guess, phi)
        
        # 尝试解密 m = c^d mod n
        m = pow(c, d, n)
        
        # 将明文整数转换为字节流
        flag_bytes = long_to_bytes(m)
        
        # 检查是否包含 flag 特征
        if b"flag" in flag_bytes:
            print(f"\n[+] Found e: {e_guess}")
            print(f"[+] Flag: {flag_bytes.decode()}")
            print(f"{flag_bytes}")
            print(f"{flag_bytes.hex()}")
            break
            
    except Exception:
        continue