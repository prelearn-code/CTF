from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# ========== 根据你的实际情况填这些值 ==========
# 你可以用十进制 int，或者 hex 字符串手动转成 int



# 如果你已经是 int，就直接赋值即可：
n = 86934482296048119190666062003494800588905656017203025617216654058378322103517
e = 65537
d = 81176168860169991027846870170527607562179635470395365333547868786951080991441
p = 285960468890451637935629440372639283459
q = 304008741604601924494328155975272418463

# ============================================

# 简单的扩展欧几里得算法，求模逆
def modinv(a, m):
    """返回 a 在模 m 下的乘法逆元，即 a * x ≡ 1 (mod m) 的 x"""
    def egcd(x, y):
        if y == 0:
            return x, 1, 0
        g, s, t = egcd(y, x % y)
        return g, t, s - (x // y) * t

    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("a 和 m 不互素，逆元不存在")
    return x % m


# 计算 CRT 相关参数
dp = d % (p - 1)        # d mod (p-1)
dq = d % (q - 1)        # d mod (q-1)
qi = modinv(q, p)       # q^{-1} mod p

# 构造 RSA 私钥对象
private_numbers = rsa.RSAPrivateNumbers(
    p=p,
    q=q,
    d=d,
    dmp1=dp,
    dmq1=dq,
    iqmp=qi,
    public_numbers=rsa.RSAPublicNumbers(e=e, n=n)
)

private_key = private_numbers.private_key()

# 导出为 PKCS#1 PEM 格式（OpenSSL 默认能识别）
pem_bytes = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,  # 即 "BEGIN RSA PRIVATE KEY"
    encryption_algorithm=serialization.NoEncryption()       # 不加密，如需密码可改这里
)

# 写入文件
with open("rsa_key.pem", "wb") as f:
    f.write(pem_bytes)

print("RSA 私钥已写入 rsa_key.pem，可用 openssl 直接使用。")
