import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# ================= 配置区域 =================

# 1. 输入你的公钥 N 和 e
# (SageMath 会自动处理大整数，直接填入即可)
n = 86934482296048119190666062003494800588905656017203025617216654058378322103517
e = 65537

# 2. 指定输出路径
output_file_path = "/home/zsw/codes/CTF/data/rsa/rsa_private.pem"

# ===========================================

print(f"[-] 正在分解 n ({n.bit_length()} bits)...")

# 【核心步骤】使用 SageMath 内置函数分解 n
# factor(n) 返回的是一个分解对象，类似于 list([(p, 1), (q, 1)])
factors_obj = factor(n)

# 检查分解结果是否符合 RSA 标准 (两个质数)
if len(factors_obj) != 2:
    print(f"[!] 警告: n 分解后的因子数量不是 2，结果为: {factors_obj}")
    print("    尝试取前两个因子作为 p 和 q...")

p = factors_obj[0][0]
q = factors_obj[1][0]

print(f"    p = {p}")
print(f"    q = {q}")

print("[-] 正在计算私钥 d 和 CRT 参数...")

# 计算欧拉函数 phi
phi = (p - 1) * (q - 1)

# 计算私钥 d = e^-1 mod phi
d = inverse_mod(e, phi)

# 计算 CRT 参数
# 注意：必须转换为 Python 原生 int，否则 cryptography 库可能会报错
dp = int(d % (p - 1))
dq = int(d % (q - 1))
qi = int(inverse_mod(q, p))

# 将 Sage 的 Integer 转换为 Python int
n_int = int(n)
e_int = int(e)
d_int = int(d)
p_int = int(p)
q_int = int(q)

print("[-] 正在生成 PEM 文件...")

try:
    # 构造 RSA 私钥对象
    private_numbers = rsa.RSAPrivateNumbers(
        p=p_int,
        q=q_int,
        d=d_int,
        dmp1=dp,
        dmq1=dq,
        iqmp=qi,
        public_numbers=rsa.RSAPublicNumbers(e=e_int, n=n_int)
    )

    private_key = private_numbers.private_key()

    # 导出为 PEM 格式
    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # 确保目录存在
    output_dir = os.path.dirname(output_file_path)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # 写入文件
    with open(output_file_path, "wb") as f:
        f.write(pem_bytes)
    
    print(f"[SUCCESS] 私钥已成功写入: {output_file_path}")

except Exception as err:
    print(f"[ERROR] 生成失败: {err}")