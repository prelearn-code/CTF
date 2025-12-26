import sage.all as sage
from sage.all import is_prime, factor, inverse_mod

# --- 定义 N 和 e ---
N = 8693448229604811919066606200349480058890565601720302561721665405
e = 8378322103517

print(f"N = {N}")
print(f"Is N prime? {is_prime(N)}")

# --- 步骤 1: 分解 N ---
factors_list = list(factor(N))
print(f"Factors and their powers: {factors_list}")

# 提取质因数 p 和 q (假设 N 是两个质数的乘积)
if len(factors_list) == 2 and factors_list[0][1] == 1 and factors_list[1][1] == 1:
    p = factors_list[0][0]
    q = factors_list[1][0]
    print(f"Found two prime factors: p = {p}, q = {q}")

    # --- 步骤 2: 计算 phi_N 和 d ---
    phi_N = (p - 1) * (q - 1)
    print(f"phi(N) = (p-1) * (q-1) = {phi_N}")

    d = inverse_mod(e, phi_N)
    print(f"Private exponent d = {d}")

    # --- 步骤 3: 读取 c 并解密 ---
    with open('/home/zsw/codes/CTF/data/RSA/flag.enc', 'rb') as f:
        c_bytes = f.read()
    c = int.from_bytes(c_bytes, byteorder='big')
    print(f"Encrypted value c (as integer): {c}")

    m = pow(c, d, N)
    print(f"Decrypted value m (as integer): {m}")

    # --- 步骤 4: 将 m 转换为字符串 ---
    hex_m = hex(m)[2:]
    if len(hex_m) % 2:
        hex_m = '0' + hex_m

    try:
        secret_message = bytes.fromhex(hex_m).decode('ascii', errors='ignore')
        print("The secret message is:")
        print(secret_message)
    except ValueError:
        print("Failed to convert decrypted integer to ASCII string.")
        print(f"Hex representation of m: {hex_m}")
else:
    print(f"N does not appear to be a product of two distinct primes (or factorization failed quickly). Factors found: {factors_list}")