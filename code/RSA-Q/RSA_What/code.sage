import base64
from Crypto.Util.number import long_to_bytes

def solve_stego(rsa_output):
    print("[*] 检测到 Base64 隐写，开始提取...")
    
    # 1. 按行分割
    lines = rsa_output.strip().split(b'\n')
    
    bin_str = ""
    base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    
    for line in lines:
        line = line.strip()
        if not line: continue
        
        # 转换为字符串处理
        s = line.decode()
        
        # 2. 判断 Padding 数量，提取隐写位
        if s.endswith("=="):
            # 2个等号，说明最后剩 1 个字节 (8bit)，编码成 2 个字符 (12bit)
            # 也就意味着隐写了 12 - 8 = 4 bit
            last_char = s[-3] # 倒数第三个字符是最后一个有效编码字符 (== 是最后两个)
            # 查找该字符在 Base64 表中的索引
            char_idx = base64_chars.index(last_char)
            # 取低 4 位
            bits = f"{char_idx:06b}"[-4:]
            bin_str += bits
            
        elif s.endswith("="):
            # 1个等号，说明最后剩 2 个字节 (16bit)，编码成 3 个字符 (18bit)
            # 也就意味着隐写了 18 - 16 = 2 bit
            last_char = s[-2] # 倒数第二个字符
            char_idx = base64_chars.index(last_char)
            # 取低 2 位
            bits = f"{char_idx:06b}"[-2:]
            bin_str += bits
            
    # 3. 将提取出的二进制串转换为字符
    print(f"[*] 提取到的二进制位长度: {len(bin_str)}")
    
    flag_bytes = b""
    for i in range(0, len(bin_str), 8):
        byte_chunk = bin_str[i:i+8]
        if len(byte_chunk) == 8:
            flag_bytes += bytes([int(byte_chunk, 2)])
            
    print("-" * 30)
    print("HIDDEN FLAG:")
    print(flag_bytes.decode(errors='ignore'))
    print("-" * 30)


def solve():
    print("[*] 正在读取 HUB1 和 HUB2...")
    
    # 读取文件逻辑（保持不变）
    try:
        with open("HUB1", "r") as f:
            content1 = f.read().split()
            N = Integer(content1[0])
            e1 = Integer(content1[1])
            c1_list = [Integer(x) for x in content1[2:] if x.strip()]

        with open("HUB2", "r") as f:
            content2 = f.read().split()
            e2 = Integer(content2[1])
            c2_list = [Integer(x) for x in content2[2:] if x.strip()]
    except Exception as e:
        print(f"[-] 读取文件出错: {e}")
        return

    # 检查互质
    g, s1, s2 = xgcd(e1, e2)
    if g != 1:
        print("[-] e1 和 e2 不互质，攻击无法进行！")
        return

    print("[*] 开始解密...")
    rsa_recovered_bytes = b"" 

    # 逐块解密
    for c1, c2 in zip(c1_list, c2_list):
        v1 = power_mod(c1, s1, N)
        v2 = power_mod(c2, s2, N)
        m = (v1 * v2) % N
        

        chunk = long_to_bytes(m)
        
      
        rsa_recovered_bytes += chunk


    print("\n" + "-"*30)
    print("【调试信息】RSA 解密结果前 100 个字符：")
    print("-"*30)
    
    # 打印原始字节的十六进制表示，看看是不是乱码
    print(f"Hex: {rsa_recovered_bytes[:20].hex()} ...")
    solve_stego(rsa_recovered_bytes)
    
    # 尝试作为文本打印，看看是不是像 Base64 (A-Z, a-z, 0-9, +, /)
    try:
        preview = rsa_recovered_bytes[:100].decode('ascii')
        print(f"Text: {preview}")
        
        # 简单的启发式检查
        import re
        if re.match(r'^[A-Za-z0-9+/=\s]+$', preview):
            print("==> 看起来像是有效的 Base64 字符串！")
        else:
            print("==> 警告：包含非 Base64 字符，RSA 解密可能出错了！")
            
    except UnicodeDecodeError:
        print("==> 警告：无法解码为 ASCII，说明解密结果是二进制乱码！")

    # ==========================================
    # 尝试 Base64 解码
    # ==========================================
    print("\n[*] 正在尝试 Base64 解码...")
    try:
        # 在 Python 3 中，b64decode 对于错误的 padding 极其敏感
        # 这是一个常见的 trick：手动补全 padding
        missing_padding = len(rsa_recovered_bytes) % 4
        if missing_padding:
            rsa_recovered_bytes += b'=' * (4 - missing_padding)
            
        final_flag = base64.b64decode(rsa_recovered_bytes)
        
        print("\n" + "="*30)
        print("FINAL FLAG:")
        # 尝试 decode 为 utf-8 显示，如果不行直接显示 bytes
        try:
            print(final_flag.decode())
        except:
            print(final_flag)
        print("="*30)
        
    except Exception as e:
        print(f"[-] Base64 解码最终失败: {e}")
        print("建议检查上面打印的【调试信息】，如果是乱码，说明共模攻击本身算错了。")

solve()