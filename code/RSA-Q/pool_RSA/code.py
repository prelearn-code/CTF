import gmpy2
import base64
from Crypto.Util.number import long_to_bytes, inverse, isPrime
from tqdm import tqdm

# ================= 题目数据 =================
n = 79832181757332818552764610761349592984614744432279135328398999801627880283610900361281249973175805069916210179560506497075132524902086881120372213626641879468491936860976686933630869673826972619938321951599146744807653301076026577949579618331502776303983485566046485431039541708467141408260220098592761245010678592347501894176269580510459729633673468068467144199744563731826362102608811033400887813754780282628099443490170016087838606998017490456601315802448567772411623826281747245660954245413781519794295336197555688543537992197142258053220453757666537840276416475602759374950715283890232230741542737319569819793988431443
e = 65537
m_b64 = "GVd1d3viIXFfcHapEYuo5fAvIiUS83adrtMW/MgPwxVBSl46joFCQ1plcnlDGfL19K/3PvChV6n5QGohzfVyz2Z5GdTlaknxvHDUGf5HCukokyPwK/1EYU7NzrhGE7J5jPdi0Aj7xi/Odxy0hGMgpaBLd/nL3N8O6i9pc4Gg3O8soOlciBG/6/xdfN3SzSStMYIN8nfZZMSq3xDDvz4YB7TcTBh4ik4wYhuC77gmT+HWOv5gLTNQ3EkZs5N3EAopy11zHNYU80yv1jtFGcluNPyXYttU5qU33jcp0Wuznac+t+AZHeSQy5vk8DyWorSGMiS+J4KNqSVlDs12EqXEqqJ0uA=="

# ================= 攻击工具 =================
def pollard_p_minus_1(n):
    """
    尝试从 n 中提取一个因子
    """
    if isPrime(n):
        return n
    
    a = 2
    # 之前 20万 就能跑出来，这里设稍微大一点保证成功率
    B = 500000 
    
    x = a
    # 这里的步长可以大一点，为了速度
    for i in range(2, B):
        x = pow(x, i, n)
        if i % 5000 == 0:
            d = gmpy2.gcd(x - 1, n)
            if 1 < d < n:
                return d
    
    d = gmpy2.gcd(x - 1, n)
    if 1 < d < n:
        return d
    return None

def factor_n_fully(n):
    """
    循环分解 n，直到所有因子都是素数
    """
    factors = []
    # 待分解列表
    to_factor = [n]
    
    print("[*] 开始全量分解...")
    
    while len(to_factor) > 0:
        curr = to_factor.pop(0)
        
        if isPrime(curr):
            factors.append(curr)
            continue
            
        # 尝试分解 curr
        p = pollard_p_minus_1(curr)
        
        if p:
            print(f"    [+] Found factor: {p}")
            # 把找到的因子 p 和剩余部分 (curr // p) 放回待分解列表
            # 这样如果 p 是合数，或者剩余部分是合数，都会被继续分解
            to_factor.append(p)
            to_factor.append(curr // p)
        else:
            print(f"    [-] 无法分解剩余部分: {curr}")
            print("    [-] 可能需要更大的 B，或者它本身就是素数(但isPrime误判？)")
            # 暂时当做因子加入，避免死循环（实际情况可能需要人工干预）
            factors.append(curr)
            
    return factors

# 1. 执行全量分解