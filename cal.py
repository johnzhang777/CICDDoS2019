from decimal import Decimal, getcontext

# 设置精度（小数点后位数）
getcontext().prec = 50  # 设置50位精度

A = Decimal(0.9845)
P = Decimal(0.9785)
R = Decimal(0.9536)

tmp1 = Decimal(1) / Decimal(R) + Decimal(1) / Decimal(P) - Decimal(2)
tmp2 = tmp1 * Decimal(A) / (Decimal(1) - Decimal(A)) - Decimal(1)

tmp3 = tmp2 * (Decimal(1) / (Decimal(1) / Decimal(P) - Decimal(1)))

fpr = Decimal(1) / (1 + tmp3)

print(fpr)

a = Decimal(9452) * Decimal(526) / Decimal(9474)

b = Decimal(9452) * Decimal(796) / Decimal(9204)

c = (a + b) / Decimal(548) - Decimal(1)

d = c * Decimal(9474) / Decimal(526)

fpr = Decimal(1) / (1 + d)

print(fpr)