# HFUTCryptoHomework

合肥工业大学信息安全技术作业，本项目主要实现了RSA和DES两种加密算法

## 算法原理

### RSA

RSA加密算法是一种非对称加密算法，于1978年由Ron Rivest、Adi Shamir和Leonard Adleman提出，算法名称就是根据他们的名字首字母得来。非对称加密意味着加密和解密过程使用不同的密钥。在RSA算法中，有一对密钥：公钥和私钥。公钥用于加密数据，私钥用于解密数据。通常，公钥是公开的，任何人都可以用它加密数据；私钥是保密的，仅拥有者可以用它解密数据。

RSA加密算法的原理基于数论和大数计算。以下是算法的主要步骤：

1. 选择两个大质数 ${p}$ 和 ${q}$ 。
2. 计算${$n = p\times q}$。{$n}$用于构建公钥和私钥，是模数。
3. 计算欧拉函数${\varphi(n) = (p-1)(q-1)}$。
4. 选择一个整数${e}$，使得${1 < e < \varphi(n)}$，且${e}$与${\varphi(n)}$互质${(gcd(e, \varphi(n)) = 1)}$。e是公钥的一部分。
5. 计算整数${d}$，使得${d ≡ e⁻¹ (mod \varphi(n))}$。换句话说，找到一个数${d}$，满足${ed ≡ 1 (mod \varphi(n))}$。d是私钥的一部分。
6. 公钥为 $(n, e)$，私钥为 $(n, d)$。

加密和解密的过程如下：

1. 加密：假设明文消息为${M(0 < M < n)}$，密文C可以通过以下公式计算：${C ≡ M^e (mod n)}$。
2. 解密：已知密文${C}$，明文消息${M}$可以通过以下公式计算：${M ≡ C^d (mod n)}$。

RSA算法的安全性依赖于大数因子分解的困难性，即随着密钥长度(${n}$的位数)的增加，攻击难度呈指数级增长。给定${n}$的值，分解出${p}$和${q}$是非常困难的，特别是当${p}$和${q}$都是大质数时。目前，尚无已知的高效算法能够在合理时间内分解大数${n}$。

### DES

