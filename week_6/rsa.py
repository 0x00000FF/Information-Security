
def gcd(a: int, b: int) -> int:
    """
    최대공약수를 구하는 함수
    유클리드 호제법을 이용
    :param a: operand a
    :param b: operand b
    :return: calculated GCD(greatest common division)
    """
    while b != 0:
        a, b = b, a % b
    return a


def lcm(a: int, b: int) -> int:
    """
    최소공배수를 구하는 함수
    gcd 값을 이용
    :param a: operand a
    :param b: operand b
    :return:  calculated LCM(leatest common multiple)
    """
    # keep in mind that LG=AB
    # then we can determine L = AB/G
    return a * b // gcd(a, b)

def extended_euclidean(a: int, b: int) -> (int, int):
    """
    확장 유클리드 호제법
    ax + by = gcd 를 만족시키는 x, y 값을 계산하는 함수
    :param a: coefficient a
    :param b: coefficient b
    :return: determined unknown pair (x, y)
    """
    x0, y0 = 1, 0
    x1, y1 = 0, 1

    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return x0, y0


def inverse(a: int, mod: int) -> int:
    """
    modular inverse 값
    inverse를 계산할 수 없는 경우 (gcd 값이 1이 아닌 경우) Value Error를 raise 해야 함
    :param a: known coefficient
    :param mod: modulo operand
    :return: modulo inverse of a
    """

    # mod must be positive integer
    if mod <= 0:
        raise ValueError("mod is not valid")

    if gcd(a, mod) != 1:
        raise ValueError("a and mod must be coprimes")

    # from ax (equiv) 1 mod M
    # then we can transform this equation as
    # ax = My + 1
    # ax - My = 1
    # ax + My = 1 (y can be a negative integer)
    # apply extended euclidean algorithm on the equation above
    # then x should be modulo inverse of a (a^-1)
    x, _ = extended_euclidean(a, mod)

    # from pycryptodome, Crypto.Math.Integer.inplace_inverse, Ln 319
    while x < 0:
        x += mod

    # these two cases can occur test failure
    # return x
    return x % mod


class RSAKey:
    def __init__(self, p, q):
        self.p = p
        self.q = q
        self.n = p * q
        self.e = self.public()
        self.d = self.private()

    def public(self, e=2) -> int:
        """
        조건을 만족하는 public key 를 구하는 함수
        e가 totient 함수 값과 서로소여야 함
        :return: calculated public key
        """
        totient = lcm(self.p-1, self.q-1)
        while gcd(e, totient) != 1:
            e += 1
        return e

    def private(self) -> int:
        """
        public key에 맞는 private key를 계산하는 함수
        totient 함수 값의 mod 연산에 대한 e의 곱셈 역원을 계산
        :return: calculated private key
        """

        # ed (equiv) 1 mod fi(N)
        # then modulo inverse of e should be d
        return inverse(self.e, lcm(self.p - 1, self.q - 1))

    def set_e(self, e: int):
        """
        public key를 설정하는 함수
        :param e: public key
        :return:  nothing
        """
        self.e = self.public(e)
        self.d = self.private()

    def encrypt(self, m: int):
        """
        공개키로 값을 암호화하는 함수
        개인키로 암호화한 값을 복호화할 수 있음

        암호화 하는 값은 int 값임을 가정
        :param m: message (plaintext)
        :return:  ciphertext
        """
        # RSA encryption is m^e mod N
        # pow function provides power operation within mod N
        return pow(m, self.e, self.n)

    def decrypt(self, m: int):
        """
        개인키로 값을 암호화하는 함수 ( 서명 )
        공개키로 암호화한 값을 복호화할 수 있음
        :param m: ciphertext
        :return:  decrypted plaintext
        """
        # RSA decryption is c^d mod N
        # pow function provides power operation within mod N
        return pow(m, self.d, self.n)