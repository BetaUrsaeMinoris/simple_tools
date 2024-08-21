# -*- coding: utf-8 -*-
# @Author      : LJQ
# @Time        : 2023/3/10 16:50
# @Version     : Python 3.6.4
import base64
import hashlib
import math


def base64decode(data: str) -> bytes:
    return base64.b64decode(data + "=" * (4 - len(data) % 4))


# HMAC
def hmac(key: (str, bytes), message: (str, bytes), digestmod=hashlib.sha256) -> str:
    import hmac
    if isinstance(message, str):
        message = message.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
    return hmac.new(key, message, digestmod=digestmod).hexdigest()


# MD5
def md5(message: (str, bytes)) -> str:
    if isinstance(message, str):
        message = message.encode('utf-8')
    return hashlib.md5(message).hexdigest()


# SHA256
def sha256(message: (str, bytes)) -> str:
    if isinstance(message, str):
        message = message.encode('utf-8')
    return hashlib.sha256(message).hexdigest()


def EVP_BytesToKey(password: bytes, salt: bytes, key_len: int, iv_len: int):
    """
    Derive the key and the IV from the given password and salt.
    """
    encrypts = b''
    while len(encrypts) < (iv_len + key_len):
        encrypts += hashlib.md5(encrypts[-16:] + password + salt).digest()
    return encrypts[:key_len], encrypts[key_len:key_len + iv_len]


# OPENSSL
def openssl_with_aes_cbc_decrypt(password: bytes, salt: bytes, ciphertext: str) -> str:
    return aes_cbc_decrypt(ciphertext, *EVP_BytesToKey(password, salt, 32, 16))


# AES
def aes_cbc_decrypt(ciphertext: str, key: (bytes, str), iv: (bytes, str), pad_mode: str = 'pkcs7'):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(iv, str):
        iv = iv.encode('utf-8')
    plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(base64.b64decode(ciphertext))
    if pad_mode == 'nopadding':
        return plaintext.decode('utf-8')
    elif pad_mode == 'zeropadding':
        return plaintext.strip(b'\0').decode('utf-8')
    else:
        return unpad(plaintext, AES.block_size, pad_mode).decode('utf-8')


def aes_cbc_encrypt(plaintext: (bytes, str), key: (bytes, str), iv: (bytes, str), pad_mode: str = 'pkcs7'):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(iv, str):
        iv = iv.encode('utf-8')
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    plaintext = pad(plaintext, AES.block_size, style=pad_mode)
    return base64.b64encode(AES.new(key, AES.MODE_CBC, iv).encrypt(plaintext)).decode('utf-8')


def aes_ctr_decrypt(ciphertext: (str, bytes), key: (str, bytes), iv: (str, bytes)) -> bytes:
    from Crypto.Cipher import AES
    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(iv, str):
        iv = iv.encode('utf-8')
    cipher = AES.new(key, mode=AES.MODE_CTR, initial_value=iv, nonce=b'')
    return cipher.decrypt(ciphertext)


def aes_ctr_encrypt(plaintext: (str, bytes), key: (str, bytes), iv: (str, bytes)) -> bytes:
    from Crypto.Cipher import AES
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(iv, str):
        iv = iv.encode('utf-8')
    cipher = AES.new(key, mode=AES.MODE_CTR, initial_value=iv, nonce=b'')
    return cipher.encrypt(plaintext)


def aes_decrypt(ciphertext: str, key: (bytes, str), iv: (bytes, str), pad_mode: str = 'pkcs7', *, mode: int = 2):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(iv, str):
        iv = iv.encode('utf-8')
    plaintext = AES.new(key, mode, iv, segment_size=128).decrypt(base64.b64decode(ciphertext))
    if pad_mode == 'nopadding':
        return plaintext.decode('utf-8')
    elif pad_mode == 'zeropadding':
        return plaintext.strip(b'\0').decode('utf-8')
    else:
        return unpad(plaintext, AES.block_size, pad_mode).decode('utf-8')


def aes_encrypt(plaintext: str, key: (bytes, str), iv: (bytes, str), pad_mode: str = 'pkcs7', *, mode: int = 2):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(iv, str):
        iv = iv.encode('utf-8')
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    if pad_mode == 'nopadding':
        plaintext = plaintext
    else:
        plaintext = pad(plaintext, AES.block_size, style=pad_mode)
    return base64.b64encode(AES.new(key, mode, iv, segment_size=128).encrypt(plaintext)).decode('utf-8')


# RC4
def rc4_decrypt(ciphertext: (bytes, str), key: (bytes, str), encoding='utf-8'):
    from Crypto.Cipher import ARC4
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode('utf-8')
    return ARC4.new(key).decrypt(ciphertext).decode(encoding)


def rc4_encrypt(plaintext: (bytes, str), key: (bytes, str)):
    from Crypto.Cipher import ARC4
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    return ARC4.new(key).encrypt(plaintext)


# RSA
def rsa_decrypt(private_key: str, ciphertext: str):
    from Crypto import Random
    from Crypto.Cipher import PKCS1_v1_5
    from Crypto.PublicKey import RSA
    return PKCS1_v1_5.new(RSA.importKey(private_key)).decrypt(
        base64.b64decode(ciphertext.encode('utf-8')),
        Random.new().read
    )


def rsa_encrypt(message: str, public_key: str) -> str:
    from Crypto.Cipher import PKCS1_v1_5
    from Crypto.PublicKey import RSA
    return base64.b64encode(PKCS1_v1_5.new(RSA.importKey(public_key)).encrypt(message.encode())).decode()


def rsa_public_key_decrypt(public_key: str, ciphertext: str) -> str:
    # RSA 公钥解密
    # RSA 加密只跟e, n有关, ciphertext = pow(plaintext, e, n)
    # RSA 解密只和d, n有关, plaintext = pow(ciphertext, d, n)
    # 所有n和ciphertext/plaintext字节必须保持一致
    # 如n为2048位, 即256字节
    # ciphertext为512字节, 则必须切分为两组, 才能进行pow运算
    # plaintext为260字节, 则必须切分为两组, 每组必须填充到256字节
    import rsa
    pem_public_key = f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----"
    pk = rsa.PublicKey.load_pkcs1_openssl_pem(pem_public_key.encode(encoding='utf-8'))
    batch_size = math.ceil(pk.n.bit_length() / 8)
    ciphertext = base64.b64decode(ciphertext)
    if len(ciphertext) % batch_size:
        raise ValueError("ciphertext length error!")
    plaintext = b''
    for start in range(0, len(ciphertext), batch_size):
        pt = pow(
            int.from_bytes(ciphertext[start:start + batch_size], byteorder='big'),
            pk.e,
            pk.n
        ).to_bytes(batch_size, byteorder='big')
        index = pt.index(b"\x00", 2)
        plaintext += pt[index + 1:]
    return plaintext.decode(encoding='utf-8')


def rsa_public_key_decrypt_by_js(public_key: str, ciphertext: str, padding: str = 'pkcs1') -> str:
    import execjs
    if not hasattr(rsa_public_key_decrypt, 'code'):
        rsa_public_key_decrypt.code = '''
            const NodeRSA = require('node-rsa');
            function decrypt(public_key, ciphertext, padding){
                var key = new NodeRSA("-----BEGIN PUBLIC KEY-----" + public_key	+ "-----END PUBLIC KEY-----");
                key.setOptions({encryptionScheme: padding});
                return key.decryptPublic(ciphertext, 'base64', 'utf8');
            }'''
        rsa_public_key_decrypt.compiler = execjs.compile(rsa_public_key_decrypt.code)
    encode_text = rsa_public_key_decrypt.compiler.call('decrypt', public_key, ciphertext, padding)
    return base64.b64decode(encode_text).decode('utf-8')


def rsa_public_key_encrypt(public_key: str, plaintext: str) -> str:
    return rsa_encrypt(plaintext, f"-----BEGIN PUBLIC KEY-----\n{public_key}\n-----END PUBLIC KEY-----")


def rsa_no_padding(plaintext: (str, bytes), modulus: (int, str), exponent: (int, str) = '10001'):
    """
    var e = RSAUtils.getKeyPair("10001", "", "ab86b6371b5318aaa1d3c9e612a9f1264f372323c8c0f19875b5fc3b3fd3afcc1e5bec527aa94bfa85bffc157e4245aebda05389a5357b75115ac94f074aefcd");
    return RSAUtils.encryptedString(e, encodeURIComponent(t)).replace(/\s/g, "-")
    :param plaintext:
    :param modulus: ab86b6371b5318aaa1d3c9e612a9f1264f372323c8c0f19875b5fc3b3fd3afcc1e5bec527aa94bfa85bffc157e4245aebda05389a5357b75115ac94f074aefcd
    :param exponent: 10001
    :return:
    """
    if isinstance(modulus, str):
        modulus = int(modulus, 16)
    if isinstance(exponent, str):
        exponent = int(exponent, 16)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    plaintext = int.from_bytes(plaintext[::-1], byteorder='big')
    ciphertext = pow(plaintext, exponent, modulus).to_bytes(math.ceil(modulus.bit_length() / 8), byteorder='big').hex()
    return ciphertext
