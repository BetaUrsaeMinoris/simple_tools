# -*- coding: utf-8 -*-
# @Author      : LJQ
# @Time        : 2023/3/10 16:50
# @Version     : Python 3.6.4
import base64
import hashlib
import math


def md5(message: (str, bytes)) -> str:
    if isinstance(message, str):
        message = message.encode('utf-8')
    return hashlib.md5(message).hexdigest()


def sha256(message: (str, bytes)) -> str:
    if isinstance(message, str):
        message = message.encode('utf-8')
    return hashlib.sha256(message).hexdigest()


def hmac(key: (str, bytes), message: (str, bytes), digestmod=hashlib.sha256) -> str:
    import hmac
    if isinstance(message, str):
        message = message.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
    return hmac.new(key, message, digestmod=digestmod).hexdigest()


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


def rsa_public_key_decrypt(public_key: str, ciphertext: str, padding: str = 'pkcs1') -> str:
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


def rsa_public_key_encrypt(public_key: str, plaintext: str, padding: str = 'pkcs1') -> str:
    import execjs
    if not hasattr(rsa_public_key_encrypt, 'code'):
        rsa_public_key_encrypt.code = '''
            const NodeRSA = require('node-rsa');
            function encrypt(public_key, ciphertext, padding){
                var key = new NodeRSA("-----BEGIN PUBLIC KEY-----" + public_key	+ "-----END PUBLIC KEY-----");
                key.setOptions({encryptionScheme: padding});
                return key.encrypt(ciphertext, 'base64', 'utf8');
            }'''
        rsa_public_key_encrypt.compiler = execjs.compile(rsa_public_key_encrypt.code)
    return rsa_public_key_encrypt.compiler.call('encrypt', public_key, plaintext, padding)


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


def rsa_encrypt(message: str, public_key: str) -> str:
    from Crypto.Cipher import PKCS1_v1_5
    from Crypto.PublicKey import RSA
    return base64.b64encode(PKCS1_v1_5.new(RSA.importKey(public_key)).encrypt(message.encode())).decode()


def rsa_decrypt(private_key: str, ciphertext: str):
    from Crypto import Random
    from Crypto.Cipher import PKCS1_v1_5
    from Crypto.PublicKey import RSA
    return PKCS1_v1_5.new(RSA.importKey(private_key)).decrypt(
        base64.b64decode(ciphertext.encode('utf-8')),
        Random.new().read
    )


def EVP_BytesToKey(password: bytes, salt: bytes, key_len: int, iv_len: int):
    """
    Derive the key and the IV from the given password and salt.
    """
    encrypts = b''
    while len(encrypts) < (iv_len + key_len):
        encrypts += hashlib.md5(encrypts[-16:] + password + salt).digest()
    return encrypts[:key_len], encrypts[key_len:key_len + iv_len]


def openssl_with_aes_cbc_decrypt(password: bytes, salt: bytes, ciphertext: str) -> str:
    return aes_cbc_decrypt(ciphertext, *EVP_BytesToKey(password, salt, 32, 16))


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
