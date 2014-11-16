#! /usr/bin/env python

import binascii
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util import Counter
from passlib.context import CryptContext


password_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    default="pbkdf2_sha256",
    all__vary_rounds=0.0,
    pbkdf2_sha256__default_rounds=2**12)


class EncryptionError(RuntimeError):
    pass


class DecryptionError(RuntimeError):
    pass


def hash_password(password):
    return password_context.encrypt(password.encode('utf-8'))


def verify_password(password, password_hash):
    return password_context.verify(password.encode('utf-8'), password_hash)


class Cipher(object):

    __CIPHER_KEY_EXPANSION__ = '\xe7r\x86\xd5]&||\x00o-\x93P\x85\x0cS'
    __MAC1_KEY_EXPANSION__ = '\xab!\xb0\xc7\xa9A0\x03\x92\xb1I\x82y\xf2K\x8b'
    __MAC2_KEY_EXPANSION__ = '~\x83kF\xf8\xd05\x84\xb6\x8bL\x8d\xcd\x10:$'

    def __init__(self, key):
        ctr = Counter.new(AES.block_size * 8, initial_value=1)
        cipher = AES.AESCipher(key, AES.MODE_CTR, counter=ctr)
        self._cipherkey = cipher.encrypt(self.__CIPHER_KEY_EXPANSION__)
        self._mackey1 = cipher.encrypt(self.__MAC1_KEY_EXPANSION__)
        self._mackey2 = cipher.encrypt(self.__MAC2_KEY_EXPANSION__)

    @staticmethod
    def random_bytes(n):
        return Random.new().read(n)

    @classmethod
    def generate_key(cls):
        return cls.random_bytes(AES.block_size)

    @staticmethod
    def bin2long(n):
        """translates a binary seuquence into a long integer"""
        return long(binascii.hexlify(n), 16)

    def sign(self, msg):
        """sign a message"""
        signature = SHA256.new()
        signature.update(self._mackey1)
        signature.update(msg)
        signature.update(self._mackey2)
        return signature.digest()

    def encrypt(self, msg):
        """encrypts a message"""
        iv = self.random_bytes(AES.block_size)
        ctr = Counter.new(AES.block_size * 8, initial_value=self.bin2long(iv))
        cipher = AES.AESCipher(self._cipherkey, AES.MODE_CTR, counter=ctr)
        cipher_text = cipher.encrypt(msg)
        intermediate = iv + cipher_text
        signature = self.sign(intermediate)
        return signature + intermediate

    def decrypt(self, msg):
        """decrypt a message"""
        error = False
        signature = msg[0:SHA256.digest_size]
        iv = msg[SHA256.digest_size:SHA256.digest_size + AES.block_size]
        cipher_text = msg[SHA256.digest_size + AES.block_size:]
        if self.sign(iv + cipher_text) != signature:
            error = True
        ctr = Counter.new(AES.block_size * 8, initial_value=self.bin2long(iv))
        cipher = AES.AESCipher(self._cipherkey, AES.MODE_CTR, counter=ctr)
        plain_text = cipher.decrypt(cipher_text)
        if error:
            raise DecryptionError
        return plain_text

# if __name__ == "__main__":
#     import random as rand
#     import string
#     key = Cipher.generate_key()
#     cipher = Cipher(key)
#     chars = (string.letters + string.digits + string.punctuation)
#     for i in xrange(1000):
#         msg = ''.join(rand.choice(chars) for x in xrange(1000))
#         algo = cipher.decrypt(cipher.encrypt(msg))
#         if algo != msg:
#             print "Error"
#             exit(1)
#     print "Success"
