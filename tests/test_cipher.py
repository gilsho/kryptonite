#!/usr/bin/env python
from Crypto.Hash import SHA256
from mock import Mock
import random
import unittest

from kryptonite import Cipher, DecryptionError
from utils import random_string

# Python3 compatibility code
try:
    range = xrange
except NameError:
    pass


class TestCipher(unittest.TestCase):

    def test_cipher_basic(self):
        key = Cipher.generate_key()
        cipher = Cipher(key)
        msg = "hello world!"
        enc = cipher.encrypt(msg)
        self.assertNotEqual(msg, enc)
        self.assertEqual(cipher.decrypt(enc), str.encode(msg))

    def test_no_repeatability(self):
        key = Cipher.generate_key()
        cipher = Cipher(key)
        msg = "hello san francisco"
        hist = set()
        for _ in range(1000):
            enc = cipher.encrypt(msg)
            self.assertNotIn(enc, hist)
            hist.add(enc)

    def test_two_ciphers(self):
        key = Cipher.generate_key()
        cipher1 = Cipher(key)
        cipher2 = Cipher(key)
        msg = "magic"
        enc = cipher1.encrypt(msg)
        self.assertEqual(cipher2.decrypt(enc), str.encode(msg))

    def test_malleability_detection(self):
        key = Cipher.generate_key()
        cipher = Cipher(key)
        msg = random_string(1000)
        enc = cipher.encrypt(msg)
        index = random.randint(0, len(enc))
        original_char = enc[index]
        new_char = random_string(1)
        if original_char == new_char:
            return
        enc = enc[:index] + str.encode(new_char) + enc[index + 1:]
        exception_raised = False
        try:
            cipher.decrypt(enc)
        except DecryptionError:
            exception_raised = True
        self.assertTrue(exception_raised)

    def test_extension_attack(self):
        shaobj = SHA256.new()
        orig = SHA256.new
        SHA256.new = Mock()
        SHA256.new.return_value = shaobj
        key = Cipher.generate_key()
        cipher = Cipher(key)
        msg = random_string(1000)
        enc = cipher.encrypt(msg)
        extra = str.encode(random_string(16))
        extended_content = enc[SHA256.digest_size:] + extra
        shaobj.update(extended_content)
        extended_signature = shaobj.digest()
        extended = extended_signature + extended_content
        exception_raised = False
        try:
            cipher.decrypt(extended)
        except DecryptionError:
            exception_raised = True
        finally:
            SHA256.new = orig
        self.assertTrue(exception_raised)

    def test_cipher_stress(self):
        key = Cipher.generate_key()
        cipher = Cipher(key)
        for _ in range(1000):
            msg = random_string(1000)
            algo = cipher.decrypt(cipher.encrypt(msg))
            self.assertEqual(algo, str.encode(msg))


if __name__ == '__main__':
    unittest.main()
