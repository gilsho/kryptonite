#!/usr/bin/env python

from Crypto.Hash import SHA256
from mock import Mock
import random
import unittest

from kryptonite import Cipher, DecryptionError
from tests.utils import random_string


class TestCipher(unittest.TestCase):

    def test_cipher_basic(self):
        key = Cipher.generate_key()
        cipher = Cipher(key)
        msg = "hello world!"
        enc = cipher.encrypt(msg)
        self.assertNotEquals(msg, enc)
        self.assertEquals(cipher.decrypt(enc), msg)

    def test_no_repeatability(self):
        key = Cipher.generate_key()
        cipher = Cipher(key)
        msg = "hello san francisco"
        hist = set()
        for _ in xrange(1000):
            enc = cipher.encrypt(msg)
            self.assertNotIn(enc, hist)
            hist.add(enc)

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
        enc = enc[:index] + new_char + enc[index + 1:]
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
        extra = random_string(16)
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
        for _ in xrange(1000):
            msg = random_string(1000)
            algo = cipher.decrypt(cipher.encrypt(msg))
            self.assertEquals(algo, msg)


if __name__ == '__main__':
    unittest.main()
