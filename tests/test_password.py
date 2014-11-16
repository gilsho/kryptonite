##!/usr/bin/env python

import random
import unittest

from kryptonite import conceal, verify
from tests.utils import random_string


class TestCipher(unittest.TestCase):

    def test_verify_success(self):
        msg = random_string(40)
        self.assertTrue(verify(msg, conceal(msg)))

    def test_verify_fail(self):
        msg = random_string(40)
        index = random.randint(0, len(msg))
        original_char = msg[index]
        new_char = random_string(1)
        if original_char == new_char:
            return
        wrong = msg[:index] + new_char + msg[index + 1:]
        self.assertFalse(verify(wrong, conceal(msg)))


if __name__ == '__main__':
    unittest.main()
