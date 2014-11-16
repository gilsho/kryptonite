#!/usr/bin/env python

import random
import string


def random_string(n):
    chars = (string.letters + string.digits + string.punctuation)
    msg = ''.join(random.choice(chars) for x in xrange(n))
    return msg
