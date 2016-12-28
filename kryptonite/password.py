#!/usr/bin/env python

from passlib.context import CryptContext

ROUNDS_OF_HASHING = 2 ** 12

password_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    default="pbkdf2_sha256",
    all__vary_rounds=0.0,
    pbkdf2_sha256__default_rounds=ROUNDS_OF_HASHING)


def conceal(plain):
    return password_context.hash(plain.encode('utf-8'))


def verify(plain, concealed):
    return password_context.verify(plain.encode('utf-8'), concealed)
