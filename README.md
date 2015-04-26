# kryptonite
Cryptography for humans. The purpose of this library is to make it easier for python developers to incorporate cyrptography into their applications. There are excellent crypto libraries available for python such as pycrypto, but they only provide cryptographic primitives such as ciphers and hash functions. Developers shouldn't need to know which Cipher to use in order to encrypt data, or whether to digitally sign their data before or after encrypting it. Neither should they know which hash function to use for their password and how to salt it. For the most part, applications could be served by having these are decisions made for them by experts. This underlying philosophy of this library is to provide application developers with the simplest interface possible to cyrptography. Incorporating encryption, for example, should be as easy as using a pair of encrypt/decyrpt functions.

## Install

    pip install kryptonite


## Usage

### Symmetric Encryption

    from kryptonite import Cipher
    key = Cipher.generate_key()
    cipher = Cipher(key)
    cipher_text = cipher.encrypt('my message')
    plain_text = cipher.decrypt(cipher_text)

### Password Management

    from kryptonite import password
    concealed_password = password.conceal('my password')
    if password.verify('my password', concealed_password):
       do_something()

## Development

    git clone https://github.com/gilsho/kryptonite
    pip install -r requirements.txt

and you're good to go!

## Tests
run:

    nosetests

