#!/usr/bin/env python

'''
Creates BitCoin Wallet complaint credentials:
- Public Key
- Private Key
- Private Key (Wallet Import Format)
'''

import hashlib
import base58
import ecdsa
import codecs

from ecdsa.keys import SigningKey
from utilitybelt import dev_random_entropy
from binascii import hexlify, unhexlify


def random_secret_exponent(curve_order):
    while True:
        random_hex = hexlify(dev_random_entropy(32))
        random_int = int(random_hex, 16)
        if 1 <= random_int < curve_order:
            return random_int


def generate_private_key():
    curve = ecdsa.curves.SECP256k1
    se = random_secret_exponent(curve.order)
    key = SigningKey.from_secret_exponent(se, curve, hashlib.sha256)
    return hexlify(key.to_string())


def generate_public_key(private_key_hex):
    hash160 = ripe_hash(private_key_hex)
    public_key_and_version_hex = b"04" + hash160
    checksum = double_hash(public_key_and_version_hex)[:4]
    return base58.b58encode(public_key_and_version_hex + checksum)


def ripe_hash(key):
    ret = hashlib.new('ripemd160')
    ret.update(hashlib.sha256(key).digest())
    return ret.digest()


def double_hash(key):
    return hashlib.sha256(hashlib.sha256(key).digest()).digest()


def generate_private_key_wif(private_key_hex):
    private_key_and_version = b"80" + private_key_hex
    private_key_and_version = codecs.decode(private_key_and_version, 'hex')
    checksum = double_hash(private_key_and_version)[:4]
    hashed = private_key_and_version + checksum
    return base58.b58encode(hashed)


def main():
    private_key_hex = generate_private_key()
    public_key_hex = generate_public_key(private_key_hex)
    private_key_wif_hex = generate_private_key_wif(private_key_hex)
    print("Private Key: {}".format(private_key_hex))
    print("Public Key: {}".format(public_key_hex))
    print("Private Key (WIF Format): {}".format(private_key_wif_hex))


if __name__ == '__main__':
    main()
