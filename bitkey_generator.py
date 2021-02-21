#!/usr/bin/env python

'''
Creates BitCoin Wallet complaint credentials:
- Public Key
- Private Key
- Private Key (Wallet Import Format)
'''

import os
import ecdsa
import binascii
import hashlib
import base58


def main():
    # private_key = os.urandom(32).encode('hex')
    private_key = binascii.hexlify(os.urandom(32)).decode()
    print("private_key: {}".format(type(private_key)))

    Private_Key = bytes.fromhex(private_key)
    print("Private_Key: ".format(Private_Key))

    signing_key = ecdsa.SigningKey.from_string(Private_Key, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    print("signing_key: ".format(signing_key))
    print("verifying_key: ".format(verifying_key))

    public_key = bytes.fromhex("04") + verifying_key.to_string()
    print("public key = " + public_key.hex())

    compress_pubkey = False
    pubkey = public_key.hex()
    # pubkey = "04f25c3fbbf53bb811f1ad9654a9bce8b79f34dae5618ef83e1abc52911970f04c58d10d79e1cdac2b8c59dc8fc2be5ed62f7a01726bc923c8c68cea818366da13"
    print("pubkey: ".format(pubkey))

    if compress_pubkey:
        if ord(bytearray.fromhex(pubkey[-2:])) % 2 == 0:
            pubkey_compressed = '02'
        else:
            pubkey_compressed = '03'
        pubkey_compressed += pubkey[2:66]
        hex_str = bytearray.fromhex(pubkey_compressed)
    else:
        hex_str = bytearray.fromhex(pubkey)

    # Obtain key:
    key_hash = '00' + hash160(hex_str)

    # Obtain signature:
    sha = hashlib.sha256()
    sha.update( bytearray.fromhex(key_hash) )
    checksum = sha.digest()
    sha = hashlib.sha256()
    sha.update(checksum)
    checksum = sha.hexdigest()[0:8]

    print("checksum = \t{}".format(sha.hexdigest()))
    print("key_hash + checksum = \t{}".format(key_hash + ' ' + checksum))
    key_cksum = str(key_hash + checksum)
    print("key_cksum: ".format(key_cksum))
    print("bitcoin address = \t" + base58.b58encode(bytes(bytearray.fromhex(key_cksum))))


def hash160(hex_str):
    sha = hashlib.sha256()
    rip = hashlib.new('ripemd160')
    sha.update(hex_str)
    rip.update(sha.digest())
    print("key_hash = \t" + rip.hexdigest())
    return rip.hexdigest()  # .hexdigest() is hex ASCII


if __name__ == '__main__':
    main()
