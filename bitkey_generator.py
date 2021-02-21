import os
import ecdsa
import binascii
import hashlib
import base58


def main():
    # private_key = os.urandom(32).encode('hex')
    private_key = binascii.hexlify(os.urandom(32)).decode()
    print("private_key: {}".format(private_key))

    Private_Key = bytes.fromhex(private_key)
    print("Private_Key: ".format(Private_Key))

    signing_key = ecdsa.SigningKey.from_string(Private_Key, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    print("signing_key: ".format(signing_key))
    print("verifying_key: ".format(verifying_key))

    public_key = bytes.fromhex("04") + verifying_key.to_string()
    print("public key = " + public_key.hex())

    compress_pubkey = False
    pubkey = public_key

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

    print("checksum = \t" + sha.hexdigest() )
    print("key_hash + checksum = \t" + key_hash + ' ' + checksum)
    print("bitcoin address = \t" + base58.b58encode(bytes(bytearray.fromhex(key_hash + checksum))))


def hash160(hex_str):
    sha = hashlib.sha256()
    rip = hashlib.new('ripemd160')
    sha.update(hex_str)
    rip.update(sha.digest() )
    print("key_hash = \t" + rip.hexdigest())
    return rip.hexdigest()  # .hexdigest() is hex ASCII


if __name__ == '__main__':
    main()
