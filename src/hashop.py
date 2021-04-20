"""
This module contains functions for converting strings to hashes mainly using the hashlib
module. It can also verify two hashes regardless of their case, using the passlib module.
Supports the following hash functions: lm, nthash/ntlm, md4, md5, sha1, sha256, sha512.
"""

import sys
import hashlib
from passlib.hash import (
    lmhash,
    nthash,
    hex_md4,
    hex_md5,
    hex_sha1,
    hex_sha256,
    hex_sha512,
)
from passlib.crypto import des


def to_md4(password):
    """Returns the md4 hash from the given plaintext using the hashlib module"""
    hash_obj = hashlib.new("md4", password.encode("utf-8"))
    return hash_obj.hexdigest()


def to_md5(password):
    """Returns the md5 hash from the given plaintext using the hashlib module"""
    hash_obj = hashlib.md5()  # create md5 hash obj
    hash_obj.update(password.encode("utf-8"))  # hash obj to bytes-like obj
    return hash_obj.hexdigest()


def to_sha1(password):
    """Returns the sha1 hash from the given plaintext using the hashlib module"""
    hash_obj = hashlib.sha1()  # create sha1 hash obj
    hash_obj.update(password.encode("utf-8"))  # hash obj to bytes-like obj
    return hash_obj.hexdigest()


def to_sha256(password):
    """Returns the sha256 hash from the given plaintext using the hashlib module"""
    hash_obj = hashlib.sha256()  # create sha256 hash obj
    hash_obj.update(password.encode("utf-8"))  # hash obj to bytes-like obj
    return hash_obj.hexdigest()


def to_sha512(password):
    """Returns the sha512 hash from the given plaintext using the hashlib module"""
    hash_obj = hashlib.sha512()  # create sha512 hash obj
    hash_obj.update(password.encode("utf-8"))  # hash obj to bytes-like obj
    return hash_obj.hexdigest()


def to_lmhash(password):
    """Returns the lm hash from the given plaintext with the help of passlib.crypto.des"""

    # all upper case and padd null until maximum 14 chars
    password = password.upper()[:14]
    password += (14 - len(password)) * "\x00"

    # split into two equal chunks for two des keys
    # expand_des_key() adds a parity bit to get the 8 byte des key. but since
    # des_encrypt_block() doesn't need it, it's there for best practice
    key1 = des.expand_des_key(password[:7].encode())
    key2 = des.expand_des_key(password[7:].encode())

    # encrypt the constant with des and concatenate them to form lmhash
    hash_str = des.des_encrypt_block(key1, b"KGS!@#$%")
    hash_str += des.des_encrypt_block(key2, b"KGS!@#$%")

    return hash_str.hex()


def to_nthash(password):
    """Returns the nthash from the given plaintext using the hashlib module"""
    # nthash is basically md4 but encoded as little endian utf-16
    hash_obj = hashlib.new("md4", password.encode("utf-16le"))
    return hash_obj.hexdigest()


def check_md4(pos_passwd, hash_str):
    """Returns the result of comparing two md4 hashes using passlib.hash.hex_md4"""
    try:
        return hex_md4.verify(pos_passwd, hash_str)
    except ValueError as e:  # length doesn't meet the criteria
        print(f"\n\nerror: {e}")
        sys.exit(1)


def check_md5(pos_passwd, hash_str):
    """Returns the result of comparing two md5 hashes using passlib.hash.hex_md5"""
    try:
        return hex_md5.verify(pos_passwd, hash_str)
    except ValueError as e:  # length doesn't meet the criteria
        print(f"\n\nerror: {e}")
        sys.exit(1)


def check_sha1(pos_passwd, hash_str):
    """Returns the result of comparing two sha1 hashes using passlib.hash.hex_sha1"""
    try:
        return hex_sha1.verify(pos_passwd, hash_str)
    except ValueError as e:  # length doesn't meet the criteria
        print(f"\n\nerror: {e}")
        sys.exit(1)


def check_sha256(pos_passwd, hash_str):
    """Returns the result of comparing two sha256 hashes using passlib.hash.hex_sha256"""
    try:
        return hex_sha256.verify(pos_passwd, hash_str)
    except ValueError as e:  # length doesn't meet the criteria
        print(f"\n\nerror: {e}")
        sys.exit(1)


def check_sha512(pos_passwd, hash_str):
    """Returns the result of comparing two sha512 hashes using passlib.hash.hex_sha512"""
    try:
        return hex_sha512.verify(pos_passwd, hash_str)
    except ValueError as e:  # length doesn't meet the criteria
        print(f"\n\nerror: {e}")
        sys.exit(1)


def check_lmhash(pos_passwd, hash_str):
    """Returns the result of comparing two lm hashes using passlib.hash.lmhash"""
    try:
        return lmhash.verify(pos_passwd, hash_str)
    except ValueError as e:  # length doesn't meet the criteria
        print(f"\n\nerror: {e}")
        sys.exit(1)


def check_nthash(pos_passwd, hash_str):
    """Returns the result of comparing two nthashes using passlib.hash.nthash"""
    try:
        return nthash.verify(pos_passwd, hash_str)
    except ValueError as e:  # length doesn't meet the criteria
        print(f"\n\nerror: {e}")
        sys.exit(1)
