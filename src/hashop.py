"""
This module contains functions for converting strings to hashes using the hashlib module.
"""

import hashlib


def to_md4(password):
    hash = hashlib.new("md4", password.encode("utf-8"))
    return hash.hexdigest()


def to_md5(password):
    hash_obj = hashlib.md5()  # create md5 hash obj
    hash_obj.update(password.encode("utf-8"))  # hash obj to bytes-like obj
    return hash_obj.hexdigest()


def to_sha1(password):
    hash_obj = hashlib.sha1()  # create sha1 hash obj
    hash_obj.update(password.encode("utf-8"))  # hash obj to bytes-like obj
    return hash_obj.hexdigest()


def to_sha256(password):
    hash_obj = hashlib.sha256()  # create sha256 hash obj
    hash_obj.update(password.encode("utf-8"))  # hash obj to bytes-like obj
    return hash_obj.hexdigest()


def to_sha512(password):
    hash_obj = hashlib.sha512()  # create sha512 hash obj
    hash_obj.update(password.encode("utf-8"))  # hash obj to bytes-like obj
    return hash_obj.hexdigest()
