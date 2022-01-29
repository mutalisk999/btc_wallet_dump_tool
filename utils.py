#!/usr/bin/env python
# encoding: utf-8


import hashlib


def hash160(data):
    d32 = hashlib.sha256(data).digest()
    h = hashlib.new('ripemd160')
    h.update(d32)
    d20 = h.digest()
    return d20


def sha256(data):
    d32 = hashlib.sha256(data).digest()
    return d32


def double_sha256(data):
    d32 = sha256(sha256(data))
    return d32


def checksum(data):
    d4 = hashlib.sha256(hashlib.sha256(data).digest()).digest()[0:4]
    return d4