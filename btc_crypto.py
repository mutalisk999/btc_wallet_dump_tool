#!/usr/bin/env python
# encoding: utf-8

import io
from Crypto.Cipher import AES


PKCS5_SALT_LEN = 8


def EVP_BytesToKey(key_length, iv_length, md, salt, data, count):
    assert data
    assert salt == b'' or len(salt) == PKCS5_SALT_LEN

    md_buf = b''
    key = b''
    iv = b''

    addmd = 0

    while key_length > len(key) or iv_length > len(iv):
        c = md()
        if addmd:
            c.update(md_buf)
        addmd += 1
        c.update(data)
        c.update(salt)
        md_buf = c.digest()
        for i in range(1, count):
            md_buf = md(md_buf).digest()

        md_buf2 = md_buf

        if key_length > len(key):
            key, md_buf2 = key + md_buf2[:key_length - len(key)], md_buf2[key_length - len(key):]

        if iv_length > len(iv):
            iv, md_buf2 = iv + md_buf2[:iv_length - len(iv)], md_buf2[iv_length - len(iv):]

    return key, iv


def openssl_enc_decrypt(key, iv, cipherText):
    cipher = AES.new(key=key, mode=AES.MODE_CBC, IV=iv)

    input = io.BytesIO(cipherText)
    prefetch = chunk = None
    output = b""
    while 1:
        chunk = prefetch
        prefetch = input.read(cipher.block_size)

        if chunk:
            chunk = cipher.decrypt(chunk)
            if not prefetch:
                chunk = chunk[:-chunk[-1]]
            output += chunk

        if not prefetch:
            break
    return output









