#!/usr/bin/env python
# encoding: utf-8

import hashlib
import bsddb3
from ecdsa import SigningKey, SECP256k1

import Crypto
from Crypto.Cipher import AES

from btc_address import get_compressed_address, get_compressed_wif_key, get_compressed_pubkey
from btc_crypto import EVP_BytesToKey, openssl_enc_decrypt
from btc_db import open_wallet_db, get_wallet_db_cursor, close_wallet_db
from btc_types import CMasterKey

import base58
import utils

OP_0 = chr(0)
SCRIPT_PREFIX = chr(5)


class BizException(Exception):
    pass


def read_key_type(keydata):
    c = chr(keydata[0])
    if c == "\n" or c == "\t":
        return keydata[1:]
    else:
        l = ord(c)
        return keydata[1:l+1]


def read_address_from_keydata(keydata):
    c = chr(keydata[0])
    assert(len(keydata[1:]) == ord(c))
    return keydata[1:]


def read_pubkey_from_keydata(keydata):
    c = chr(keydata[0])
    assert(len(keydata[1:]) == ord(c))
    return keydata[1:]


def read_privkey_from_valuedata(valuedata):
    c = chr(valuedata[8])
    l = ord(c)
    return valuedata[9:l+9]


def read_encrypted_privkey_from_valuedata(valuedata):
    c = chr(valuedata[0])
    l = ord(c)
    assert(l == 48)
    return valuedata[1:]


def read_keyid_from_keydata(keydata):
    assert(len(keydata) == 4)
    return (keydata[3] << 24) + (keydata[2] << 16) + (keydata[1] << 8) + keydata[0]


def read_cmasterkey_from_valuedata(valuedata):
    masterKey = CMasterKey()
    c = chr(valuedata[0])
    l = ord(c)
    assert (l == 48)
    masterKey.cryptedKey = valuedata[1:l+1]
    valuedata = valuedata[49:]

    c = chr(valuedata[0])
    l = ord(c)
    assert (l == 8)
    masterKey.salt = valuedata[1:l + 1]
    valuedata = valuedata[9:]

    masterKey.derivationMethod = (valuedata[3] << 24) + (valuedata[2] << 16) + (valuedata[1] << 8) + valuedata[0]
    masterKey.deriveIterations = (valuedata[7] << 24) + (valuedata[6] << 16) + (valuedata[5] << 8) + valuedata[4]

    valuedata = valuedata[8:]
    c = chr(valuedata[0])
    l = ord(c)
    assert (l == 0)

    return masterKey


def witness_pubkey_to_p2sh_address(pubkey):
    assert (type(pubkey) == bytes)
    assert (len(pubkey) == 33)
    
    pubkey = pubkey.decode('iso-8859-15')
    d20 = utils.hash160(pubkey.encode('iso-8859-15')).decode('iso-8859-15')
    witness_script = OP_0 + chr(len(d20)) + d20

    script_prefix = SCRIPT_PREFIX
    
    h20 = utils.hash160(witness_script.encode('iso-8859-15')).decode('iso-8859-15')
    d21 = script_prefix + h20
    c4 = utils.checksum(d21.encode('iso-8859-15')).decode('iso-8859-15')

    d25 = d21 + c4
    return base58.b58encode(d25.encode('iso-8859-15'))


def dump_private_key_from_wallet_db(file_name, wallet_pass):
    try:
        if type(wallet_pass) is str:
            wallet_pass = bytes(wallet_pass, encoding="ascii")

        try:
            d = open_wallet_db(file_name)
        except bsddb3.db.DBNoSuchFileError as e:
            raise BizException("wallet file not exist or file format error")
        c = get_wallet_db_cursor(d)
        currentItem = c.first()

        wallet_encrypted = False
        all_user_addresses_in_wallet = set()
        all_unencrypted_keys_in_wallet = {}
        all_user_unencrypted_keys_in_wallet = {}
        all_encrypted_keys_in_wallet = {}
        all_user_encrypted_keys_in_wallet = {}
        all_mkeys_in_wallet = {}

        while True:
            ssKey = currentItem[0]
            ssValue = currentItem[1]

            keyType = read_key_type(ssKey)
            ssKey = ssKey[1+len(keyType):]

            if keyType == b"name":
                addressBytes = read_address_from_keydata(ssKey)
                all_user_addresses_in_wallet.add(addressBytes)

            # unencrypted wallet
            elif keyType == b"key":
                pubkeyBytes = read_pubkey_from_keydata(ssKey)
                addressStr = get_compressed_address(pubkeyBytes)
                segAddressStr = witness_pubkey_to_p2sh_address(pubkeyBytes)

                # get unencrypted private key
                privkeyBytes = read_privkey_from_valuedata(ssValue)
                all_unencrypted_keys_in_wallet[addressStr] = privkeyBytes
                all_unencrypted_keys_in_wallet[segAddressStr] = privkeyBytes

            # encrypted wallet
            elif keyType == b"ckey":
                wallet_encrypted = True
                pubkey = read_pubkey_from_keydata(ssKey)
                addressStr = get_compressed_address(pubkey)
                segAddressStr = witness_pubkey_to_p2sh_address(pubkey)

                # get encrypted private key
                encrypted_privkey = read_encrypted_privkey_from_valuedata(ssValue)
                all_encrypted_keys_in_wallet[addressStr] = (pubkey, encrypted_privkey)
                all_encrypted_keys_in_wallet[segAddressStr] = (pubkey, encrypted_privkey)

            elif keyType == b"mkey":
                mKeyId = read_keyid_from_keydata(ssKey)
                masterKey = read_cmasterkey_from_valuedata(ssValue)

                key, iv = EVP_BytesToKey(32, Crypto.Cipher.AES.block_size, hashlib.sha512,
                                         masterKey.salt, wallet_pass, masterKey.deriveIterations)
                decryptedKey = openssl_enc_decrypt(key, iv, masterKey.cryptedKey)
                all_mkeys_in_wallet[mKeyId] = decryptedKey

            try:
                currentItem = c.next()
            except bsddb3.db.DBNotFoundError as e:
                close_wallet_db(d)
                break

        # get user related key
        for addr in all_user_addresses_in_wallet:
            if addr in all_unencrypted_keys_in_wallet.keys():
                all_user_unencrypted_keys_in_wallet[addr] = all_unencrypted_keys_in_wallet[addr]
            if addr in all_encrypted_keys_in_wallet.keys():
                all_user_encrypted_keys_in_wallet[addr] = all_encrypted_keys_in_wallet[addr]

        if wallet_encrypted:
            # get latest unencrypted mkey
            maxKeyId = -1
            latestKey = b""
            for k, v in all_mkeys_in_wallet.items():
                if k > maxKeyId:
                    latestKey = v

            for k2, v2 in all_user_encrypted_keys_in_wallet.items():
                iv2 = hashlib.sha256(hashlib.sha256(v2[0]).digest()).digest()[0:16]
                key2 = latestKey
                decrypted_privkey = openssl_enc_decrypt(key2, iv2, v2[1])
                all_user_unencrypted_keys_in_wallet[k2] = decrypted_privkey

        # check if address is match to the private key
        user_wifkey_map = {}
        for addressStr, decrypted_privkey in all_user_unencrypted_keys_in_wallet.items():
            # check private key
            if len(decrypted_privkey) != 32:
                raise BizException("invalid private key in wallet file or use invalid wallet passphrase")
            privkey = SigningKey.from_string(decrypted_privkey, curve=SECP256k1)
            pubkey = privkey.get_verifying_key()
            pubkeyUncompressBytes = pubkey.to_string()
            pubkeyCompressBytes = get_compressed_pubkey(pubkeyUncompressBytes)
            addressStr2 = get_compressed_address(pubkeyCompressBytes)
            addressStr3 = witness_pubkey_to_p2sh_address(pubkeyCompressBytes)
            if addressStr != addressStr2 and addressStr != addressStr3:
                raise BizException("invalid private key in wallet file or use invalid wallet passphrase")
            wifKey = get_compressed_wif_key(decrypted_privkey)
            user_wifkey_map[bytes.decode(addressStr, "ascii")] = bytes.decode(wifKey, "ascii")

        res_obj = {}
        res_obj["wallet_key"] = user_wifkey_map
        return res_obj
    except Exception as e:
        err_obj = {}
        err_obj["err_msg"] = str(e)
        return err_obj




