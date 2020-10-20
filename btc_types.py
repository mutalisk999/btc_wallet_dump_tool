#!/usr/bin/env python
# encoding: utf-8


class CMasterKey(object):
    def __init__(self):
        self.cryptedKey = b""
        self.salt = b""
        self.derivationMethod = 0
        self.deriveIterations = 0


class Global(object):
    wallet_ids_in_processing = set()
