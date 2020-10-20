#!/usr/bin/env python
# encoding: utf-8

import bsddb3
from bsddb3 import db, _DBWithCursor


def open_wallet_db(dbfile):
    bdb = db.DB()
    bdb.open(dbfile, dbname="main", dbtype=db.DB_BTREE)
    return bdb


def get_wallet_db_cursor(bdb):
    cursor = _DBWithCursor(bdb)
    return cursor


def close_wallet_db(bdb):
    if bdb is not None:
        bdb.close()
