#!/usr/bin/env python
# encoding: utf-8

import getopt
import sys

from btc_wallet import dump_private_key_from_wallet_db


def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "", ["dat-file=", "pass="])
        datDir = None
        datPass = None
        for o, a in opts:
            if o == "--dat-file":
                datDir = a
            elif o == "--pass":
                datPass = a
            else:
                sys.exit(2)
            
            if datDir is not None and datPass is not None:
                res_obj = dump_private_key_from_wallet_db(datDir, datPass)
                if "wallet_key" in res_obj:
                    for k, v in res_obj.get("wallet_key").items():
                        print(k, v)
                else:
                    print(res_obj.get("err_msg"))
                break
    except Exception as err:
        print(err)
        sys.exit(2)


if __name__ == "__main__":
    main()
