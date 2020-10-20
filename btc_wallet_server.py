#!/usr/bin/env python
# encoding: utf-8

import json
from flask import Flask
from flask import request
from btc_wallet import dump_private_key_from_wallet_db
from btc_types import Global

app = Flask(__name__)


@app.route('/dumpwallet', methods=['POST'])
def dumpwallet():
    req_obj = json.loads(request.data)
    wallet_id = str(req_obj["wallet_id"])

    if wallet_id in Global.wallet_ids_in_processing:
        resp_obj = {}
        resp_obj["wallet_id"] = wallet_id
        resp_obj["err_msg"] = "wallet id %s is in processing now" % wallet_id
        return json.dumps(resp_obj)

    wallet_file_dir = req_obj["wallet_file_dir"]
    wallet_pass = req_obj["wallet_pass"]

    Global.wallet_ids_in_processing.add(wallet_id)
    resp_obj = dump_private_key_from_wallet_db(wallet_file_dir, wallet_pass)
    Global.wallet_ids_in_processing.remove(wallet_id)

    resp_obj["wallet_id"] = wallet_id

    return json.dumps(resp_obj)


if __name__ == "__main__":
    app.run()


