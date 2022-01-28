# btc_wallet_dump_tool
dump private key from btc wallet dat file


### module requirement
* flask

* pycryptodome

* ecdsa
```
https://github.com/warner/python-ecdsa
```

* bsddb3
```
whl for win: https://www.lfd.uci.edu/~gohlke/pythonlibs/
```

### How to Use

* Use in a flask service

```
    # Run flask service
    python3 btc_wallet_server.py
```

* Use in a command line (strongly recommend)

```
    python3 btc_wallet_cmd.py --dat-file=[path of btc wallet data file] --pass=[wallet pass]
    
    # example:
    python3 btc_wallet_cmd.py --dat-file=C:\\btc_data\\wallet.dat --pass=12345678
```
