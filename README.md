# FastPGP

## Dependencies Installation

```sh
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Generate key pairs on CLI

```sh
python keygen.py USERNAME
```

Edit `fastpgp/keys.py` & `client.py`

* add new username and primary key to `fastpgp/keys.py`
* replace existing public key of `client.py`


## Run server & client

Run the server using Uvicorn,

```sh
uvicorn fastpgp.app:app --reload --host 127.0.0.1 --port 8000
```

Check the API endpoints on [API Doc](http://localhost:8000/docs)


Run the client on CLI,

```sh
python client.py
```
