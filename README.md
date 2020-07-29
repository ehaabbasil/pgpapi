# FastPGP

## Quickstart

```sh
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn fastpgp.app:app --reload --host 127.0.0.1 --port 8000
```

Check the API endpoints on [API Doc](http://localhost:8000/docs)

Run the client on CLI,

```sh
python client.py
```
