# PGPApi

* Web framework: [FastAPI](https://fastapi.tiangolo.com/)
* Python PGP library: [PGPy](https://pgpy.readthedocs.io/en/latest/)
* JavaScript PGP library: [OpenPGP.js](https://openpgpjs.org/) by ProtonMail


## Dependencies Installation

```sh
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run server & client

Run the server using Uvicorn,

```sh
uvicorn pgpapi.app:app --reload --host 127.0.0.1 --port 8000
```

Check the API endpoints on [API Doc](http://localhost:8000/docs)

Check the test communication page on [Test Page](http://localhost:8000/)
