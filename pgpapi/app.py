import pathlib
from typing import Optional

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from pgpy import PGPKey, PGPMessage


__title__ = 'PGP API'
__description__ = 'Secure communication API using PGP'
__version__ = '0.1.0'
CUR_ABSPATH = pathlib.Path(__file__).parent.absolute()
STATIC = CUR_ABSPATH.joinpath('static')


class Message(BaseModel):
    publickey: str
    blob: Optional[str]


def encrypt(data: str, pub_key: str) -> str:
    msg = PGPMessage.new(data)
    pub_key_obj = PGPKey.from_blob(pub_key)[0]
    return str(pub_key_obj.encrypt(msg))


app = FastAPI(title=__title__, description=__description__, version=__version__)
app.mount("/assets", StaticFiles(directory=STATIC), name="static")


@app.get("/")
async def home():
    return FileResponse(STATIC.joinpath('index.html'))


@app.post('/getencrypteddata')
async def getencrypteddata(msg: Message):
    '''
    ## Recieve data from server

    * Client sends public key via POST request
    * Server encrypts data using the public key
    * The response includes encrypted blob
    '''
    with open(STATIC.joinpath('data.txt')) as f:
        data = f.read()
    msg.blob = encrypt(data, msg.publickey)
    return msg
