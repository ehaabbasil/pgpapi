from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel
from pgpy import PGPKey, PGPMessage

from fastpgp.keys import KEYS


__title__ = 'FastPGP'
__description__ = 'Secure communication API using PGP'
__version__ = '0.0.2'


class UnregisteredKeyError(Exception):
    pass


class Message(BaseModel):
    publickey: str
    blob: Optional[str]


def encrypt(data: str, pub_key: str) -> str:
    msg = PGPMessage.new(data)
    pub_key_obj = PGPKey.from_blob(pub_key)[0]
    return str(pub_key_obj.encrypt(msg))


def decrypt(encrypted_data: str, pub_key: str):
    encrypted_msg = PGPMessage.from_blob(encrypted_data)

    pub_key_obj = PGPKey.from_blob(pub_key)[0]
    user = pub_key_obj.userids[0].name
    if user not in KEYS:
        raise UnregisteredKeyError()

    key = KEYS[user]
    msg = key.decrypt(encrypted_msg)

    return str(msg.message)


app = FastAPI(title=__title__, description=__description__, version=__version__)


@app.post('/pgp/recieve')
async def recieve(msg: Message):
    '''
    ## Recieve data from server

    * Client sends public key via POST request
    * Server encrypts data using the public key
    * The response includes encrypted blob
    '''
    data = 'This is some message from server to client.'
    msg.blob = encrypt(data, msg.publickey)
    return msg


@app.post('/pgp/send')
async def send(msg: Message):
    '''
    ## Send data to server

    * Client encrypts data using the public key
    * Server finds the paired private key
    * The encrypted data is in the Message.blob
    '''
    data = decrypt(msg.blob, msg.publickey)

    print("[INFO] Successfully get data from client:")
    print(data)
