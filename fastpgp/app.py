from typing import Optional

from fastapi import FastAPI
from pydantic import BaseModel
from pgpy import PGPKey, PGPMessage, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm


__author__ = 'Sriram G.'
__title__ = 'FastPGP'
__version__ = '0.0.1'
__description__ = 'PGP communication API'
__email__ = 'sriram@sriramg.com'

ALGORITHM = PubKeyAlgorithm.RSAEncryptOrSign
PRIMARY_KEY = PGPKey.new(ALGORITHM, 4096)
UID = PGPUID.new(__author__, comment=__description__, email=__email__)
PRIMARY_KEY.add_uid(UID, usage={KeyFlags.EncryptCommunications},
            hashes=[HashAlgorithm.SHA512],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZIP])


class Message(BaseModel):
    publickey: str
    blob: Optional[str]


def encrypt(data: str, pub_key: str) -> str:
    msg = PGPMessage.new(data)
    pub_key_obj = PGPKey.from_blob(pub_key)[0]
    return str(pub_key_obj.encrypt(msg))


def decrypt(encrypted_data: str, key: PGPKey):
    encrypted_msg = PGPMessage.from_blob(encrypted_data)
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


@app.get('/pgp/send')
async def get_pubkey_for_send():
    '''
    ## Get public key for sending data to server

    * Client asks public key to be used for encryption
    '''
    msg = Message(publickey=str(PRIMARY_KEY.pubkey))
    return msg


@app.post('/pgp/send')
async def send(msg: Message):
    '''
    ## Send data to server

    * Client encrypts data using the public key - got from the above GET request
    * The encrypted data is in the Message.blob
    '''
    assert msg.publickey == str(PRIMARY_KEY.pubkey)
    data = decrypt(msg.blob, PRIMARY_KEY)

    print("[INFO] Successfully get data from client:")
    print(data)
