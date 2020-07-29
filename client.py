import httpx
from pgpy import PGPKey, PGPMessage, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm



# Note:
# These ALGORITHM, UID, and PRIMARY_KEY do not need to be the same as the server's
# Just copied from server code without special reason

ALGORITHM = PubKeyAlgorithm.RSAEncryptOrSign
PRIMARY_KEY = PGPKey.new(ALGORITHM, 4096)
UID = PGPUID.new('foo')
PRIMARY_KEY.add_uid(UID, usage={KeyFlags.EncryptCommunications},
            hashes=[HashAlgorithm.SHA512],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZIP])


def encrypt(data: str, pub_key: str) -> str:
    msg = PGPMessage.new(data)
    pub_key_obj = PGPKey.from_blob(pub_key)[0]
    return str(pub_key_obj.encrypt(msg))


def decrypt(encrypted_data: str, key: PGPKey):
    encrypted_msg = PGPMessage.from_blob(encrypted_data)
    msg = key.decrypt(encrypted_msg)
    return str(msg.message)


BASE_URL = 'http://localhost:8000'


def send_data_to_server(data: str):
    r = httpx.get(BASE_URL + '/pgp/send')
    pub_key = r.json()['publickey']
    encrypted_data = encrypt(data, pub_key)
    r = httpx.post(
            BASE_URL + '/pgp/send',
            json = {'publickey': pub_key, 'blob': encrypted_data})
    assert r.status_code == 200


def get_data_from_server(key: PGPKey):
    r = httpx.post(
            BASE_URL + '/pgp/recieve',
            json = {'publickey': str(key.pubkey)})
    encrypted_data = r.json()['blob']
    data = decrypt(encrypted_data, key)

    print("[INFO] Successfully get data from server:")
    print(data)


# This message will be shown in the server log
send_data_to_server("This is a message sent from client to server.")

# A message from server will be logged out to the console
get_data_from_server(PRIMARY_KEY)
