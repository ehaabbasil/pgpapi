import httpx
from pgpy import PGPKey, PGPMessage, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm


PUBKEY = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----

xsFNBF8hQRYBEACmlTiMcXfLYZCSiVpAfYy2aAeEr08j4V9H9TbLPJjNwGH/UrBR
niG/lTShudIgnuUDO1bV01kUx1N6eRDRB3P1mSq5r6nZn4GVN6/CHRj3sJWqkZAW
2DvzCsNKbuYyPNC5LdGR5B06T22AeMEqVSM1go3PdebaqQxsqx6m0HPG/a4FUwxY
lKmDkfI0LUfubsFl6hOBkNXc/2kcZc7IjUKhL76pTi3GgDSDodWNFWUiUOTD0hEs
NE0nWN/7HduVE0bEaKOWFCu42m44g1MAWHHm4mNkuWcZHTmiGm5RJC1Sub+T3eM7
UrPYwRqgUywuxoNtRRDPlGVpSJnFZCxbZvrdDT2CQGWyC5v+z3wVncZcLNEVbV1l
wilt9zvbaZYRq7/NuuT1OsNOK0sv3P76XRWAcY7SOIcK6y0wy8Rvm3t0nS3xxJGt
FACfQF7JW20Wq7zIsNrMywNWX05UC+M8OtZMY4cC2Ba8vSZ14g1C1RSV8shYL6V+
pBnYRpFhuVL1f7lkSwJTuiVCOtzTYFH61kt3yimG4xsBZcrM9JKOk7elzsNmm0Aj
aXtYI71b/soKXdghvE7WvpkHOeDESqZwIENB5FMlLsTV6BknGyVk0xXAy3RXfuQO
5VtGhEJep84XAET+RDaL0/1d08rXsp0OmERR2cm/ir3VMCvhSfRQt5wY1QARAQAB
zQNGb2/CwWgEEwEIABIFAl8hQRYCGwQCCwkCFgECHgEACgkQa/GHHs7353RV+A//
RnRa8tzN8861TWf4qDxVZID1WMytPoEvlhFeuhefdzzApK8JoZAZoitbjX4p5VHZ
BCdf1Dsvj7z3Hse5erAZxzyyqqHH06a9bXgc/5gGaa2wmvMMvfSJHA5k9aSv3MMM
X6HPAa9XkzqMFEWcSv8wXZhyvfW95r4wNrFjqPwRcQcSfEsshQMQKCxaFMwmiRlj
vkJRTQ+MDxWhfCYuqn+YwjbEWXLBeOv0dO64td4ynrlogNs59ZGrTyOV2r6PQPau
1TN+JdLUhdkJm+iXbvuALvLLNHv3dmMdSm1ddBaOwYA5ue5dlWG6+rWGVs/Z0yr3
e0RriL0vws5FJ8QbdK9gd9I33jRhX+USvI05d+DWxcX9AGRcapOSjnYuliDDSb5B
aFFRrnWUVN65v6cY57p7h/jX/69FrYcy81KQpPotgdA2WLEmjNBFGd7QKmTcR46W
I9nvO3xaY/z7v0u6eQh7ikYwTXMl4lqB7BGpFipsYGbRAwhtuHdXCxRHgoTjE7U8
UWJO3vr7UiVWHfTlbqJozrFzpgJk6tdsbEbJJKDxv62lvGLTCW6nVQjsJ3uIsGaq
Zf5KyQT5WX4WbC3FWQux1yvEoWl3RiwKtceIS7vR2UGa+3ypEyGvGQAkXKJF6XrH
AZs3q5AX9TF67C5wYcQ2qqKjThXw+dNglhzajKZzcqw=
=MEs4
-----END PGP PUBLIC KEY BLOCK-----
'''


def _generate_key(username: str):
    primary_key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    primary_key.add_uid(
            PGPUID.new(username),
            usage={KeyFlags.EncryptCommunications},
            uidhashes=[HashAlgorithm.SHA512],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZIP]
    )
    return primary_key


def _encrypt(data: str) -> str:
    msg = PGPMessage.new(data)
    pub_key_obj = PGPKey.from_blob(PUBKEY)[0]
    return str(pub_key_obj.encrypt(msg))


def _decrypt(encrypted_data: str, key: PGPKey):
    encrypted_msg = PGPMessage.from_blob(encrypted_data)
    msg = key.decrypt(encrypted_msg)
    return str(msg.message)


BASE_URL = 'http://localhost:8000'


def send_data_to_server(data: str):
    encrypted_data = _encrypt(data)
    r = httpx.post(
            BASE_URL + '/pgp/send',
            json = {'publickey': PUBKEY, 'blob': encrypted_data})
    assert r.status_code == 200


def get_data_from_server(key: PGPKey):
    r = httpx.post(
            BASE_URL + '/pgp/recieve',
            json = {'publickey': str(key.pubkey)})
    encrypted_data = r.json()['blob']
    data = _decrypt(encrypted_data, key)

    print("[INFO] Successfully get data from server:")
    print(data)


# This message will be shown in the server log
send_data_to_server("This is a message sent from client to server.")

# A message from server will be logged out to the console
key = _generate_key('Some dummy name')
get_data_from_server(key)
