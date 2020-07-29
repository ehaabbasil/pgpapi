import httpx
from pgpy import PGPKey, PGPMessage, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm


FINGERPRINT = 'F6ED 3113 7FCB 1109 A9D0  1614 AEAE 8BC7 8844 981D'
PUBKEY = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----

xsFNBF8hWvQBEACjkIB7aVhzNqHQ/XzgSsrhUsNbPVrwkF0dtUiEXQyeuf7fuw59
YNMb1oaTkWxrvogFbEW9WBKsF+ely0JBmK0aU0IaIec/9VB737llQDDy0YJ0PE7X
Jr2QMv+Ph3B2vTgjc/eARukqe9nCcGK+AMuYT9GH1bPlpUZtMFLs30P6aDFv2uUN
zsgVwsjA8Qtmm93eUVtqdum6b4qHXwHMRyroewn8GHD1Ha3L0pRpw8kjpGYuC7FY
LZutvPBeL/+NaoKHrwaV0hkQZEzSTIig8OTXDGF1J2ECvpPMx8VU3Q/q2FhrLUy2
rVowuMHUk1fMENZ+2qsveJDfnquuDnPtTBskVGgfvazeabetUNvSjPFB0fQR/V1a
vpi/vp/GzABC/5S/gaKNmY++AQfMIsRZw0TtuwGqDqKC0z2Hrggktsb25+Qjcr7h
rxe3CYQagoSlB5ECmH9CQEB94ihjiQ2jG8PNYm8wc/okyzl1cKGv2DvucQ+hPtH9
O0ntAfb8IBCQLhZD0l/dNgqIpwOmyKCR2s7CDSYaZIoFTn/YDTc8+uXlcec/qXsE
CO9QnfSdlAeWJ4MqNaHcBK9oYS3yui0x2F/nExQQ3jpSZata8NnGIDal8sRgReGi
/xZUNgy2mbT4oRXB6CnZAIPMV/DDIZnsGFhknBg8odAfLdl/s7Epy3ckqQARAQAB
zQZHZ29tZWXCwWgEEwEIABIFAl8hWvYCGwQCCwkCFgECHgEACgkQrq6Lx4hEmB06
vw/+JPZvmSzoylHT/DJ7bJtHtpOIL3nhPcdotjLalFVI2VZSAfVs1aOQy9iFzg6g
L9W5ysIg9W971CZ49DQro+ZqGG/dVHVFvoj6BE2mIy1RVBOSkvlkM/BdwM4T6vDw
vTeH3y7T9J1LyZKLXoILgeFikE3/ImDvMNt4WRBO5Wz/b+B8OjpwAHMAAYRFh4Cx
7REJ/ZYoEVnBFrEBIIRiWdU7NQWQrqwOj2c7ObHPiA2ACRNv4b6rYD+H0DOuVVzR
xDusBE+GeQ+3BBBfaMPKXbTxCK/QUXyViEMKxhCTk7e8LswGnpq8MlYrXpeEv9JP
DkETj3NWJcia1SwqrrtOtXLx6S1HKvgvhtyh9aUPjLGmqySHUWr1Mf1yzX/AFCJ9
x40pvSN34FeNmL2GxaZIMhi2g0ab3PkvPCJe4BoaZBVy3debQv04iYpAKcJW/m70
del2H1Lfzzg3qYn7Y6ZmAUgIVd2xNUgLf1Vgp9NVpMZ5DEvZNFj/dhPC0uxeyY+k
14Wb4m4ylBR3FWZn/ZSOSv8VOksyyeiLk8u1PVCp+0PXXJFh57rtNbMKK3+eQOaJ
3Xc3GUsaabAmr0lqu9Ys4o0FKUR8+FycziRWURO2qN9uXcnlWdlO+TCXMcyfapuq
jb+5NpbyYMfT4qqLrXhY/qxDMRdWKXKG5pYKS7BISRhXC8I=
=Ib2m
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
            json = {'fingerprint': FINGERPRINT, 'blob': encrypted_data})
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
