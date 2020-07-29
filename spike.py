from pgpy import PGPKey, PGPMessage, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm


ALGORITHM = PubKeyAlgorithm.RSAEncryptOrSign
USER = {
    'name': 'Sriram G.',
    'comment': 'PGP communication API',
    'email': 'sriram@sriramg.com'
}

key = PGPKey.new(ALGORITHM, 4096)
uid = PGPUID.new(USER['name'], comment=USER['comment'], email=USER['email'])
key.add_uid(uid, usage={KeyFlags.EncryptCommunications},
            hashes=[HashAlgorithm.SHA512],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZLIB])

pub_key_str = str(key.pubkey)


def encrypt(data: str, pub_key: str) -> str:
    msg = PGPMessage.new(data)
    pub_key_obj = PGPKey.from_blob(pub_key)[0]
    return str(pub_key_obj.encrypt(msg))


def decrypt(encrypted_data: str, key: PGPKey):
    encrypted_msg = PGPMessage.from_blob(encrypted_data)
    msg = key.decrypt(encrypted_msg)
    return str(msg.message)


data = "my dear Ggomee"
enc_data = encrypt(data, pub_key_str)
print(pub_key_str)
print(enc_data)
print(decrypt(enc_data, key))