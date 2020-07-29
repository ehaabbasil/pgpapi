from datetime import timedelta
import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm


ALGORITHM = PubKeyAlgorithm.RSAEncryptOrSign
USER = {
    'name': 'Sriram G.',
    'comment': 'PGP communication API',
    'email': 'sriram@sriramg.com'
}

key = pgpy.PGPKey.new(ALGORITHM, 4096)
uid = pgpy.PGPUID.new(USER['name'], comment=USER['comment'], email=USER['email'])
key.add_uid(uid, usage={KeyFlags.EncryptCommunications},
            hashes=[HashAlgorithm.SHA512],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZLIB])

pub_key_str = str(key.pubkey)


def encrypt(data: str, pub_key: str) -> str:
    msg = pgpy.PGPMessage.new(data)
    pub_key_obj = pgpy.PGPKey.from_blob(pub_key)[0]
    return str(pub_key_obj.encrypt(msg))


def decrypt(encrypted_data: str, key: pgpy.PGPKey):
    encrypted_msg = pgpy.PGPMessage.from_blob(encrypted_data)
    msg = key.decrypt(encrypted_msg)
    return str(msg.message)


data = "my dear Ggomee"
enc_data = encrypt(data, pub_key_str)
print(pub_key_str)
print(enc_data)
print(decrypt(enc_data, key))