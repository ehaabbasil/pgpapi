from pgpy import PGPKey, PGPMessage, PGPUID
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
from typer import run, secho, colors


def generate(username: str):
    primary_key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    primary_key.add_uid(
            PGPUID.new(username),
            usage={KeyFlags.EncryptCommunications},
            uidhashes=[HashAlgorithm.SHA512],
            ciphers=[SymmetricKeyAlgorithm.AES256],
            compression=[CompressionAlgorithm.ZIP]
    )

    secho("Primary key, to be saved in server", fg=colors.BLUE)
    secho(primary_key.fingerprint, fg=colors.RED)
    secho(str(primary_key), fg=colors.YELLOW)

    secho("Public key, to be saved in server", fg=colors.BLUE)
    secho(primary_key.fingerprint, fg=colors.RED)
    secho(str(primary_key.pubkey), fg=colors.GREEN)


if __name__ == '__main__':
    run(generate)
