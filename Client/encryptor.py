import os
import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class Encryptor():

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, val):
        self._key = val[0]
        self.nonce = val[1]
        self.cipher = AES.new(self._key, AES.MODE_CTR, nonce=self.nonce)

    def generate_key(self):
        self.key = [get_random_bytes(32), get_random_bytes(10)]

    def generate_rsa_keys(self, nbits=1024):
        self.public_key, self.private_key = rsa.newkeys(nbits)

    def save_rsa_keys(self):
        if not os.path.exists("rsa_keys"):
            os.mkdir("rsa_keys")
        with open("rsa_keys/public.pem", "wb") as f:
            f.write(rsa.PublicKey.save_pkcs1(self.public_key))
        with open("rsa_keys/private.pem", "wb") as f:
            f.write(rsa.PrivateKey.save_pkcs1(self.private_key))

    def load_rsa_keys(self):
        with open("rsa_keys/public.pem", "rb") as f:
            self.public_key = rsa.PublicKey.load_pkcs1(f.read())
        with open("rsa_keys/private.pem", "rb") as f:
            self.private_key = rsa.PrivateKey.load_pkcs1(f.read())

    def init_rsa(self):
        self.generate_rsa_keys()
        self.save_rsa_keys()

    def encrypt(self, msg: bytes) -> bytes:
        return self.cipher.encrypt(msg)

    def decrypt(self, msg: bytes) -> bytes:
        return self.cipher.decrypt(msg)

    def encrypt_rsa(self, msg: bytes) -> bytes:
        return rsa.encrypt(msg, self.public_key)

    def decrypt_rsa(self, msg: bytes) -> bytes:
        return rsa.decrypt(msg, self.private_key)
