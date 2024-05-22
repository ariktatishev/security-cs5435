import os
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.backends import default_backend
import base64
import binascii


def format_plaintext(is_admin, password):
    tmp = bytearray(str.encode(password))
    return bytes(bytearray((is_admin).to_bytes(1,"big")) + tmp)

def is_admin_cookie(decrypted_cookie):
    if len(decrypted_cookie) == 0:
        return False
    return decrypted_cookie[0] == 1

class Encryption(object):
    def __init__(self, in_key=None):
        self._backend = default_backend()
        self._block_size_bytes = int(ciphers.algorithms.AES.block_size/8)
        if in_key is None:
            self._key = os.urandom(self._block_size_bytes)
        else:
            self._key = in_key

    def encrypt(self, msg):
        # CBC
        # padder = padding.PKCS7(ciphers.algorithms.AES.block_size).padder()
        # padded_msg = padder.update(msg) + padder.finalize()
        # iv = os.urandom(self._block_size_bytes)
        # encryptor = ciphers.Cipher(ciphers.algorithms.AES(self._key),
        #                            ciphers.modes.CBC(iv),
        #                            self._backend).encryptor()
        # _ciphertext = iv + encryptor.update(padded_msg) + encryptor.finalize()

        # GCM
        iv = os.urandom(self._block_size_bytes)
        encryptor = ciphers.Cipher(ciphers.algorithms.AES(self._key),
                                   ciphers.modes.GCM(iv),
                                   self._backend).encryptor()
        _ciphertext = encryptor.update(msg) + encryptor.finalize()
        ctx = iv + encryptor.tag + _ciphertext
        return ctx
    
    def decrypt(self, ctx):
        # CBC
        # iv, ctx = ctx[:self._block_size_bytes], ctx[self._block_size_bytes:]
        # unpadder = padding.PKCS7(ciphers.algorithms.AES.block_size).unpadder()
        # decryptor = ciphers.Cipher(ciphers.algorithms.AES(self._key),
        #                            ciphers.modes.CBC(iv),
        #                            self._backend).decryptor()        
        # padded_msg = decryptor.update(ctx) + decryptor.finalize()
        # try:
        #     msg = unpadder.update(padded_msg) + unpadder.finalize()
        #     return msg  # Successful decryption
        # except ValueError:
        #     return False  # Error!!

        # GCM
        iv, tag = ctx[:self._block_size_bytes], ctx[self._block_size_bytes:][:self._block_size_bytes]
        _ciphertext = ctx[len(iv) + len(tag):]

        decryptor = ciphers.Cipher(ciphers.algorithms.AES(self._key),
                                   ciphers.modes.GCM(iv, tag),
                                   self._backend).decryptor()        
        try:
            msg = decryptor.update(_ciphertext) + decryptor.finalize()
            return msg  # Successful decryption
        except ValueError:
            return False  # Error!!

def test_encr_decr():
    msg = "squimishossifrage"
    GCM = Encryption(bytearray(16))
    ct = GCM.encrypt(msg.encode())
    pt = GCM.decrypt(ct).decode()
    print("MSG:", msg)
    print("DECODED:", pt)

        
if __name__=='__main__':
    test_encr_decr()
