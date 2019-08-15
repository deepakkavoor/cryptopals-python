from Crypto.Cipher import AES
from c1 import base642bytes
from c2 import bytes_xor
from c9 import pad_pkcs7, is_padded_pkcs7, unpad_pkcs7
from c7 import aes_encrypt_ecb, aes_decrypt_ecb


def aes_encrypt_cbc(text, key, iv, pad = False):

    if pad:

        text = pad_pkcs7(text, AES.block_size)

    c = b''

    prev = iv

    for block in range(0, len(text), AES.block_size):

        textBlock = text[block : block + AES.block_size]

        cipherBlock = aes_encrypt_ecb( bytes_xor(textBlock, prev) , key)

        c += cipherBlock

        prev = cipherBlock

    return c


def aes_decrypt_cbc(text, key, iv, padded = False):

    # padded denotes whether the message was padded or not when encrypting

    msg = b''

    prev = iv

    for block in range(0, len(text), AES.block_size):

        cipherBlock = text[block : block + AES.block_size]

        msgBlock = bytes_xor( aes_decrypt_ecb(cipherBlock, key), prev)

        msg += msgBlock

        prev = cipherBlock

    if padded:

        msg = unpad_pkcs7(msg)

    return msg


def main():

    with open('c10.txt') as f:
        text = base642bytes( bytes(f.read().replace('\n', ''), 'utf-8') )

    blockSize = 16

    key = 'YELLOW SUBMARINE'

    iv = b'\x00' * blockSize

    print(aes_decrypt_cbc(text, key, iv, True), '\n\n')

    # verify

    assert(aes_decrypt_cbc( aes_encrypt_cbc(b'Hello World', key, iv, True), key, iv, True) == b'Hello World')
    
    # show cases of optional unpadding

    print(aes_decrypt_cbc( aes_encrypt_cbc(b'Hello World', key, iv, True), key, iv, False))


if __name__ == '__main__':

    main()