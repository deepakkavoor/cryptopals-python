from Crypto.Cipher import AES
from c1 import base642bytes
from c9 import pad_pkcs7, unpad_pkcs7, is_padded_pkcs7

# https://www.dlitz.net/software/pycrypto/api/current/


def aes_encrypt_ecb(text, key, pad = False):

    # if you want to pad, pass pad = True and appropriate blockSize

    cipher = AES.new(key, AES.MODE_ECB)

    if pad:

        text = pad_pkcs7(text, AES.block_size)

    c = cipher.encrypt(text)

    return c


def aes_decrypt_ecb(text, key, padded = False):

    # padded denotes whether the message was padded or not when encrypting

    cipher = AES.new(key, AES.MODE_ECB)

    msg = cipher.decrypt(text)

    if padded:

        msg = unpad_pkcs7(msg)

    return msg


def main():

    key = b'YELLOW SUBMARINE'

    with open('c7.txt') as f:

        text = f.read().replace('\n', '')

    text = base642bytes(bytes(text, 'utf-8'))

    msg = aes_decrypt_ecb(text, key)

    assert(aes_decrypt_ecb(aes_encrypt_ecb(msg, key), key) == msg)

    print(msg)


if __name__ == '__main__':

    main()