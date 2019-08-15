from Crypto import Random
from Crypto.Cipher import AES
from random import randint
from c10 import aes_encrypt_cbc, aes_decrypt_cbc
from c7 import aes_encrypt_ecb, aes_decrypt_ecb
from c8 import get_16B_repititions

class AESEncryptionOracle:

    # using static methods to make sure they can be called both from class and its objects


    @staticmethod
    def aes_random_key_gen():

        return Random.new().read(AES.block_size)


    @staticmethod
    def pad_bytes(text):

        return Random.new().read(randint(5, 10)) + text + Random.new().read(randint(5, 10))


    @staticmethod
    def encrypt(text):

        key = AESEncryptionOracle.aes_random_key_gen()

        text = AESEncryptionOracle.pad_bytes(text)

        if randint(0, 1) == 0:

            return 'ECB', aes_encrypt_ecb(text, key, pad = True)

        else:

            return 'CBC', aes_encrypt_cbc(text, key, iv = Random.new().read(AES.block_size), pad = True)


def detect_oracle(c, blockLength = 16):

    # optional block length used in c12

    if get_16B_repititions(c, blockLength) > 0:

        return 'ECB'

    else:

        return 'CBC'

def main():

    oracle = AESEncryptionOracle()

    text = bytes([1] * 64)

    for _ in range(0, 100):

        encUsed, c = oracle.encrypt(text)

        encDetect = detect_oracle(c)

        assert(encUsed == encDetect)

    print('Successful')


if __name__ == '__main__':

    main()