from Crypto import Random
from Crypto.Cipher import AES
from c1 import base642bytes
from c7 import aes_encrypt_ecb
from c11 import detect_oracle


class ECBOracle:

    def __init__(self, unknownString):

        self.unknownString = unknownString

        # AES.key_size = (16, 24, 32)

        self.key = Random.new().read(AES.key_size[0])


    def encrypt(self, msg):

        return aes_encrypt_ecb(msg + self.unknownString, self.key, pad = True)


def discover_block_size(encOracle):

    text = b''

    c = encOracle.encrypt(text)

    newLength = initialLength = len(c)

    while newLength == initialLength:

        text += b'A'

        c = encOracle.encrypt(text)

        newLength = len(c)

    return newLength - initialLength


def discover_ecb(encOracle, blockLength):

    text = b'A' * 64

    c = encOracle.encrypt(text)

    return detect_oracle(c, blockLength)


def discover_unknown_string_length(encOracle):

    text = b''

    c = encOracle.encrypt(text)

    newLength = initialLength = len(c)

    while newLength == initialLength:

        text += b'A'

        c = encOracle.encrypt(text)

        newLength = len(c)

    # now we know, last blockLength bytes are responsible for padding

    return initialLength - len(text)

def get_next_byte(blockLength, stringDiscovered, encOracle):

    # (lenText + len(stringDiscovered) + 1) % blockLength = 0, so that next character of stringDiscovered ends at a block

    lengthText =  -(1 + len(stringDiscovered)) % blockLength

    text = b'A' * lengthText

    # length upto which ciphertexts have to be compared

    lengthToCheck = lengthText + len(stringDiscovered) + 1

    c = encOracle.encrypt(text)

    for nextByte in range(0, 256):

        testCiphertext = encOracle.encrypt(text + stringDiscovered + bytes([nextByte]))

        if testCiphertext[ : lengthToCheck] == c[ : lengthToCheck] :

            return bytes([nextByte])


def byte_ecb_decryption(encOracle):

    blockLength = discover_block_size(encOracle)

    unknownStringLength = discover_unknown_string_length(encOracle)

    discoverString = b''

    for byte in range(0, unknownStringLength):

        discoverString += get_next_byte(blockLength, discoverString, encOracle)

    return discoverString 


def main():

    unknownString = base642bytes(b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

    ecbOracle = ECBOracle(unknownString)

    blockLength = discover_block_size(ecbOracle)

    assert(blockLength == AES.block_size)

    assert(discover_ecb(ecbOracle, blockLength) == 'ECB')

    assert(discover_unknown_string_length(ecbOracle) == len(ecbOracle.unknownString))

    discoveredString = byte_ecb_decryption(ecbOracle)

    assert(discoveredString == unknownString)

    print(discoveredString)

if __name__ == '__main__':

    main()