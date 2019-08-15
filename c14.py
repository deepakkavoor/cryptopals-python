from c12 import ECBOracle
from Crypto.Cipher import AES
from Crypto import Random
from random import randint
from c7 import aes_encrypt_ecb, aes_decrypt_ecb
from c1 import base642bytes


class HarderECBOracle(ECBOracle):

    def __init__(self, unknownString):

        super(HarderECBOracle, self).__init__(unknownString)

        self.randomPrefix = Random.new().read(randint(0, 255))

    
    def encrypt(self, msg):

        return aes_encrypt_ecb(self.randomPrefix + msg + self.unknownString, self.key, pad = True)


def discover_prefix_length(encOracle):

    # first, determine block index where prefix ends

    # do this by encrypting nothing, then b'A', and checking how many blocks are identical in both cases

    blockLength = AES.block_size

    msg = b''

    msg2 = b'A'

    c1 = encOracle.encrypt(msg)

    c2 = encOracle.encrypt(msg2)

    prefixBlock = 0

    for block in range(0, len(c2), blockLength):

        if c1[block : block + blockLength] != c2[block : block + blockLength]:

            prefixBlock = block
            
            break

    # next, determine the exact index in blockIndex'th block, where random string ends

    # encrypt msg of (32 + i) b'A's, so that blocks prefixBlock / 16 + 1 and prefixBlock / 16 + 2 turn out to be equal

    # then, prefixBlock / 16 'th block would have some random bytes and i msg bytes

    # example, if length of msg turned out to be 32 + 4, then out of the 16 bytes in prefixBlock / 16 ' th block, 4 would be part of msg,

    # and the remaining 12 would be of the random prefix, and so, prefixBlock + 12 would give len(randomPrefix)
    
    msg = b'A' * 2 * blockLength

    prefixIndex = 0

    for i in range(0, blockLength):

        c = encOracle.encrypt(msg)

        # small case when randomPrefix ended at last byte of a block, and prefixBlock turned out to be a multiple of 16

        # then instead of comparing blocks prefixBlock / 16 + 1 and prefixBlock / 16 + 2, 

        # compare blocks prefixBlock / 16 and prefixBlock / 16 + 1

        if i == 0 and c[prefixBlock : prefixBlock + 16] == c[prefixBlock + 16 : prefixBlock + 32]:

            prefixIndex = prefixBlock
            
            return prefixIndex

        if c[prefixBlock + blockLength : prefixBlock + 2 * blockLength] == c[prefixBlock + 2 * blockLength : prefixBlock + 3 * blockLength]: 

            prefixIndex = prefixBlock + blockLength - i

            return prefixIndex

        msg += b'A'


def discover_unknown_string_length(encOracle):

    prefixLength = discover_prefix_length(encOracle)

    text = b''

    c = encOracle.encrypt(text)

    newLength = initialLength = len(c)

    while newLength == initialLength:

        text += b'A'

        c = encOracle.encrypt(text)

        newLength = len(c)

    # now we know, last blockLength bytes are responsible for padding

    return initialLength - len(text) - prefixLength


def get_next_byte_harder(stringDiscovered, encOracle):

    # (prefixLength + lenText + len(stringDiscovered) + 1) % blockLength = 0, so that next character of stringDiscovered ends at a block

    prefixLength = discover_prefix_length(encOracle)

    blockLength = AES.block_size

    lengthText = -(1 + prefixLength + len(stringDiscovered)) % blockLength

    text = b'A' * lengthText

    lengthToCheck = prefixLength + lengthText + len(stringDiscovered) + 1

    c = encOracle.encrypt(text)

    for nextByte in range(0, 256):

        testCiphertext = encOracle.encrypt(text + stringDiscovered + bytes([nextByte]))

        if testCiphertext[ : lengthToCheck] == c[ : lengthToCheck] :

            return bytes([nextByte])


def harder_byte_ecb_decryption(encOracle):

    unknownStringLength = discover_unknown_string_length(encOracle)

    discoverString = b''

    for byte in range(0, unknownStringLength):

        discoverString += get_next_byte_harder(discoverString, encOracle)

    return discoverString 


def main():

    unknownString = base642bytes(b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')

    ecbOracle = HarderECBOracle(unknownString)

    assert(len(ecbOracle.randomPrefix) == discover_prefix_length(ecbOracle))

    assert(len(ecbOracle.unknownString) == discover_unknown_string_length(ecbOracle))

    discoveredString = harder_byte_ecb_decryption(ecbOracle)

    # assert(discoveredString == unknownString)

    print(discoveredString)


if __name__ == '__main__':

    main()