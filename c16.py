from Crypto.Cipher import AES
from Crypto import Random
from c10 import aes_encrypt_cbc, aes_decrypt_cbc
from c2 import bytes_xor
from random import randint


class CBCOracle:

    def __init__(self, prependString, appendString):

        self.key = Random.new().read(AES.key_size[0])

        self.iv = Random.new().read(AES.block_size)

        self.prependString = prependString

        self.appendString = appendString


    def modify_and_encrypt(self, msg):

        msgString =  msg.decode('utf-8').replace(';', '').replace('=', '')

        msgBytes = msgString.encode('utf-8')

        text = self.prependString + msgBytes + self.appendString

        return aes_encrypt_cbc(text, self.key, self.iv, pad = True)


    def decrypt_and_check(self, c):

        text =  aes_decrypt_cbc(c, self.key, self.iv, padded = True)

        return text, b';admin=true;' in text

    
def discover_prepend_length(encOracle):

    # similar to challenge 14, first find the block where prependString ends, then find precise index

    blockLength = AES.block_size

    msg = b''

    msg2 = b'A'

    c1 = encOracle.modify_and_encrypt(msg)

    c2 = encOracle.modify_and_encrypt(msg2)

    prependBlock = 0

    for block in range(0, len(c2), blockLength):

        if c1[block : block + blockLength] != c2[block : block + blockLength]:

            prependBlock = block

            break

    # to find prependIndex, encrypt 16 b'A's, then encrypt message of the form b'A' * i + b'B' * (16 - i)

    # the prependBlock / 16 'th block in c1 and c2 will be equal when (prependIndex + i) = 0 mod 16 or a greater i

    # encrypt 16 b'A's in c1 just in case when prependIndex ends in last byte of a block

    msg1 = b'A' * blockLength

    c1 = encOracle.modify_and_encrypt(msg1)

    prependIndex = 0

    for i in range(1, blockLength + 1):

        msg2 = b'A' * i + b'B' * (blockLength - i)

        c2 = encOracle.modify_and_encrypt(msg2)

        if c1[prependBlock : prependBlock + blockLength] == c2[prependBlock : prependBlock + blockLength]:

            prependIndex = prependBlock + blockLength - i

            return prependBlock, prependIndex


def cbc_bit_flip_attack(encOracle):

    blockLength = AES.block_size

    prependBlock, prependIndex = discover_prepend_length(encOracle)

    # complete the prependBlock / 16 'th block with some message bytes, and at the beginning of the next fresh block encrypt the message *admin*true*

    # our goal is to modify the first, seventh and twelfth byte of prependBlock / 16 + 1 'th block, so that by CBC's property

    # appropriate bytes in the next block are modified accordingly

    # in this case, len(prependString) is 32, so actually  a complete block, i.e. 16 bytes are prepended as junk message

    # which is is even more better for us, since this is the block that gets "scrambled" when we try to modify those first, seventh and twelfth bytes

    # i am appending some junk after '*admin*true*' as well, for completeness

    numBytesPrepend = blockLength - (prependIndex) % blockLength

    msg = b'A' * numBytesPrepend + b'*admin*true*' + b'A' * randint(0, 16)

    c = encOracle.modify_and_encrypt(msg)

    bytesSemicolon = bytes([  c[prependBlock] ^ ord('*') ^ ord(';')  ])

    bytesEqual = bytes([  c[prependBlock + 6] ^ ord('*') ^ ord('=')  ])

    laterBytesSemicolon = bytes([  c[prependBlock + 11] ^ ord('*') ^ ord(';')  ])

    forcedCiphertext = c[ : prependBlock] + bytesSemicolon + c[prependBlock + 1 : prependBlock + 6] + bytesEqual + \
                    c[prependBlock + 7 : prependBlock + 11] + laterBytesSemicolon + c[prependBlock + 12 : ]

    return forcedCiphertext


def main():

    prependString = b'comment1=cooking%20MCs;userdata='

    appendString = b';comment2=%20like%20a%20pound%20of%20bacon'

    cbcOracle = CBCOracle(prependString, appendString)

    c = cbc_bit_flip_attack(cbcOracle)

    text, result = cbcOracle.decrypt_and_check(c)

    assert(result == True)

    print(text)


if __name__ == '__main__':

    main()