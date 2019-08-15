def pad_pkcs7(msg, blockSize):

    # if len(msg) is a multiple of blockSize, pad with blockSize bits

    numBytes = blockSize - ( len(msg) % blockSize )

    msg += bytes([numBytes] * numBytes)

    return msg


def is_padded_pkcs7(msg):

     # len(msg) >= 0

    numBytes = msg[-1]

    # last msg[-1] bytes must have the same value as msg[-1]

    return len(msg) >= numBytes and msg[-numBytes : ] == bytes([numBytes] * numBytes)


def unpad_pkcs7(msg):

    if is_padded_pkcs7(msg) == False:

        raise Exception('Invalid pkcs7 padding. The message was: {}'.format(msg))

    numBytes = msg[-1]

    return msg[ : -numBytes]


def main():

    msg = b'YELLOW SUBMARINE'

    blockSize = 20

    padMsg = pad_pkcs7(msg, blockSize)

    assert(padMsg == b'YELLOW SUBMARINE\x04\x04\x04\x04')

    assert(unpad_pkcs7(pad_pkcs7(msg, blockSize)) == msg)

    unpad_pkcs7(b'YELLOW SUBMARINE\x04\x04\x04\x03')

    print(padMsg)


if __name__ == '__main__':

    main()