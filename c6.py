from c1 import base642bytes, bytes2hex
from c3 import get_key_singlechar_xor, score_simple_sum
from c5 import repeat_key_xor
from itertools import combinations


def hamming_dist(string1, string2):

    hamDist = 0

    assert(len(string1) == len(string2))

    for char1, char2 in zip(string1, string2):

        hamDist += bin(char1 ^ char2).count('1')

    return hamDist


def break_repeat_key_xor(string):

    lowSize = 2

    highSize = 40

    hamSizes = []

    for size in range(lowSize, highSize + 1):

        hamDist = 0

        # blocks to consider, to compute hamming distance

        maxBlocks = 4

        blocks = [ string[ i * size : (i + 1) * size] for i in range(0, maxBlocks)]

        pairs = list(combinations(blocks, 2))

        for [string1, string2] in pairs:

            hamDist += hamming_dist(string1, string2)

        # average hamming distance per pair of blocks

        hamDist /= len(pairs)

        # normalize hamming distance wrt block size

        hamDist /= size

        hamSizes.append([size, hamDist])

    hamSizes.sort(key = lambda x: x[1])

    # pick first three key sizes

    keySizes = [hamSizes[i][0] for i in [0, 1, 2]]

    possiblePlainText = []

    for keySize in keySizes:

        transposeBlocks = [b'' for i in range(0, keySize)]

        for i in range(0, keySize):

            j = i

            while j < len(string):

                transposeBlocks[i] += bytes( [ string[j] ] )

                j += keySize

        key = b''

        for block in transposeBlocks:

            key += bytes( [ get_key_singlechar_xor( bytes2hex(block) )[0] ] )

        possiblePlainText.append( [ key, repeat_key_xor(string, key) ] )

    plainText = max(possiblePlainText, key = lambda x: score_simple_sum(x[1]))

    return plainText


def main():

    assert(hamming_dist(b'this is a test', b'wokka wokka!!!') == 37)

    with open('c6.txt') as file:

        text = file.read().replace('\n', '')

    text = base642bytes(bytes(text, 'utf-8'))
    
    [key, plainText] = break_repeat_key_xor(text)

    assert(key == b'Terminator X: Bring the noise')

    print(key)

    print('\n\n', plainText)


if __name__ == '__main__':

    main()