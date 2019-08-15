from c1 import hex2bytes
from collections import Counter


def get_16B_repititions(text, blockLength = 16):

    # optional block length used in c12

    blocks = [ text[i : i + 16] for i in range(0, len(text), blockLength) ]

    eleCount = Counter(blocks)

    result = len(blocks) - len(eleCount)

    return result


def detect_ecb_encrypt(texts):

    repitition = 0
    resText = b''
    resIndex = -1

    for index, text in enumerate(texts):

        if get_16B_repititions(text) > repitition:

            repitition = get_16B_repititions(text)
            resText = text
            resIndex = index

    return [repitition, resText, resIndex] 


def main():

    texts = []

    for l in open('c8.txt'):

        texts.append( hex2bytes(bytes(l.strip(), 'utf-8')) )

    [repitition, text, index] = detect_ecb_encrypt(texts)

    assert(repitition == 3 and index == 132)

    print(repitition, index)

if __name__ == '__main__':

    main()