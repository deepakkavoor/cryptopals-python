from c1 import hex2bytes
from collections import Counter


letterFreq = {
    b'a':  0.08167,
    b'b':  0.01492,
    b'c':  0.02782,
    b'd':  0.04253,
    b'e':  0.1270,
    b'f':  0.02228,
    b'g':  0.02015,
    b'h':  0.06094,
    b'i':  0.06966,
    b'j':  0.00153,
    b'k':  0.00772,
    b'l':  0.04025,
    b'm':  0.02406,
    b'n':  0.06749,
    b'o':  0.07507,
    b'p':  0.01929,
    b'q':  0.00095,
    b'r':  0.05987,
    b's':  0.06327,
    b't':  0.09056,
    b'u':  0.02758,
    b'v':  0.00978,
    b'w':  0.02360,
    b'x':  0.00150,
    b'y':  0.01974,
    b'z':  0.00074,
    b' ': 0.1918182,
}


def xor_single_char(string, char):

    result = b''

    for byte in string:
        result += bytes([char ^ byte])

    return result


def score_abs_diff(string):

    # if using this, make sure to take minimum score

    countDict = Counter(string.lower())

    result = 0

    result = sum(  abs(  letterFreq.get(bytes([char]), 0) - (count / len(countDict) )  )  for char, count in countDict.items()  )


    return result


def score_chi_sq(string):

    # http://alexbarter.com/statistics/chi-squared-statistic/

    # if using this, make sure to take minimum score

    # this doesn't seem to work well, especially if used in c4.py

    countDict = Counter(string.lower())

    result = 0

    for char, value in letterFreq.items():

        obs = countDict.get(ord(char), 0)

        exp = value * len(string)

        result += (1 / exp) * (obs - exp) ** 2

    return result


def score_chi_sq_penalize(string):

    # if using this, make sure to take minimum score

    # this statistic, intuitively takes care of non-alphabets as well, with a penalty of 0.3 * len(string) for each

    countDict = Counter(string.lower())

    result = 0

    for char, count in countDict.items():

        obs = count

        exp = letterFreq.get(bytes([char]), 0.3) * len(string)

        result += (1 / exp) * (obs - exp) ** 2 

    return result


def score_simple_sum(string):

    # if using this, make sure to take maximum score

    # seems to work best

    string = string.lower()

    result = 0

    for char in string:

        result += letterFreq.get(bytes([char]), 0)

    return result
    


def get_key_singlechar_xor(string):

    string = hex2bytes(string)

    scores = []

    for key in range(0, 256):

        xorResultBytes = xor_single_char(string, key)

        scores.append( [ key, score_simple_sum(xorResultBytes), xorResultBytes ] )

    scores.sort(key = lambda x: x[1], reverse = True)

    return scores[0]
    


def main():

    string = b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

    key = get_key_singlechar_xor(string)

    assert(key[0] == 88)
    assert(key[2] == b"Cooking MC's like a pound of bacon")

    print(key)


if __name__ == '__main__':
    
    main()