from c1 import hex2bytes, bytes2hex

def bytes_xor(string1, string2):

    return bytes( [b1 ^ b2 for b1, b2 in zip(string1, string2)] )


def hex_xor(string1, string2):

    # return hex(int(string1, 16) ^ int(string2, 16))[2:]

    temp1 = hex2bytes(string1)
    temp2 = hex2bytes(string2)

    result = bytes([t1 ^ t2 for t1, t2 in zip(temp1, temp2)])

    return bytes2hex(result)

def main():

    string1 = b'1c0111001f010100061a024b53535009181c'
    string2 = b'686974207468652062756c6c277320657965'

    result = hex_xor(string1, string2)

    assert(hex2bytes(result) == b"the kid don't play")

    assert(bytes_xor( hex2bytes(string1), hex2bytes(string2) ) == b"the kid don't play")

    assert(result == b'746865206b696420646f6e277420706c6179')

    print(result)


if __name__ == "__main__":
    main()