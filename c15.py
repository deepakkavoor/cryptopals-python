from c9 import is_padded_pkcs7, unpad_pkcs7


def strip_pad_pkcs7(msg):

    return unpad_pkcs7(msg)

def main():

    validPad = b'ICE ICE BABY\x04\x04\x04\x04'

    invalidPad1 = b'ICE ICE BABY\x05\x05\x05\x05'

    invalidPad2 = b'ICE ICE BABY\x01\x02\x03\x04'

    assert(is_padded_pkcs7(validPad) == True)

    assert(is_padded_pkcs7(invalidPad1) == False)

    assert(is_padded_pkcs7(invalidPad2) == False)

    assert(strip_pad_pkcs7(validPad) == b'ICE ICE BABY')

    print(strip_pad_pkcs7(validPad))


if __name__ == '__main__':

    main()