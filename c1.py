import codecs

# bytes object like b'hello' means that the h here should be thought of as in ASCII

# if you want to explicitly mention bytes, write b'\x02' whereas it would be wrong to write b'02', since here 0 would be thought of as ASCII character

# encode, lets say to hex, means that interpret as ASCII, then group into hex digits. 

# example, b'a' encode to hex means, since a is 97, its hex form is 0x61, so result is b'61' and not b'\x61'

# decode, say to hex, means that the data is split up as hex, and then ASCII form of each is taken

# example, decoding b'4142' to hex, means result is b'AB', since 0x41 = 65 = A in ASCII

# codecs encode adds a newline at the end

# https://stackoverflow.com/questions/8908287/why-do-i-need-b-to-encode-a-string-with-base64


def hex2bytes(hex):
    
    return codecs.decode(hex, 'hex')


def bytes2hex(bytes):

    # binascii.hexlify(bytes) does the same operation

    return codecs.encode(bytes, 'hex')


def bytes2base64(bytes):

    return codecs.encode(bytes, 'base64')[:-1]


def base642bytes(string):

    return codecs.decode(string, 'base64')


def hex2base64(hexString):

   #hex = hexString.encode('utf-8')

    return bytes2base64(hex2bytes(hexString))


def main():

    string = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'

    assert(hex2bytes(string) == b"I'm killing your brain like a poisonous mushroom")

    assert(hex2base64(string) == b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t')
    
    print(hex2base64(string))


if __name__ == "__main__":

    main()