from c1 import bytes2hex


def repeat_key_xor(string, key):

    result = b''

    keyInd = 0

    for char in string:

        result += bytes([ char ^ key[keyInd] ])

        keyInd = (keyInd + 1) % len(key)

    return result


def main():

    string = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

    key = b'ICE'

    result = repeat_key_xor(string, key)

    assert(bytes2hex(result) == b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f')

    print(bytes2hex(result))


if __name__ == '__main__':

    main()