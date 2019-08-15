from Crypto.Cipher import AES
from Crypto import Random
from c7 import aes_encrypt_ecb, aes_decrypt_ecb


class ECBOracle:


    def __init__(self):

        self.key = Random.new().read(AES.key_size[0])


    def encrypt(self, email):

        msg = keyvalue2string(profile_for(email))

        msgBytes = msg.encode('utf-8')

        return aes_encrypt_ecb(msgBytes, self.key, pad = True)


    def decrypt(self, c):

        return aes_decrypt_ecb(c, self.key, padded = True)


def keyvalue2string(dictObj):

    encoded = 'email' + '=' + str(dictObj['email']) + '&' + 'uid' + '=' + str(dictObj['uid']) + '&' + 'role' + '=' + str(dictObj['role'])

    return encoded[: -1]


def string2keyvalue(encoded):

    output = {}

    attrs = encoded.split('&')

    for attr in attrs:

        [key, value] = attr.split('=')

        if value.isdigit():

            value = int(value)

        output[key] = value

    return output


def profile_for(email):

    email = email.replace('&', '').replace('=', '')

    dictObj =  {
        'email' : email, 
        'uid' : 10, 
        'role' : 'user'
    }

    return dictObj


def ecb_cut_paste(encOracle):

    #  < 6 >       <     13    >< 4 >   

    #  email=______&uid=10&role=user

    # try to get a block consisting of only 'admin', concatenated with some padding

    # since blocksize is 16, and you're only allowed to select email id, write 10 unnecessary text, say b'A'

    # and that will complete the first block

    # for the second block, admin is 5 letters, then concatenate 11 b'\x0b' as padding

    # you can either do this manually or let code do it

    prepend = 'A' * (AES.block_size - len('email='))

    padLength = AES.block_size - len('admin')

    padAppend = chr(padLength) * padLength

    email = prepend + 'admin' + padAppend

    c1 = encOracle.encrypt(email)

    # next, you want to make sure that the last block, instead of 'user', will consist of 'admin' only

    # the oracle will pad it appropriately, which is admin with 11 b'\x0b'

    # to make sure 'user' goes to last block, use an email of length 13, since (6 + 13 + 13) = 0 mod 16

    #  < 6 >< 13  ><     13    >< 4 >   

    #  email=______&uid=10&role=user

    lenEmail = AES.block_size - ( len('email=') + len('&uid=10&role=') ) % AES.block_size

    # you could use a valid email of length lenEmail, or use garbage

    email = 'A' * lenEmail

    c2 = encOracle.encrypt(email)

    # now replace the last block of c2, which is encryption of user with some padding, by second of c1

    c3 = c2[ : 32] + c1[16 : 32]

    return c3


def main():

    # note that before python 3.6, dictionaries do not maintain insertion order by default

    # https://stackoverflow.com/questions/1867861/how-to-keep-keys-values-in-same-order-as-declared

    ecbOracle = ECBOracle()

    c = ecb_cut_paste(ecbOracle)

    msg = ecbOracle.decrypt(c)

    keyvalue = string2keyvalue(msg.decode('utf-8'))

    assert(keyvalue['role'] == 'admin')

    print(keyvalue)


if __name__ == '__main__':

    main()