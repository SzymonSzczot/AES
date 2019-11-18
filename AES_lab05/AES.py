import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import timeit
from base64 import b64decode

data = b"secret"
key = b'szesnascieznakow'


def CBC_encrypt_1():
    CBC = AES.new(key, AES.MODE_CBC)
    with open("1MB.txt", 'rb') as file:
        szyfrogram = CBC.encrypt(pad(file.read(), AES.block_size))


def CBC_encrypt_30():
    CBC = AES.new(key, AES.MODE_CBC)
    with open("30MB.txt", 'rb') as file:
        CBC.encrypt(pad(file.read(), AES.block_size))


def CBC_encrypt_100():
    CBC = AES.new(key, AES.MODE_CBC)
    with open("100MB.txt", 'rb') as file:
        CBC.encrypt(pad(file.read(), AES.block_size))


def ECB_encrypt_1():
    ECB = AES.new(key, AES.MODE_ECB)
    with open("1MB.txt", 'rb') as file:
        ECB.encrypt(pad(file.read(), AES.block_size))


def ECB_encrypt_30():
    ECB = AES.new(key, AES.MODE_ECB)
    with open("30MB.txt", 'rb') as file:
        ECB.encrypt(pad(file.read(), AES.block_size))


def ECB_encrypt_100():
    ECB = AES.new(key, AES.MODE_ECB)
    with open("100MB.txt", 'rb') as file:
        ECB.encrypt(pad(file.read(), AES.block_size))


def OFB_encrypt_1():
    OFB = AES.new(key, AES.MODE_OFB)
    with open("1MB.txt", 'rb') as file:
        OFB.encrypt(pad(file.read(), AES.block_size))


def OFB_encrypt_30():
    OFB = AES.new(key, AES.MODE_OFB)
    with open("30MB.txt", 'rb') as file:
        OFB.encrypt(pad(file.read(), AES.block_size))


def OFB_encrypt_100():
    OFB = AES.new(key, AES.MODE_OFB)
    with open("100MB.txt", 'rb') as file:
        OFB.encrypt(pad(file.read(), AES.block_size))


def CFB_encrypt_1():
    CFB = AES.new(key, AES.MODE_CFB)
    with open("1MB.txt", 'rb') as file:
        CFB.encrypt(pad(file.read(), AES.block_size))


def CFB_encrypt_30():
    CFB = AES.new(key, AES.MODE_CFB)
    with open("30MB.txt", 'rb') as file:
        CFB.encrypt(pad(file.read(), AES.block_size))


def CFB_encrypt_100():
    CFB = AES.new(key, AES.MODE_CFB)
    with open("100MB.txt", 'rb') as file:
        CFB.encrypt(pad(file.read(), AES.block_size))


def CTR_encrypt_1():
    CTR = AES.new(key, AES.MODE_CTR)
    with open("1MB.txt", 'rb') as file:
        CTR.encrypt(pad(file.read(), AES.block_size))


def CTR_encrypt_30():
    CTR = AES.new(key, AES.MODE_CTR)
    with open("30MB.txt", 'rb') as file:
        CTR.encrypt(pad(file.read(), AES.block_size))



def CTR_encrypt_100():
    CTR = AES.new(key, AES.MODE_CTR)
    with open("100MB.txt", 'rb') as file:
        CTR.encrypt(pad(file.read(), AES.block_size))


def CBC():
    elapsed_time_CBC_1 = timeit.timeit(CBC_encrypt_1, number=10)/10
    print("CBC - 1MB  : ", elapsed_time_CBC_1)

    elapsed_time_CBC_30 = timeit.timeit(CBC_encrypt_30, number=10)/10
    print("CBC - 30MB : ", elapsed_time_CBC_30)

    elapsed_time_CBC_100 = timeit.timeit(CBC_encrypt_100, number=10)/10
    print("CBC - 100MB: ", elapsed_time_CBC_100)


def ECB():
    elapsed_time_ECB_1 = timeit.timeit(ECB_encrypt_1, number=10)/10
    print("ECB - 1MB  : ", elapsed_time_ECB_1)

    elapsed_time_ECB_30 = timeit.timeit(ECB_encrypt_30, number=10)/10
    print("ECB - 30MB : ", elapsed_time_ECB_30)

    elapsed_time_ECB_100 = timeit.timeit(ECB_encrypt_100, number=10)/10
    print("ECB - 100MB: ", elapsed_time_ECB_100)


def OFB():
    elapsed_time_OFB_1 = timeit.timeit(OFB_encrypt_1, number=10)/10
    print("OFB - 1MB  : ", elapsed_time_OFB_1)

    elapsed_time_OFB_30 = timeit.timeit(OFB_encrypt_30, number=10)/10
    print("OFB - 30MB : ", elapsed_time_OFB_30)

    elapsed_time_OFB_100 = timeit.timeit(OFB_encrypt_100, number=10)/10
    print("OFB - 100MB: ", elapsed_time_OFB_100)


def CFB():
    elapsed_time_CFB_1 = timeit.timeit(CFB_encrypt_1, number=10)/10
    print("CFB - 1MB  : ", elapsed_time_CFB_1)

    elapsed_time_CFB_30 = timeit.timeit(CFB_encrypt_30, number=10)/10
    print("CFB - 30MB : ", elapsed_time_CFB_30)

    elapsed_time_CFB_100 = timeit.timeit(CFB_encrypt_100, number=10)/10
    print("CFB - 100MB: ", elapsed_time_CFB_100)


def CTR():
    elapsed_time_CTR_1 = timeit.timeit(CTR_encrypt_1, number=10)/10
    print("CTR - 1MB  : ", elapsed_time_CTR_1)

    elapsed_time_CTR_30 = timeit.timeit(CTR_encrypt_30, number=10)/10
    print("CTR - 30MB : ", elapsed_time_CTR_30)

    elapsed_time_CTR_100 = timeit.timeit(CTR_encrypt_100, number=10)/10
    print("CTR - 100MB: ", elapsed_time_CTR_100)


def failure_test_CBC():
    data = b"jakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomosc"
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    ct = ct[:10] + 'x' + ct[11:]
    result = {'iv': iv, 'ciphertext': ct}

    try:
        b64 = result
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        print("The message was: ", pt)
    except (ValueError, KeyError):
        print("Incorrect decryption")


def failure_test_ECB():
    data = b"jakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomosc"
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    ct = b64encode(ct_bytes).decode('utf-8')
    ct = ct[:10] + 'x' + ct[11:]
    result = {'ciphertext': ct}

    try:
        b64 = result
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_ECB)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        print("The message was: ", pt)
    except (ValueError, KeyError):
        print("Incorrect decryption")


def failure_test_OFB():
    data = b"jakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomosc"
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_OFB)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    ct = ct[:10] + 'x' + ct[11:]
    result = {'iv': iv, 'ciphertext': ct}

    try:
        b64 = result
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_OFB, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        print("The message was: ", pt)
    except (ValueError, KeyError):
        print("Incorrect decryption")


def failure_test_CFB():
    data = b"jakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomosc"
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    ct = ct[:10] + 'x' + ct[11:]
    result = {'iv': iv, 'ciphertext': ct}

    try:
        b64 = result
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CFB, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        print("The message was: ", pt)
    except (ValueError, KeyError):
        print("Incorrect decryption")


def failure_test_CTR():
    data = b"jakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomoscjakas dosc dluga wiadomosc"
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CTR)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    ct = b64encode(ct_bytes).decode('utf-8')
    result = {'ciphertext': ct}


    try:
        b64 = result
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(key, AES.MODE_CTR)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        print("The message was: ", pt)
    except (ValueError, KeyError):
        print("Incorrect decryption")


if __name__ == '__main__':
    def zadanie_1():
        CBC()
        ECB()
        OFB()
        CFB()
        CTR()

    def zadanie_2():
        print("CBC")
        failure_test_CBC() # Uszkodzenie bloku
        print("ECB")
        failure_test_ECB() # Uszkodzenie bloku
        print("OFB")
        failure_test_OFB() # uszkodzenie tylko pierwszego znaku
        print("CFB")
        failure_test_CFB() # Uszkodzenie bloku
        print("CTR")
        failure_test_CTR() # Nie da się odszyfrować

    def zadanie_3():
        def xor(in1, in2):
            ret = []
            for i in range(0, max(len(in1), len(in2))):
                ret.append(in1[i % len(in1)] ^ in2[i % len(in2)])
            return bytes(ret)

        def decrypt_aes_ecb(data, key):
            cipher = AES.new(key, AES.MODE_ECB)
            return cipher.decrypt(data)

        def encrypt_aes_ecb(data, key):
            cipher = AES.new(key, AES.MODE_ECB)
            return cipher.encrypt(data)

        def padding(val, block_size=16):
            remaining = block_size - len(val) % block_size
            if remaining == block_size:
                remaining = 16

            ret = val + chr(remaining).encode() * remaining
            print("VALUE ", val)
            print("Padding ", ret)

            return ret

        def un_padding(val, block_size=16):
            pad_amount = val[-1]
            if pad_amount == 0:
                raise Exception
            for i in range(len(val) - 1, len(val) - (pad_amount + 1), -1):
                if val[i] != pad_amount:
                    raise Exception

            return val[:-pad_amount]

        def decrypt_aes_cbc(data, key, iv=b'\x00' * 16, pad=True):
            prev_chunk = iv

            decrypted = []

            for i in range(0, len(data), 16):
                chunk = data[i: i + 16]
                decrypted += xor(decrypt_aes_ecb(chunk, key), prev_chunk)
                prev_chunk = chunk

            if pad:
                return un_padding(bytes(decrypted))
            return bytes(decrypted)

        def encrypt_aes_cbc(data, key, iv=b'\x00' * 16, pad=True):
            if pad:
                padded = padding(data)
            else:
                padded = data

            prev_chunk = iv

            encrypted = []

            for i in range(0, len(padded), 16):
                chunk = padded[i: i + 16]
                encrypted_block = encrypt_aes_ecb(xor(chunk, prev_chunk), key)
                encrypted += encrypted_block
                prev_chunk = encrypted_block

            return bytes(encrypted)

        encrypted = encrypt_aes_cbc(b"wiadomosc", key)
        print(encrypted)
        print(decrypt_aes_cbc(encrypted, key))

    # zadanie_1()
    # zadanie_2()
    zadanie_3()
