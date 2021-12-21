from os import urandom

s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

inv_s_box = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

r_con = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A
)


class AES:
    def __init__(self, master_key):
        assert len(master_key) == 16

        self._master_key = master_key
        self._rounds = 10
        self._round_keys = self._expand_key(master_key)

    def _expand_key(self, master_key):
        key_columns = self._bytes_to_matrix(master_key)
        """ copies initial 4 words from key . 44 words / 11 round keys"""
        i = 1
        while len(key_columns) < 44:
            word = list(key_columns[-1])  # copy previous wor
            if len(key_columns) % 4 == 0:
                word.append(word.pop(0))  # circular left shift 1 byte
                for x in range(4):
                    word[x] = s_box[word[x]]  # s_box substitution

                word[0] ^= r_con[i]
                i += 1

            word2 = key_columns[-4]

            for x in range(4):
                word[x] ^= word2[x]

            key_columns.append(word)

        key_columns = [key_columns[i: i + 4] for i in range(0, 44, 4)]

        return key_columns

    def encrypt_block(self, plaintext):
        assert len(plaintext) == 16

        plain_state = self._bytes_to_matrix(plaintext)
        self._add_round_key(plain_state, self._round_keys[0])

        for i in range(1, self._rounds):
            self._sub_bytes(plain_state)
            self._shift_rows(plain_state)
            self._mix_columns(plain_state)
            self._add_round_key(plain_state, self._round_keys[i])

        self._sub_bytes(plain_state)
        self._shift_rows(plain_state)
        self._add_round_key(plain_state, self._round_keys[-1])

        return self._matrix_to_bytes(plain_state)

    def decrypt_block(self, ciphertext):
        assert len(ciphertext) == 16
        cipher_state = self._bytes_to_matrix(ciphertext)
        self._add_round_key(cipher_state, self._round_keys[-1])
        self._inv_shift_rows(cipher_state)
        self._inv_sub_bytes(cipher_state)

        for j in range(self._rounds - 1, 0, -1):
            self._add_round_key(cipher_state, self._round_keys[j])
            self._inv_mix_columns(cipher_state)
            self._inv_shift_rows(cipher_state)
            self._inv_sub_bytes(cipher_state)

        self._add_round_key(cipher_state, self._round_keys[0])

        return self._matrix_to_bytes(cipher_state)

    def encrypt_ecb(self, plaintext):
        if len(plaintext) != 16:
            plaintext = AES._pad(self, plaintext)

        blocks = self._split_blocks(plaintext)
        blocks = [self._bytes_to_matrix(self._split_blocks(plaintext)[i]) for i in range(len(blocks))]
        encrypted_blocks = [list("") for i in range(len(blocks))]

        for i in range(len(blocks)):
            plain_state = blocks[i]
            self._add_round_key(plain_state, self._round_keys[0])

            for j in range(1, self._rounds):
                self._sub_bytes(plain_state)
                self._shift_rows(plain_state)
                self._mix_columns(plain_state)
                self._add_round_key(plain_state, self._round_keys[j])

            self._sub_bytes(plain_state)
            self._shift_rows(plain_state)
            self._add_round_key(plain_state, self._round_keys[-1])
            encrypted_blocks[i] = self._matrix_to_bytes(plain_state)

        return [encrypted_blocks[i][j] for i in range(len(blocks)) for j in range(16)]

    def decrypt_ecb(self, ciphertext):
        self._pad(ciphertext)

        blocks = self._split_blocks(ciphertext)
        blocks = [self._bytes_to_matrix(self._split_blocks(ciphertext)[i]) for i in range(len(blocks))]
        encrypted_blocks = [list("") for i in range(len(blocks))]

        for i in range(len(blocks)):
            cipher_state = blocks[i]
            self._add_round_key(cipher_state, self._round_keys[-1])
            self._inv_shift_rows(cipher_state)
            self._inv_sub_bytes(cipher_state)

            for j in range(self._rounds - 1, 0, -1):
                self._add_round_key(cipher_state, self._round_keys[j])
                self._inv_mix_columns(cipher_state)
                self._inv_shift_rows(cipher_state)
                self._inv_sub_bytes(cipher_state)

            self._add_round_key(cipher_state, self._round_keys[0])
            encrypted_blocks[i] = self._matrix_to_bytes(cipher_state)

        unpadded = AES._unpad(self, encrypted_blocks[-1])

        return [encrypted_blocks[i][j] for i in range(len(blocks) - 1) for j in range(16)] + unpadded

    def xor(self, a, b):
        assert len(a) == len(b)
        return [a[i] ^ b[i] for i in range(len(a))]

    def encrypt_cbc(self, plaintext, iv):
        """ CBC Encryption:
        Encrypt (block[i] ^ previous)
        """
        assert len(iv) == 16
        plaintext = self._pad(plaintext)

        blocks = self._split_blocks(plaintext)
        encrypted_blocks = []
        previous = iv

        for i in range(len(blocks)):
            plaintext = self.xor(blocks[i], previous)
            encrypted_block = self.encrypt_block(plaintext)
            encrypted_blocks.append(encrypted_block)
            previous = encrypted_block

        return [encrypted_blocks[i][j] for i in range(len(blocks)) for j in range(len(plaintext))]

    def decrypt_cbc(self, ciphertext, iv):
        """ CBC Decryption
        previous ^ decrypt(ciphertext)
        """
        assert len(iv) == 16

        blocks = self._split_blocks(ciphertext)
        decrypted_blocks = []

        previous = iv

        for i in range(len(blocks)):
            ciphertext = self.decrypt_block(blocks[i])
            decrypted_block = self.xor(ciphertext, previous)
            decrypted_blocks.append(decrypted_block)
            previous = blocks[i]

        unpadded = self._unpad(decrypted_blocks[-1])

        return [decrypted_blocks[i][j] for i in range(len(blocks) - 1) for j in range(len(ciphertext))] + unpadded

    def _bytes_to_matrix(self, b):
        temp = [[0 for x in range(4)] for x in range(4)]  # empty 4x4 array
        for i in range(0, 16, 4):
            for j in range(4):
                temp[int(i / 4)][j] = b[i + j]
        return temp

    def _matrix_to_bytes(self, matrix):
        b = []
        index = 0
        for i in range(4):
            for j in range(4):
                b.append(matrix[i][j])
                index += 1
        return b

    def _sub_bytes(self, state):
        for i in range(4):
            for j in range(4):
                state[i][j] = s_box[state[i][j]]

    def _inv_sub_bytes(self, state):
        for i in range(4):
            for j in range(4):
                state[i][j] = inv_s_box[state[i][j]]

    def _shift_rows(self, state):
        state[0][1], state[1][1], state[2][1], state[3][1] = state[1][1], state[2][1], state[3][1], state[0][1]
        state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]
        state[0][3], state[1][3], state[2][3], state[3][3] = state[3][3], state[0][3], state[1][3], state[2][3]

    def _inv_shift_rows(self, state):
        state[0][1], state[1][1], state[2][1], state[3][1] = state[3][1], state[0][1], state[1][1], state[2][1]
        state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]
        state[0][3], state[1][3], state[2][3], state[3][3] = state[1][3], state[2][3], state[3][3], state[0][3]

    def _add_round_key(self, state, key):
        for i in range(4):
            for j in range(4):
                state[i][j] ^= key[i][j]  # XOR each element in the state array with that in the round key

    def _mul2(self, x):
        x <<= 1  # byte shift left once (*2)
        if x & 0x100:
            x ^= 0x11B
        return x

    def _mul3(self, x):
        """ 0b11 = 0b01 ^ 0b10 | 3 = 2 ^ 1"""
        return self._mul2(x) ^ x

    def _mix_column(self, c):
        """   multiplication matrix:
        02 03 01 01
        01 02 03 01
        01 01 02 03
        03 01 01 02
        c0 = (2 * c[0]) ^ (3 * c[1]) ^ (1 * c[2]) ^ (1 * c[3])  """
        c0 = self._mul2(c[0]) ^ self._mul3(c[1]) ^ c[2] ^ c[3]
        c1 = c[0] ^ self._mul2(c[1]) ^ self._mul3(c[2]) ^ c[3]
        c2 = c[0] ^ c[1] ^ self._mul2(c[2]) ^ self._mul3(c[3])
        c3 = self._mul3(c[0]) ^ c[1] ^ c[2] ^ self._mul2(c[3])

        c[0], c[1], c[2], c[3] = c0, c1, c2, c3

    def _mix_columns(self, state):
        for column in state:
            self._mix_column(column)

    def _mul_9(self, x):
        # 9 = (((i * 2) * 2) * 2) + i
        return self._mul2(self._mul2(self._mul2(x))) ^ x

    def _mul_11(self, x):
        # 11 = ((((i * 2) * 2) + i) * 2) + i
        return self._mul2(self._mul2(self._mul2(x)) ^ x) ^ x

    def _mul_13(self, x):
        # 13 = (((i * 2) + i) * 2) * 2) + i
        return self._mul2(self._mul2(self._mul2(x) ^ x)) ^ x

    def _mul_14(self, x):
        # 14 = (((i * 2) + i) * 2) + i) * 2
        return self._mul2(self._mul2(self._mul2(x) ^ x) ^ x)

    def _inv_mix_column(self, c):
        """  multiplication matrix:
        0E 0B 0D 09     14 11 13  9
        09 0E 0B 0D  =   9 14 11 13
        0D 09 0E 0B     13  9 14 11
        0B 0D 09 0E     11 13  9 14
        c0 = (14 * c[0]) ^ (11 * c[1]) ^ (13 * c[2]) ^ (9 * c[3])   """
        c0 = self._mul_14(c[0]) ^ self._mul_11(c[1]) ^ self._mul_13(c[2]) ^ self._mul_9(c[3])
        c1 = self._mul_9(c[0]) ^ self._mul_14(c[1]) ^ self._mul_11(c[2]) ^ self._mul_13(c[3])
        c2 = self._mul_13(c[0]) ^ self._mul_9(c[1]) ^ self._mul_14(c[2]) ^ self._mul_11(c[3])
        c3 = self._mul_11(c[0]) ^ self._mul_13(c[1]) ^ self._mul_9(c[2]) ^ self._mul_14(c[3])

        c[0], c[1], c[2], c[3] = c0, c1, c2, c3

    def _inv_mix_columns(self, state):
        for column in state:
            self._inv_mix_column(column)

    def _pad(self, text):
        """ converts string plaintext to int array and pads to length of 16 bytes """
        text = [ord(text[i]) for i in range(len(text))]
        pad_length = 16 - (len(text) % 16)
        padding = [pad_length] * pad_length
        return text + padding

    def _unpad(self, text):
        pad_size = text[-1]
        assert pad_size > 0
        text, padding = text[:-pad_size], text[-pad_size:]
        assert all(p == pad_size for p in padding)
        return text

    def _split_blocks(self, text):
        return [text[i: i + 16] for i in range(0, len(text), 16)]


def main():
    # key = [236, 188, 251, 122, 155, 226, 168, 41, 49, 167, 27, 111, 28, 11, 254, 69]
    # iv = [12, 193, 117, 185, 192, 241, 182, 168, 49, 195, 153, 226, 105, 119, 38, 97]
    # ciphertext = [50, 57, 248, 186, 12, 180, 17, 253, 62, 3, 198, 47, 162, 213, 3, 95]
    # plaintext = AES(key).decrypt_cbc(ciphertext, iv)
    # print(''.join([chr(x) for x in plaintext]))

    """ text, iv, key, encrypted
    test
    b'\x86\xa9\x0e\x10\xe5\x8en\x83\x87\xdb7:\xa3>qN'
    b'\x0c\xc1u\xb9\xc0\xf1\xb6\xa81\xc3\x99\xe2iw&a'
    [22, 66, 65, 223, 147, 39, 171, 24, 70, 12, 50, 219, 88, 186, 61, 82]
    :return:
    """

    text = 'test'
    iv = b'\x86\xa9\x0e\x10\xe5\x8en\x83\x87\xdb7:\xa3>qN'
    key = b'\x0c\xc1u\xb9\xc0\xf1\xb6\xa81\xc3\x99\xe2iw&a'

    expected = [22, 66, 65, 223, 147, 39, 171, 24, 70, 12, 50, 219, 88, 186, 61, 82]

    # ciphertext = AES(key).encrypt_cbc(text, iv)
    # print(ciphertext)

    plaintext = AES(key).decrypt_cbc(expected, iv)
    print(plaintext)



if __name__ == '__main__':
    main()
