from Crypto.Util.Padding import pad, unpad
from secrets import token_bytes
from random import randrange
import hashlib


class DES:
    def __init__(self):
        self.ip = self.generate_ip()
        self.inv_ip = self.generate_iip(self.ip)

    def hash_message(self, message):
        return hashlib.sha256(message.encode('ascii')).hexdigest()

    def integrity_check(self, message, hash_value):
        return self.hash_message(message) == hash_value

    def key_generator(self):
        token = token_bytes(8)
        return ''.join(format(byte, '08b') for byte in token)

    def generate_ip(self):
        bits = [bit for bit in range(1, 65)]
        ip = []
        while len(bits) > 0:
            bit = randrange(len(bits))
            ip.append(bits[bit])
            bits.pop(bit)
        return ip

    def generate_iip(self, ip):
        inv_ip = [0] * len(ip)
        for index, value in enumerate(ip):
            inv_ip[value - 1] = index + 1
        return inv_ip

    def permute(self, bits, table):
        return ''.join(bits[i - 1] for i in table)

    def left_shift(self, bits, shifts):
        return bits[shifts:] + bits[:shifts]

    def generate_subkeys(self, key):
        pc1 = [
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
        ]

        PC2 = [
            14, 17, 11, 24, 1, 5, 3, 28,
            15, 6, 21, 10, 23, 19, 12, 4,
            26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56,
            34, 53, 46, 42, 50, 36, 29, 32
        ]

        shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

        key56 = self.permute(key, pc1) # Permutation choice #1
        left = key56[:28]
        right = key56[28:]
        subkeys = []

        for rnd in range(16): # 16 rounds subkeys
            left = self.left_shift(left, shifts[rnd])
            right = self.left_shift(right, shifts[rnd])
            subkeys.append(self.permute(left + right, PC2)) # Permutation choice #2

        return subkeys

    def sbox(self):
        sboxes = [
            [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
             [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
             [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
             [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 14, 10, 0, 6, 3, 13]],

            [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
             [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
             [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
             [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

            [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
             [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
             [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
             [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

            [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
             [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
             [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
             [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

            [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
             [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
             [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
             [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

            [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
             [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
             [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
             [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

            [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
             [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
             [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
             [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

            [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
             [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
             [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 5, 5, 8],
             [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
        ]
        return sboxes

    def des_round(self, left, right, subkey):
        e_table = [
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
        ]

        p_table = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

        right48 = self.permute(right, e_table)
        xor = bin(int(right48, 2) ^ int(subkey, 2))[2:].zfill(48)
        groups_6bit = [xor[i:i + 6] for i in range(0, len(xor), 6)]

        sboxes = self.sbox()
        sbox_output = ''
        for i, group in enumerate(groups_6bit):
            row = int(group[0] + group[5], 2)
            col = int(group[1:5], 2)
            sbox_value = sboxes[i][row][col]
            sbox_output += f"{sbox_value:04b}"

        pbox_output = self.permute(sbox_output, p_table)
        final_xor = bin(int(left, 2) ^ int(pbox_output, 2))[2:].zfill(32)
        return right, final_xor

    def encrypt(self, message, key):
        subkeys = self.generate_subkeys(key)
        message_ip = self.permute(message, self.ip) # Initial permutation
        left, right = message_ip[:32], message_ip[32:] # Ciphertext_ip split in two halves
        for r in range(16): # 16 rounds
            left, right = self.des_round(left, right, subkeys[r])
        pre_output = left + right
        encrypted = self.permute(pre_output, self.inv_ip) # Inverse initial permutation
        return encrypted

    def decrypt(self, ciphertext, key):
        subkeys = self.generate_subkeys(key)
        ciphertext_ip = self.permute(ciphertext, self.ip) # Initial permutation
        left, right = ciphertext_ip[:32], ciphertext_ip[32:] # Ciphertext_ip split in two halves
        for r in range(15,-1,-1):
            left, right = self.des_round(left, right, subkeys[r])
        pre_output = left + right
        decrypted = self.permute(pre_output, self.inv_ip)
        return decrypted

    def encryption(self, message, key):
        message_padded = pad(message.encode('ascii'), 8)
        message_in_bits = ''.join(format(byte, '08b') for byte in message_padded)
        print(message_in_bits)
        ciphertext = ''.join(self.encrypt(message_in_bits[i:i+64], key) for i in range(0, len(message_in_bits), 64)) # Encrypt each 64-bit
        return ciphertext

    def decryption(self, ciphertext, key):
        decrypted = "".join(self.decrypt(ciphertext[i:i+64], key) for i in range(0, len(ciphertext), 64)) # Decrypt each 64-bit
        print(decrypted)
        pad_removed = unpad(bytes(decrypted, 'ascii'), 8) #Remove padding
        return pad_removed.decode('ascii')


if __name__ == '__main__':
    message = "HOPE"
    E1 = message

    des = DES()
    des_key = des.key_generator()  # Random generated key for increased security
    des_hash_value = des.hash_message(E1)  # Hash for integrity test
    E2 = des.encryption(E1, des_key)
    D1 = des.decryption(E2, des_key)

    if not des.integrity_check(D1, des_hash_value):
        print("Decryption failed")
    else:
        print("Decryption completed")
    print("DES system finished")

