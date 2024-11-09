from secrets import token_bytes
from random import randrange
import hashlib, time
import psutil, os

class DES:
    def __init__(self):
        self.padding = False
        self.ip = self.generate_ip()
        self.inv_ip = self.generate_iip(self.ip)

    def encryption(self, msg, key):
        if len(msg) % 8 != 0: #Checks if plaintext size is multiple of 8
            msg = self.add_padding(msg) #Adds padding
            self.padding = True
        # Encrypts each 8 bytes and join them, then converts bits to txt
        ciphertext = bits_to_msg(''.join(self.encrypt_decrypt(msg[i:i+8], key) for i in range(0, len(msg), 8)))
        return ciphertext

    def decryption(self, ciphertext, key):
        # Decrypts each 8 bytes and join them, then converts bits to txt
        decrypted_msg = bits_to_msg(''.join(self.encrypt_decrypt(ciphertext[i:i+8], key, False) for i in range(0, len(ciphertext), 8))) # Encrypt each 64-bit
        if self.padding: # Checks if padding was apply
            decrypted_msg = self.rem_padding(decrypted_msg) # Remove padding
        return decrypted_msg

    def encrypt_decrypt(self, msg, key, encrypt=True):# Encrypts or decrypts
        subkeys = self.generate_subkeys(key) # Generates all subkeys
        msg_in_bits = msg_to_bits(msg)
        message_ip = self.permute(msg_in_bits, self.ip) # Initial permutation
        left, right = message_ip[:32], message_ip[32:] # message_ip split in two halves
        for r in range(16): # 16 rounds
            subkey = subkeys[r] if encrypt else subkeys[15-r] # Assign the appropriate subkey depending on whether it is encryption or decryption
            left, right = self.des_round(left, right, subkey) # Performs the Feistel cipher
        pre_output = right + left # 32-bit swap
        result = self.permute(pre_output, self.inv_ip) # Inverse initial permutation
        return result

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

        shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1] # Left shift amount for each round

        key56 = self.permute(key, pc1) # Permutation choice #1
        left = key56[:28]
        right = key56[28:]
        subkeys = []

        for rnd in range(16): # 16 rounds subkeys
            left = self.left_shift(left, shifts[rnd])
            right = self.left_shift(right, shifts[rnd])
            subkeys.append(self.permute(left + right, PC2)) # Permutation choice #2

        return subkeys

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
        xor = bin(int(subkey, 2)^int(right48, 2))[2:].zfill(48)
        groups_6bit = [xor[i:i + 6] for i in range(0, len(xor), 6)]

        sboxes = sbox()
        sbox_output = ''
        for i, group in enumerate(groups_6bit):
            row = int(group[0] + group[5], 2)
            col = int(group[1:5], 2)
            sbox_value = sboxes[i][row][col]
            sbox_output += bin(sbox_value)[2:].zfill(4)

        pbox_output = self.permute(sbox_output, p_table)
        final_xor = bin(int(left, 2) ^ int(pbox_output, 2))[2:].zfill(32)
        return right, final_xor

    def key_generator(self): # Generates random key
        token = token_bytes(8)
        return ''.join(format(byte, '08b') for byte in token)

    def generate_ip(self): # Generates random initial permutation table
        bits = [bit for bit in range(1, 65)]
        ip = []
        while len(bits) > 0:
            bit = randrange(len(bits))
            ip.append(bits[bit])
            bits.pop(bit)
        return ip

    def generate_iip(self, ip): # Generates random inverse initial permutation table
        inv_ip = [0] * len(ip)
        for index, value in enumerate(ip):
            inv_ip[value - 1] = index + 1
        return inv_ip

    def hash_message(self, msg):
        return hashlib.sha256(msg.encode('ascii')).hexdigest()

    def integrity_check(self, msg, hash_value):
        return self.hash_message(msg) == hash_value

    def permute(self, bits, table):
        return ''.join(bits[i - 1] for i in table)

    def left_shift(self, bits, shifts):
        return bits[shifts:] + bits[:shifts]

    def add_padding(self, msg):
        pad_size = 8 - (len(msg) % 8)
        msg += pad_size * chr(pad_size)
        return msg

    def rem_padding(self, decrypted_msg):
        pad_size = ord(decrypted_msg[-1])
        return decrypted_msg[:-pad_size]

def msg_to_bits(msg):
    bits = ''
    for char in msg:
        if isinstance(char, int):
            bits += bin(char)[2:].zfill(8)
        else:
            bits += bin(ord(char))[2:].zfill(8)
    return bits

def bits_to_msg(bits):
    byte_list = [bits[i:i +8] for i in range(0, len(bits), 8)]
    txt = ''.join(chr(int(byte, 2)) for byte in byte_list)  # Decrypt each 64-bit
    return txt

def sbox():
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

# inner psutil function
def process_memory():
    process = psutil.Process(os.getpid())
    mem_info = process.memory_info()
    return mem_info.rss

# decorator function
def profile(func):
    def wrapper(*args, **kwargs):

        mem_before = process_memory()
        result = func(*args, **kwargs)
        mem_after = process_memory()
        print("{}:consumed memory: {:,}".format(
            func.__name__,
            mem_before, mem_after, mem_after - mem_before))

        return result
    return wrapper

# instantiation of decorator function
@profile

def execute():
    message = input("Message: ")
    E1 = message
    des = DES()
    time_start = time.perf_counter()
    des_key = des.key_generator()  # Random generated key for increased security
    des_hash_value = des.hash_message(E1)  # Hash for integrity test
    E2 = des.encryption(E1, des_key)
    D1 = des.decryption(E2, des_key)
    time_elapsed = (time.perf_counter() - time_start)
    # print(f"Message: {E1}")
    print(f"Encrypted message: {E2}")
    print(f"Decrypted message: {D1}")
    print(f"Time: {round(time_elapsed * 1000, 2)} ms")
    if not des.integrity_check(D1, des_hash_value):
        print("DES decryption failed")
    else:
        print("DES decryption completed")

if __name__ == '__main__':
    execute()