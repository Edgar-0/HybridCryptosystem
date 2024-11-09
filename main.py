from des import DES
import time, rotor_machine as rm

def hybrid_cryptosystem():
    message = input("Enter message: ").upper()
    time_start = time.perf_counter()
    keyrm = rm.keyrm()
    E1 = rm.encryptrm(message, keyrm)
    print(f"Encrypted message E1: {E1}")
    des = DES()
    des_key = des.key_generator()  # Random generated key for increased security
    des_hash_value = des.hash_message(E1)  # Hash for integrity test
    E2 = des.encryption(E1, des_key)  # DES encrypted text
    D1 = des.decryption(E2, des_key)  # DES decrypted text
    print(f"Encrypted message E2: {E2}")
    print(f"Decrypted message D1: {D1}")
    if not des.integrity_check(D1, des_hash_value):
        print("Unsuccessful des decryption")
        return
    print("Successful des decryption")
    D2 = rm.decryptrm(D1, keyrm)
    time_elapsed = (time.perf_counter() - time_start)
    print(f"Decrypted message D2: {D2}")
    print(f"Time taken: {round(time_elapsed * 1000, 2)} ms")

if __name__ == '__main__':
    hybrid_cryptosystem()