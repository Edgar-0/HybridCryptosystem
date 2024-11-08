import des

def hybrid_cryptosystem():
    message = input("Enter message: ")

    E1 = message # Encrypted message using rotor machine TODO: Remove message variable and add rotor machine encryption

    des_key = des.key_generator() # Random generated key for increased security
    des_hash_value = des.hash_message(E1) # Hash for integrity test
    E2, iv = des.encrypt(E1, des_key)
    D1 = des.decrypt(E2, des_key, iv)

    print(f"Encrypted message E2: {E2}")
    print(f"Decrypted message D1: {D1}")

    if not des.integrity_check(D1, des_hash_value):
        print("Unsuccessful des decryption")
        return
    print("Successful des decryption")

if __name__ == '__main__':
    hybrid_cryptosystem()


