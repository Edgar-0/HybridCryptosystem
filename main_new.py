from des_new import DES

def hybrid_cryptosystem():
    message = input("Enter message: ")

    E1 = message # Encrypted message using rotor machine TODO: Remove message variable and add rotor machine encryption

    des = DES()
    des_key = des.key_generator() # Random generated key for increased security
    des_hash_value = des.hash_message(E1) # Hash for integrity test
    E2 = des.encryption(E1, des_key)
    D1 = des.decryption(E2, des_key)

    if not des.integrity_check(D1, des_hash_value):
        print("DES decryption failed")
        return
    print("DES decryption completed")

    D2 = D1  # Todo: Add Rotor Machine decryption

if __name__ == '__main__':
    hybrid_cryptosystem()


