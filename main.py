import des, rotor_machine as rm
import psutil, os

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

def hybrid_cryptosystem():
    message = input("Enter original message: ")
    message = message.upper()
    keyrm = rm.keyrm()
    E1 = rm.encryptrm(message, keyrm)
    print(f"Encrypted message E1: {E1}")
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
    D2 = rm.decryptrm(D1, keyrm)
    print(f"Decrypted message D2: {D2}")
if __name__ == '__main__':
    hybrid_cryptosystem()