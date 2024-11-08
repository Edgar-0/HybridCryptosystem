import string, random
from numpy import *

def keyrm():
    keys = []
    alphabet = list(string.ascii_uppercase)
    random.shuffle(alphabet)
    keys.append(alphabet)
    #first rotor
    firstconfig = alphabet.copy()
    random.shuffle(firstconfig)
    keys.append(firstconfig)
    #second rotor
    secondconfig = alphabet.copy()
    random.shuffle(secondconfig)
    keys.append(secondconfig)
    #third rotor
    thirdconfig = alphabet.copy()
    random.shuffle(thirdconfig)
    keys.append(thirdconfig)
    print("Original vocabulary: " + str(alphabet))
    print("First rotor:         " + str(firstconfig))
    print("Second rotor:        " + str(secondconfig))
    print("Third rotor:         " + str(thirdconfig))
    return keys

def encryptrm(element, keys):
    c1 = c2= c3 = 0
    eoutput = ""
    for caracter in element:
        if caracter.isalpha():
            r1 = keys[1][(keys[0].index(caracter)+c1)%26] #added mod 26 to avoid when the rotate is in the last characters like "Y" and it must restart
            r2 = keys[2][(keys[0].index(r1)+c2)%26]
            r3 = keys[3][(keys[0].index(r2)+c3)%26]
            eoutput+=r3
            c1+=1
            if c1==26:
                c1=0
                c2+=1
            if c2==26:
                c2=0
                c3+=1
            if c3==26:
                c3=0
        else:
            eoutput+=caracter
    return eoutput

def decryptrm(eoutput, keys):
    c1 = c2= c3 = 0
    doutput =""
    for caracter in eoutput:
        if caracter.isalpha():
            r3 = keys[0][(keys[3].index(caracter)-c3)%26]
            r2 = keys[0][(keys[2].index(r3)-c2)%26]
            r1 = keys[0][(keys[1].index(r2)-c1)%26]
            doutput+=r1
            c1+=1
            if c1==26:
                c1=0
                c2+=1
            if c2==26:
                c2=0
                c3+=1
            if c3==26:
                c3=0
        else:
            doutput+=caracter
    return doutput

def execute():
    #from collections import deque - explain in the last line
    #filling alphabet uppercase in the array
    alphabet = []
    alphabet = list(string.ascii_uppercase)
    #first rotor
    firstconfig = alphabet.copy()
    random.shuffle(firstconfig)
    #second rotor
    secondconfig = alphabet.copy()
    random.shuffle(secondconfig)
    #third rotor
    thirdconfig = alphabet.copy()
    random.shuffle(thirdconfig)
    print("Original vocabulary: " + str(alphabet))
    print("First rotor:         " + str(firstconfig))
    print("Second rotor:        " + str(secondconfig))
    print("Third rotor:         " + str(thirdconfig))
    input = ["HOPE",'HELLO','NEW YEAR']
    c1 = c2= c3 = 0 #These counters are for simulate rotate, one per rotor
    eoutput = doutput ="" #to save encrypted and decrypted output
    #encryption process
    for element in input:
        print ("Text to encrypt: " + element)
        for caracter in element:
            if caracter.isalpha():
                r1 = firstconfig[(alphabet.index(caracter)+c1)%26] #added mod 26 to avoid when the rotate is in the last characters like "Y" and it must restart
                r2 = secondconfig[(alphabet.index(r1)+c2)%26]
                r3 = thirdconfig[(alphabet.index(r2)+c3)%26]
                eoutput+=r3
                print(caracter+"=>"+r1+"=>"+r2+"=>"+r3)
                c1+=1
                if c1==26:
                    c1=0
                    c2+=1
                if c2==26:
                    c2=0
                    c3+=1
                if c3==26:
                    c3=0
            else:
                eoutput+=caracter
                print("Find especial character"+caracter)
        print ("Encrypted text: " + eoutput)
        c1 = c2= c3 = 0
        #decryption process
        for caracter in eoutput:
            if caracter.isalpha():
                r3 = alphabet[(thirdconfig.index(caracter)-c3)%26]
                r2 = alphabet[(secondconfig.index(r3)-c2)%26]
                r1 = alphabet[(firstconfig.index(r2)-c1)%26]
                doutput+=r1
                print(caracter+"=>"+r3+"=>"+r2+"=>"+r1)
                c1+=1
                if c1==26:
                    c1=0
                    c2+=1
                if c2==26:
                    c2=0
                    c3+=1
                if c3==26:
                    c3=0
            else:
                doutput+=caracter
        c1 = c2= c3 = 0
        eoutput = doutput =""
#this is other mode to rotate without the counters, but we prefer the counters cause we can see the changes visualiazing the rotors to map the encrypted character.
# de = deque([1, 2, 3, 4])
# de.rotate(2)

def question1():
    keyrm = keyrm()
    E1 = encryptrm('NEW YEAR', keyrm)
    print(f"Encrypted message with initial configuration: {E1}")
    keyrm2 = []
    other = keyrm[1].copy() #copy of the rotor2
    random.shuffle(other) #suffle of elements to create a different configuration
    keyrm2.append(keyrm[0].copy()) #append to the new keyrm2 to create changed configuration
    keyrm2.append(other)
    keyrm2.append(keyrm[2].copy())
    keyrm2.append(keyrm[3].copy())
    print("First rotor changed:         " + str(keyrm2[1]))
    E2 = encryptrm('HELLO WORLD', keyrm2)
    print(f"Encrypted message with configuration changed: {E2}")


