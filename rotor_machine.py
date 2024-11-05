import string, random
from numpy import *
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