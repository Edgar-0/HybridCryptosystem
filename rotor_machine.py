import string, random
from numpy import *
from collections import deque
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
input = ['HOPE','HELLO','NEW YEAR']
c1 = c2= c3 = 0
output=""
for caracter in input[0]:
    if caracter.isalpha():
        r1 = firstconfig[alphabet.index(caracter)+c1]
        r2 = secondconfig[alphabet.index(r1)+c2]
        r3 = thirdconfig[alphabet.index(r2)+c3]
        output+=r3
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
        output+=caracter
print ("Encrypted text : " + output)
print ("List after insertion : " + str(alphabet))
print ("List after insertion : " + str(firstconfig))
print ("List after insertion : " + str(secondconfig))
print ("List after insertion : " + str(thirdconfig))

c1 = c2= c3 = 0
for caracter in output:
    if caracter.isalpha():
        r3 = alphabet[thirdconfig.index(caracter)-c3]
        r2 = alphabet[secondconfig.index(r3)-c2]
        r1 = alphabet[firstconfig.index(r2)-c1]
        output+=r1
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
        output+=caracter

# de = deque([1, 2, 3, 4])
# de.rotate(2)