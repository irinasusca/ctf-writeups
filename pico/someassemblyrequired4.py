

bytes2 = bytearray(b'\x18j|a\x118i7\x1fYyY>\x1cVc\rB\x1d~l9\x1cZ!]c\x11\x00b\x05IK~a4\x1cW(\x0fR')

#we need to do this in reverse, so the swap first

j = 0
while(j<len(bytes2)):
    if(j%2==0 and j+1<len(bytes2)):
        bytes2[j], bytes2[j+1] = bytes2[j+1], bytes2[j]
    j=j+1


#now the XOR in reverse

i = len(bytes2)-1

while(i>=0):
    bytes2[i] = bytes2[i] ^ 0x14
    if(0<i):
        bytes2[i] = bytes2[i] ^ bytes2[i-1]
    if(2<i):
        bytes2[i] = bytes2[i] ^ bytes2[i-3]
    bytes2[i] = bytes2[i] ^ (i%10)
    if(i%2==0):
        bytes2[i] = bytes2[i] ^ 9
    else:
        bytes2[i] = bytes2[i] ^ 8
    if(i%3==0):
        bytes2[i] = bytes2[i] ^ 7
    elif(i%3==1):
        bytes2[i] = bytes2[i] ^ 6
    else:
        bytes2[i] = bytes2[i] ^ 5
    i=i-1
        
print(bytes2.decode('latin-1'))
