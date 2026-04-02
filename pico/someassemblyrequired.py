r1 = 0xf1
r2 = 0xa7
r3 = 0xf0
r4 = 0x07
r5 = 0xed
r = [r1, r2, r3, r4, r5]

bytes = b"\x9dn\x93\xc8\xb2\xb9A\x8b\x94\x90\xdd>\x94\x97\x90\xdd?\xc4\xc2\xc9\xdd4\xc2\xc5\x97\xdb1\x93\x92\xc0\xda6\x93\x93\xc1\xd9>\x91\xc1\x97\x90"

#val=u64(bytes)
print(bytes)

i = 0
while(i<len(bytes)):
    j = 4 - i%5
    print(chr(bytes[i]^(r[j])), end="")
    i=i+1
