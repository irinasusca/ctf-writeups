from pwn import *

from ctypes import CDLL
import time

elf = ELF('/home/kali/Downloads/pwn_honeypot')
p=elf.process()

cyberedu = '34.159.240.221:31819'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    gdb.attach(p, gdbscript = '''
    c
    ''')
    
#c code
libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
now = int(time.time())


i=11
j=1

for seed in range(now - 10, now + 20):
    libc.srand(seed)
    random = libc.rand()
    print(seed, random)
    if i==j:
    	random_number = random
    	random_seed = seed
    
    j=j+1
    
libc.srand(random_seed)
random_number = libc.rand()
    
print(f"random number for i={i} is {random_number}")

#dont forget to save the seed too dumbass

#local testing, run normally
#remote testing, run python3 exploit.py REMOTE

#we want: option 2, 
#make current_defense 1 to get hacker_hurt_29

#make a defense var rand() & 3 (the first time, use random_number)
#then option 3, send defense to ward attacks

#repeat

#send name
p.recvuntil(b"name?\n")
p.sendline(b"fufu")

p.recvuntil(b"option:")
p.sendline(b"2")

p.recvuntil(b"Option: ")
p.sendline(b"1")

print(f"hacker number is {random_number}")

#hacker takes damage, so rand() is called, let's keep up;
#the first time, we don't call rand() for this 
#because we already called it once for our seed

p.recvuntil(b"option:")
p.sendline(b"3")

random_number = libc.rand()
print(f"player number is {random_number}")
defense = random_number & 3
p.recvuntil(b"Option: ")
p.sendline(str(defense).encode())

#now we can start a loop! while we receive a string
#that contains "Enter option:" from the binary
#we do what i said above. 

while True:
    
    #go forth with our thing
    try: 
        p.recvuntil(b"option:", timeout=0.5)
        p.sendline(b"2")
        
        p.recvuntil(b"Option: ")
        p.sendline(b"1")

        
        #hacker takes damage here, rand() called
        hacker = libc.rand()
        print(f"hacker number is {hacker}")
        
        random_number = libc.rand()
        print(f"player number is {random_number}")
        defense = random_number & 3
        
        p.recvuntil(b"option:")
        p.sendline(b"3")
        p.recvuntil(b"Option: ")
        p.sendline(str(defense).encode())
        
        buf = b""          # reset after handling
        continue

    # if the program printed something else (flag hopefully) and stopped prompting
    except:
        break

p.interactive()
