from pwn import *
import base64

context.arch = 'amd64'
cyberedu = 'host8.dreamhack.games:10149'

ip, port = cyberedu.split(':')
port = int(port)


if args.REMOTE:
    p = remote(ip, port)
else:
    p = elf.process()
    

#add size -1 = x250 size shcnk
#la free, adauga un check de cv
#si la show, adauga check 
# &ptr + v0[0] = 0;
#se scrie in 0x6010A0 (ptr)

#double free, oob(?)ce oob lol

#am uitat, da null la rdi
#ah si bounds - check if 0 <= rax <= 9
#very cool ja verifica unsigned si valorile negative ies din problema
#rax gets clobbered by free so save it smwhere
first_cave = '''
cmp rax, 9
ja 0x400948
mov rdi, qword ptr [rax*8 + 0x6010A0]
cmp qword ptr [rax*8 + 0x6010A0], 0
je 0x400948
mov r15, rax
call 0x400640
mov qword ptr [r15*8 + 0x6010A0], 0
jmp 0x400948
'''

second_cave = '''
cmp rax, 9
ja 0x40099a
mov rdx, qword ptr [rax*8 + 0x6010A0]
cmp qword ptr [rax*8 + 0x6010A0], 0
je 0x40099a
jmp 0x400986
'''

#pick addr in IDA -> click edit->patch->assemble on a random x section
#then give it name loc_addr 
#edit->patch->assemble on intruction to jmp loc_addr
#edit->patch->edit bytes->paste instruction bytes. (16 at a time)
# our caves
encoded = asm(first_cave, vma=0x400B50)
print(encoded.hex(b' '))
print("now the second cave")
encoded = asm(second_cave, vma=0x400B9C)
print(encoded.hex(b' '))

#now , just must find the oob...
#in show/free, idx is not checked to be anything
#it must be < 10 or sth
#The patched binary must have the same I/O values as the original binary.
#when we re asked to show a bad value, do we print Data: (emprty)? currently js nothing
#wc -c  shows file

with open('./originality', 'rb') as f:
    enc = base64.b64encode(f.read())
    
p.recvuntil(b'\n')
p.send(enc)

p.interactive()
